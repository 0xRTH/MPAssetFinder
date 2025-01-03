package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"compress/flate"
	"compress/gzip"

	"crypto/tls"

	"github.com/andybalholm/brotli"
	"golang.org/x/net/html"
)

var (
	printMutex  sync.Mutex
	proxyFlag   = flag.String("proxy", "", "Proxy address (e.g., --proxy=127.0.0.1:8080)")
	verboseFlag = flag.Bool("v", false, "Verbose output (print errors)")
	imageFlag   = flag.Bool("img", false, "Include image assets in output")
	anchorFlag  = flag.Bool("a", false, "Include anchor (a tag) URLs in output")
	sourceFlag  = flag.Bool("s", false, "Show source URL for each asset")
	client      *http.Client
	bufferPool  = sync.Pool{
		New: func() interface{} {
			return new(strings.Builder)
		},
	}
)

func initHTTPClient() {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	// Configure proxy if flag is set
	if *proxyFlag != "" {
		proxyURL, err := url.Parse("http://" + *proxyFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing proxy URL: %v\n", err)
			os.Exit(1)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
}

func main() {
	// Parse command line flags
	flag.Parse()

	// Initialize HTTP client with proxy if specified
	initHTTPClient()

	scanner := bufio.NewScanner(os.Stdin)
	var urls []string

	// Collect URLs first
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	// Create a worker pool
	numWorkers := runtime.NumCPU() * 2 // Adjust based on your needs
	workChan := make(chan string, len(urls))
	results := make(chan error, len(urls))

	// Start workers
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Launch workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(ctx, &wg, workChan, results)
	}

	// Send work to workers
	for _, url := range urls {
		workChan <- url
	}
	close(workChan)

	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for err := range results {
		if err != nil && *verboseFlag {
			fmt.Fprintf(os.Stderr, "Error scraping: %v\n", err)
		}
	}
}

func worker(ctx context.Context, wg *sync.WaitGroup, workChan <-chan string, results chan<- error) {
	defer wg.Done()
	for {
		select {
		case url, ok := <-workChan:
			if !ok {
				return
			}
			results <- scrapeAssets(ctx, url)
		case <-ctx.Done():
			return
		}
	}
}

func safePrintln(s string, sourceURL string) {
	printMutex.Lock()
	if *sourceFlag && sourceURL != "" {
		fmt.Printf("%s | referrer: %s\n", s, sourceURL)
	} else {
		fmt.Println(s)
	}
	printMutex.Unlock()
}

func isRelatedDomain(urlDomain, baseDomain string) bool {
	// Convert to lowercase for comparison
	urlDomain = strings.ToLower(urlDomain)
	baseDomain = strings.ToLower(baseDomain)

	// Check if domains are exactly the same
	if urlDomain == baseDomain {
		return true
	}

	// Check if URL is a subdomain of base domain
	if strings.HasSuffix(urlDomain, "."+baseDomain) {
		return true
	}

	// Get top level domain of base
	parts := strings.Split(baseDomain, ".")
	if len(parts) > 1 {
		tld := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if strings.HasSuffix(urlDomain, "."+tld) {
			return true
		}
	}

	return false
}

func cleanURL(urlStr string) string {
	// Remove any content after single quote or double quote
	if idx := strings.IndexByte(urlStr, '\''); idx != -1 {
		urlStr = urlStr[:idx]
	}
	if idx := strings.IndexByte(urlStr, '"'); idx != -1 {
		urlStr = urlStr[:idx]
	}

	// Remove any content after whitespace
	if idx := strings.IndexByte(urlStr, ' '); idx != -1 {
		urlStr = urlStr[:idx]
	}

	return urlStr
}

func checkAndPrintAnchor(urlStr string, domain string, sourceURL string) {
	urlStr = cleanURL(urlStr)
	builder := bufferPool.Get().(*strings.Builder)
	defer func() {
		builder.Reset()
		bufferPool.Put(builder)
	}()

	var fullURL string
	switch {
	case strings.HasPrefix(urlStr, "http"):
		fullURL = urlStr
	case strings.HasPrefix(urlStr, "//"):
		builder.WriteString("https:")
		builder.WriteString(urlStr)
		fullURL = builder.String()
	case strings.HasPrefix(urlStr, "/"):
		builder.WriteString("https://")
		builder.WriteString(domain)
		builder.WriteString(urlStr)
		fullURL = builder.String()
	default:
		return // Skip invalid URLs
	}

	// Parse the URL to get its domain
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return
	}

	// Only print if the domain is related
	if isRelatedDomain(parsedURL.Host, domain) {
		safePrintln(fullURL, sourceURL)
	}
}

func checkAndPrint(urlStr string, domain string, sourceURL string) {
	urlStr = cleanURL(urlStr)
	builder := bufferPool.Get().(*strings.Builder)
	defer func() {
		builder.Reset()
		bufferPool.Put(builder)
	}()

	switch {
	case strings.HasPrefix(urlStr, "http"):
		safePrintln(urlStr, sourceURL)
	case strings.HasPrefix(urlStr, "//"):
		builder.WriteString("https:")
		builder.WriteString(urlStr)
		safePrintln(builder.String(), sourceURL)
	case strings.HasPrefix(urlStr, "/"):
		builder.WriteString("https://")
		builder.WriteString(domain)
		builder.WriteString(urlStr)
		safePrintln(builder.String(), sourceURL)
	}
}

func formatURL(url string) (fullURL string, domain string) {
	if strings.HasPrefix(url, "https://") {
		fullURL = url
		domain = strings.TrimPrefix(url, "https://")
	} else if strings.HasPrefix(url, "http://") {
		fullURL = url
		domain = strings.TrimPrefix(url, "http://")
	} else {
		fullURL = "https://" + url
		domain = url
	}
	if idx := strings.IndexByte(domain, '/'); idx != -1 {
		domain = domain[:idx]
	}
	return
}

func scrapeAssets(ctx context.Context, url string) error {
	fullURL, domain := formatURL(url)
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	// Add browser-like headers
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Create a client that doesn't follow redirects automatically
	clientNoRedirect := &http.Client{
		Transport: client.Transport,
		Timeout:   client.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var finalResp *http.Response
	maxRedirects := 10
	redirectCount := 0

	for {
		resp, err := clientNoRedirect.Do(req)
		if err != nil {
			return fmt.Errorf("error fetching URL: %v", err)
		}

		checkAndPrint(fullURL, domain, "")

		// Store the last response
		if finalResp != nil {
			finalResp.Body.Close()
		}
		finalResp = resp

		// Handle redirects
		if resp.StatusCode == http.StatusFound ||
			resp.StatusCode == http.StatusMovedPermanently ||
			resp.StatusCode == http.StatusTemporaryRedirect ||
			resp.StatusCode == http.StatusPermanentRedirect {

			redirectURL := resp.Header.Get("Location")
			if redirectURL == "" {
				break
			}

			// Handle relative URLs
			if !strings.HasPrefix(redirectURL, "http") {
				if strings.HasPrefix(redirectURL, "/") {
					redirectURL = "https://" + domain + redirectURL
				} else {
					redirectURL = "https://" + domain + "/" + redirectURL
				}
			}

			// Print redirect URL
			safePrintln(redirectURL, fullURL)

			// Prepare next request
			req, err = http.NewRequestWithContext(ctx, "GET", redirectURL, nil)
			if err != nil {
				return fmt.Errorf("error creating redirect request: %v", err)
			}

			// Copy all headers to new request
			for k, v := range resp.Request.Header {
				req.Header[k] = v
			}

			redirectCount++
			if redirectCount >= maxRedirects {
				return fmt.Errorf("too many redirects")
			}
			continue
		}
		break
	}
	defer finalResp.Body.Close()

	// Handle compressed responses
	var reader io.Reader = finalResp.Body
	switch finalResp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(finalResp.Body)
		if err != nil {
			return fmt.Errorf("error creating gzip reader: %v", err)
		}
		defer reader.(*gzip.Reader).Close()
	case "deflate":
		reader = flate.NewReader(finalResp.Body)
		defer reader.(io.ReadCloser).Close()
	case "br":
		reader = brotli.NewReader(finalResp.Body)
	}

	seen := make(map[string]struct{}) // Track seen assets to avoid duplicates
	doc, err := html.Parse(reader)
	if err != nil {
		return fmt.Errorf("error parsing HTML: %v", err)
	}

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script":
				for _, attr := range n.Attr {
					if attr.Key == "src" && attr.Val != "" {
						if _, exists := seen[attr.Val]; !exists {
							checkAndPrint(attr.Val, domain, fullURL)
							seen[attr.Val] = struct{}{}
						}
					}
				}
			case "link":
				var rel, href string
				for _, attr := range n.Attr {
					switch attr.Key {
					case "rel":
						rel = attr.Val
					case "href":
						href = attr.Val
					}
				}
				if (rel == "stylesheet" || strings.Contains(rel, "font")) && href != "" {
					if _, exists := seen[href]; !exists {
						checkAndPrint(href, domain, fullURL)
						seen[href] = struct{}{}
					}
				}
			case "a":
				if *anchorFlag {
					for _, attr := range n.Attr {
						if attr.Key == "href" && attr.Val != "" {
							if _, exists := seen[attr.Val]; !exists {
								checkAndPrintAnchor(attr.Val, domain, fullURL)
								seen[attr.Val] = struct{}{}
							}
						}
					}
				}
			case "img":
				if *imageFlag {
					for _, attr := range n.Attr {
						if attr.Key == "src" && attr.Val != "" {
							if _, exists := seen[attr.Val]; !exists {
								checkAndPrint(attr.Val, domain, fullURL)
								seen[attr.Val] = struct{}{}
							}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)
	return nil
}
