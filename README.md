# MPAssetFinder

A fast concurrent asset finder that discovers URLs of various web assets (scripts, stylesheets, images, links) from a list of URLs.

## Features

- Fast concurrent processing
- Support for HTTP/HTTPS URLs
- Finds assets from script, link, img, and anchor tags
- Proxy support
- Handles redirects
- Browser-like request headers
- Compressed response handling (gzip, deflate, brotli)
- Customizable with flags

## Usage

```bash
# Basic usage (reads URLs from stdin)
cat urls.txt | ./MPAssetFinder

# Include images in output
cat urls.txt | ./MPAssetFinder --img

# Include anchor tag URLs in output
cat urls.txt | ./MPAssetFinder -a

# Show source URL for each asset
cat urls.txt | ./MPAssetFinder -s

# Use with proxy
cat urls.txt | ./MPAssetFinder --proxy 127.0.0.1:8080

# Verbose mode (show errors)
cat urls.txt | ./MPAssetFinder -v

# Combine flags
cat urls.txt | ./MPAssetFinder -a --img -s -v
```

## Installation

```bash
go install github.com/0xRTH/MPAssetFinder@latest
```

## Building from source

```bash
git clone https://github.com/0xRTH/MPAssetFinder.git
cd MPAssetFinder
go build
```

## License

MIT License 