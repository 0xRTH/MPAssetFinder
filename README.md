# MPAssetFinder

A fast concurrent asset finder that discovers URLs of various web assets (scripts, stylesheets, images) from a list of URLs.

## Features

- Fast concurrent processing
- Support for HTTP/HTTPS URLs
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

# Use with proxy
cat urls.txt | ./MPAssetFinder --proxy 127.0.0.1:8080

# Verbose mode (show errors)
cat urls.txt | ./MPAssetFinder -v
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