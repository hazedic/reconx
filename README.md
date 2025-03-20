# ReconX

## Introduction

This is an automated reconnaissance tool designed to discover assets (subdomains and URLs) of a target domain using a variety of open-source tools. It leverages parallel processing for efficiency and provides detailed logging with color-coded output for better visibility. The tool is highly configurable via a `config.json` file and includes features like subdomain enumeration, URL crawling, and validation of live endpoints.

## Prerequisites

Before using this tool, ensure the following dependencies are installed on your system:

### Required Tools

- subfinder
- assetfinder
- amass
- httpx
- waymore
- katana
- gospider
- gowitness
- subzy

## Installing Required Tools

### 1. Install Go

```sh
$ ARCH=$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/' -e 's/arm64/arm64/') && \
    FILE="go1.23.6.linux-$ARCH.tar.gz" && \
    wget "https://go.dev/dl/$FILE" && \
    sudo tar -C /usr/local -xzf "$FILE"
$ sudo chown -R root:root /usr/local/go
$ mkdir -p "$HOME/go/bin" "$HOME/go/src"
$ grep -qxF 'export GOPATH=$HOME/go' $HOME/.profile || echo 'export GOPATH=$HOME/go' >> $HOME/.profile
$ grep -qxF 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' $HOME/.profile || echo 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' >> $HOME/.profile
$ export GOPATH=$HOME/go
$ export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
```

### 2. Install Required Tools

#### subfinder

```sh
$ go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

#### assetfinder

```sh
$ go install -v github.com/tomnomnom/assetfinder@latest
```

#### amass

```sh
$ go install -v github.com/owasp-amass/amass/v3/...@latest
```

#### httpx

```sh
$ go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

**Note:** In the Kali Linux 2024.3 environment, httpx may exist in the /usr/bin directory, and you need to delete that file and install the httpx tool developed by ProjectDiscovery with the same name.

#### waymore

```sh
$ pipx install git+https://github.com/xnl-h4ck3r/waymore.git
```

#### katana

```sh
$ go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

#### gospider

```sh
$ go install -v github.com/jaeles-project/gospider@latest
```

#### gowitness

```sh
$ go install -v github.com/sensepost/gowitness@latest
```

#### subzy

```sh
$ go install -v github.com/PentestPad/subzy@latest
```

## Installation

```sh
$ git clone https://github.com/hazedic/reconx
$ cd reconx
$ pip install -r requirements.txt
```

## Configuration

The tool uses a config.json file for customization. If not present, default settings are applied. 

```json
{
    "subfinder_threads": 50,
    "httpx_threads": 50,
    "httpx_timeout": 5,
    "katana_depth": 5,
    "katana_concurrency": 20,
    "exclude_extensions": "ttf,woff,woff2,svg,png,jpg,jpeg,gif,mp4,mp3,pdf,css,js,ico,eot",
    "dns_resolvers": "8.8.8.8,1.1.1.1",
    "gowitness_timeout": 20,
    "required_tools": [
        "subfinder",
        "assetfinder",
        "amass",
        "httpx",
        "waymore",
        "katana",
        "gospider",
        "gowitness",
        "subzy"
    ]
}
```

- `subfinder_threads`: Number of threads for `subfinder`.
- `httpx_threads`: Number of threads for `httpx`.
- `httpx_timeout`: Timeout (in seconds) for `httpx` requests.
- `katana_depth`: Crawling depth for `katana`.
- `katana_concurrency`: Concurrent requests for `katana`.
- `exclude_extensions`: File extensions to exclude from URL crawling.
- `dns_resolvers`: DNS resolvers for `amass`.
- `gowitness_timeout`: Timeout (in seconds) for `gowitness` screenshot capturing.

## Usage

```sh
$ python reconx.py -h
usage: reconx.py [-h] [-v] [-s] [-w] domain

ReconX: Automated reconnaissance tool

positional arguments:
  domain            Target domain to scan (e.g., example.com)

options:
  -h, --help        show this help message and exit
  -v, --verbose     Show detailed command logs (default: False)
  -s, --screenshot  Take screenshots of subdomains (default: False)
  -w, --wide        Perform reverse DNS lookup in target’s /24 network (default: False)
```
