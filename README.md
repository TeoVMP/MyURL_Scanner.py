# URL Sandbox Analysis Tool

A Python command-line tool for analyzing URLs through various sandbox services to detect malicious content and security threats.

## Features

- **Multiple Sandbox Services**: Support for VirusTotal, urlscan.io, Hybrid Analysis, and AnyRun
- **Flexible API Management**: Command-line API keys or configuration file
- **Comprehensive Reporting**: Detailed analysis results with threat scores
- **Easy to Use**: Simple command-line interface
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Supported Services

| Service | API Key Required | Free Tier | Description |
|---------|------------------|-----------|-------------|
| urlscan.io | Optional | Yes | Public sandbox with detailed analysis |
| VirusTotal | Required | Limited | Multi-engine malware scanning |
| Hybrid Analysis | Required | Limited | Advanced malware analysis |
| AnyRun | Required | Trial | Interactive malware analysis |

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Setup

1. **Clone the repository**:
```bash
git clone <repository-url>
cd url-sandbox-analyzer
