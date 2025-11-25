#!/usr/bin/env python3
"""
URL Sandbox Analysis Tool
Command-line tool to analyze URLs through various sandbox services
"""

import argparse
import requests
import json
import sys
import time
import hashlib
from urllib.parse import urlparse, quote
import os

class URLSandboxAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def validate_url(self, url):
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def analyze_url_anyrun(self, url, api_key=None):
        """
        Analyze URL with AnyRun (requires API key)
        """
        if not api_key:
            return {"error": "AnyRun API key required"}

        endpoint = "https://api.any.run/v1/analysis"
        headers = {
            "Authorization": f"API-Key {api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "obj_type": "url",
            "obj_url": url,
            "options": {
                "enable_screenshots": True,
                "skip_related": False
            }
        }

        try:
            response = self.session.post(endpoint, json=data, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"API error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def analyze_url_hybrid_analysis(self, url, api_key=None):
        """
        Analyze URL with Hybrid Analysis (requires API key)
        """
        if not api_key:
            return {"error": "Hybrid Analysis API key required"}

        endpoint = "https://www.hybrid-analysis.com/api/v2/quick-scan/url"
        headers = {
            "api-key": api_key,
            "User-Agent": "Falcon Sandbox"
        }
        
        data = {"scan_type": "all", "url": url}

        try:
            response = self.session.post(endpoint, data=data, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"API error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def analyze_url_urlscan(self, url, api_key=None):
        """
        Analyze URL with urlscan.io (public API)
        """
        endpoint = "https://urlscan.io/api/v1/scan/"
        headers = {
            "Content-Type": "application/json"
        }
        
        data = {
            "url": url,
            "public": "on"
        }

        if api_key:
            headers["API-Key"] = api_key

        try:
            response = self.session.post(endpoint, json=data, headers=headers)
            if response.status_code == 200:
                result = response.json()
                # Wait for results to be ready
                time.sleep(10)
                return self.get_urlscan_result(result['uuid'])
            else:
                return {"error": f"API error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def get_urlscan_result(self, scan_id):
        """Get results from urlscan.io"""
        result_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
        try:
            response = self.session.get(result_url)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": "Results not ready yet"}
        except Exception as e:
            return {"error": str(e)}

    def analyze_url_virustotal(self, url, api_key=None):
        """
        Analyze URL with VirusTotal (requires API key)
        """
        if not api_key:
            return {"error": "VirusTotal API key required"}

        # Submit URL for analysis
        submit_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": api_key}
        
        encoded_url = quote(url, safe='')
        data = f"url={encoded_url}"

        try:
            # Submit URL
            response = self.session.post(submit_url, data=data, headers=headers)
            if response.status_code == 200:
                analysis_id = response.json()['data']['id']
                
                # Wait for analysis to complete
                time.sleep(30)
                
                # Get analysis results
                result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                result_response = self.session.get(result_url, headers=headers)
                
                if result_response.status_code == 200:
                    return result_response.json()
                else:
                    return {"error": "Failed to get analysis results"}
            else:
                return {"error": f"Submission error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def print_results(self, results, service):
        """Print analysis results in a readable format"""
        print(f"\n{'='*50}")
        print(f"Results from {service}")
        print(f"{'='*50}")
        
        if "error" in results:
            print(f"Error: {results['error']}")
            return

        # Format based on service
        if service == "VirusTotal" and "data" in results:
            stats = results['data']['attributes']['stats']
            print(f"Malicious: {stats.get('malicious', 0)}")
            print(f"Suspicious: {stats.get('suspicious', 0)}")
            print(f"Undetected: {stats.get('undetected', 0)}")
            print(f"Harmless: {stats.get('harmless', 0)}")
            
        elif service == "urlscan.io":
            if "verdicts" in results:
                verdicts = results['verdicts']
                print(f"Overall Score: {verdicts.get('overall', {}).get('score', 'N/A')}")
                print(f"Malicious: {verdicts.get('overall', {}).get('malicious', 'N/A')}")
            
        elif service == "Hybrid Analysis":
            if "finished" in results:
                print(f"Scan finished: {results['finished']}")
                if "scanners" in results:
                    malicious = sum(1 for s in results['scanners'] if s.get('status') == 'malicious')
                    print(f"Malicious detections: {malicious}")
                    
        elif service == "AnyRun":
            if "data" in results:
                data = results['data']
                print(f"Analysis ID: {data.get('id', 'N/A')}")
                print(f"Status: {data.get('status', 'N/A')}")

def main():
    parser = argparse.ArgumentParser(description='URL Sandbox Analysis Tool')
    parser.add_argument('url', help='URL to analyze')
    parser.add_argument('--service', choices=['virustotal', 'urlscan', 'hybrid', 'anyrun'], 
                       default='urlscan', help='Sandbox service to use')
    parser.add_argument('--api-key', help='API key for the service')
    parser.add_argument('--config', help='Path to config file with API keys')
    
    args = parser.parse_args()
    
    analyzer = URLSandboxAnalyzer()
    
    # Validate URL
    if not analyzer.validate_url(args.url):
        print("Error: Invalid URL format")
        sys.exit(1)
    
    # Load API keys from config file if provided
    api_keys = {}
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, 'r') as f:
                api_keys = json.load(f)
        except:
            pass
    
    # Use provided API key or get from config
    api_key = args.api_key or api_keys.get(args.service)
    
    print(f"Analyzing URL: {args.url}")
    print(f"Using service: {args.service}")
    
    # Perform analysis based on selected service
    if args.service == 'virustotal':
        results = analyzer.analyze_url_virustotal(args.url, api_key)
        analyzer.print_results(results, "VirusTotal")
        
    elif args.service == 'urlscan':
        results = analyzer.analyze_url_urlscan(args.url, api_key)
        analyzer.print_results(results, "urlscan.io")
        
    elif args.service == 'hybrid':
        results = analyzer.analyze_url_hybrid_analysis(args.url, api_key)
        analyzer.print_results(results, "Hybrid Analysis")
        
    elif args.service == 'anyrun':
        results = analyzer.analyze_url_anyrun(args.url, api_key)
        analyzer.print_results(results, "AnyRun")

if __name__ == "__main__":
    main()
