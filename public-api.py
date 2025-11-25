#!/usr/bin/env python3
"""
Simple URL Sandbox Scanner using urlscan.io
"""

import argparse
import requests
import json
import time
import sys

def scan_url(url):
    """Scan URL using urlscan.io public API"""
    
    headers = {
        'Content-Type': 'application/json',
        'API-Key': ''  # Public API doesn't require key for basic scans
    }
    
    data = {
        "url": url,
        "public": "on"
    }
    
    try:
        # Submit URL for scanning
        response = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            json=data
        )
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result['uuid']
            
            print(f"Scan submitted successfully!")
            print(f"Scan ID: {scan_id}")
            print("Waiting for results...")
            
            # Wait for scan to complete
            time.sleep(15)
            
            # Get results
            result_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
            result_response = requests.get(result_url)
            
            if result_response.status_code == 200:
                scan_data = result_response.json()
                return scan_data
            else:
                return {"error": "Results not ready yet"}
        else:
            return {"error": f"Failed to submit URL: {response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}

def print_simple_results(results):
    """Print simplified results"""
    if "error" in results:
        print(f"Error: {results['error']}")
        return
    
    print("\n" + "="*50)
    print("SCAN RESULTS")
    print("="*50)
    
    # Basic info
    if 'page' in results:
        page = results['page']
        print(f"URL: {page.get('url', 'N/A')}")
        print(f"Domain: {page.get('domain', 'N/A')}")
        print(f"IP: {page.get('ip', 'N/A')}")
        print(f"Country: {page.get('country', 'N/A')}")
    
    # Verdicts
    if 'verdicts' in results:
        verdicts = results['verdicts']
        overall = verdicts.get('overall', {})
        print(f"\nOverall Score: {overall.get('score', 'N/A')}")
        print(f"Malicious: {overall.get('malicious', 'N/A')}")
    
    # Stats
    if 'stats' in results:
        stats = results['stats']
        print(f"\nResource Stats:")
        print(f"  - Total: {stats.get('resourceStats', {}).get('total', 'N/A')}")
        print(f"  - Malicious: {stats.get('malicious', 'N/A')}")
    
    # Console message if available
    if 'data' in results and 'requests' in results['data']:
        requests = results['data']['requests']
        print(f"\nRequests made: {len(requests)}")

def main():
    parser = argparse.ArgumentParser(description='Simple URL Sandbox Scanner')
    parser.add_argument('url', help='URL to scan')
    parser.add_argument('--wait', type=int, default=15, 
                       help='Wait time for results in seconds')
    
    args = parser.parse_args()
    
    print(f"Scanning URL: {args.url}")
    results = scan_url(args.url)
    print_simple_results(results)

if __name__ == "__main__":
    main()
