#!/usr/bin/env python3
"""
Shadow API Hunter - Automated API Security Testing Tool
Author: Your Name
Description: Discovers hidden API endpoints and tests for common vulnerabilities
"""

import requests
import json
import re
import time
import argparse
import pandas as pd
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

class ShadowAPIHunter:
    def __init__(self, base_url, auth_token=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})

        self.discovered_endpoints = []
        self.vulnerabilities = []

    def crawl_for_endpoints(self):
        """Discover API endpoints through multiple methods"""
        print("🔍 Starting API endpoint discovery...")

        # Method 1: Check common locations
        endpoints = self._check_common_locations()

        # Method 2: Parse HTML for API references
        html_endpoints = self._parse_html_for_apis()
        endpoints.update(html_endpoints)

        # Method 3: Check JavaScript files
        js_endpoints = self._discover_from_javascript()
        endpoints.update(js_endpoints)

        self.discovered_endpoints = list(endpoints)
        print(f"✅ Discovered {len(endpoints)} potential API endpoints")
        return self.discovered_endpoints

    def _check_common_locations(self):
        """Check common API endpoint locations"""
        common_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/rest/', '/graphql',
            '/swagger/', '/docs/', '/openapi/', '/api-docs/'
        ]

        endpoints = set()
        for path in common_paths:
            url = self.base_url + path
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    endpoints.add(url)
                    print(f"Found: {url}")
            except:
                pass
        return endpoints

    def _parse_html_for_apis(self):
        """Parse HTML content for API endpoint references"""
        endpoints = set()
        try:
            response = self.session.get(self.base_url)
            soup = BeautifulSoup(response.content, 'html.parser')

            # Look for script tags with API calls
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Find URL patterns in JavaScript
                    urls = re.findall(r'https?://[^\s"\']+|/\w+/\w+[^\s"\')]*', script.string)
                    for url in urls:
                        if self._looks_like_api(url):
                            full_url = urljoin(self.base_url, url)
                            endpoints.add(full_url)
        except Exception as e:
            print(f"HTML parsing error: {e}")

        return endpoints

    def _discover_from_javascript(self):
        """Discover endpoints from external JavaScript files"""
        endpoints = set()
        try:
            response = self.session.get(self.base_url)
            soup = BeautifulSoup(response.content, 'html.parser')

            # Find JavaScript files
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                js_url = urljoin(self.base_url, script['src'])
                if js_url.endswith('.js'):
                    endpoints.update(self._parse_js_file(js_url))
        except Exception as e:
            print(f"JavaScript discovery error: {e}")

        return endpoints

    def _parse_js_file(self, js_url):
        """Parse JavaScript file for API endpoints"""
        endpoints = set()
        try:
            response = self.session.get(js_url)
            content = response.text

            # Common API patterns
            patterns = [
                r'(?:GET|POST|PUT|DELETE)\s*[\'"]([^\'"]*\b(?:api|rest)[^\'"]*)',
                r'url\s*:\s*[\'"]([^\'"]*\b(?:api|rest)[^\'"]*)',
                r'[\'"](\/api\/[^\'"]+)',
                r'[\'"](\/rest\/[^\'"]+)',
                r'endpoint[s]?\s*[:=]\s*[\'"]([^\'"]+)',
            ]

            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if len(match) > 3:  # Filter out very short strings
                        full_url = urljoin(self.base_url, match)
                        endpoints.add(full_url)

        except Exception as e:
            print(f"JS parsing error for {js_url}: {e}")

        return endpoints

    def _looks_like_api(self, url):
        """Heuristic to determine if URL looks like an API endpoint"""
        api_indicators = ['api', 'rest', 'json', 'service', 'endpoint']
        return any(indicator in url.lower() for indicator in api_indicators)

    def test_vulnerabilities(self):
        """Test discovered endpoints for common vulnerabilities"""
        print("🛡️ Testing for vulnerabilities...")

        for endpoint in self.discovered_endpoints:
            print(f"Testing: {endpoint}")

            # Test for IDOR-like patterns
            self._test_idor_patterns(endpoint)

            # Test for excessive data exposure
            self._test_data_exposure(endpoint)

            # Test for rate limiting issues
            self._test_rate_limiting(endpoint)

    def _test_idor_patterns(self, endpoint):
        """Test for Insecure Direct Object References"""
        # Simple test - try to access with modified parameters
        test_params = ['1', '2', 'admin', 'root', '0']

        for param in test_params:
            test_url = f"{endpoint}/{param}" if not '?' in endpoint else f"{endpoint}&id={param}"
            try:
                response = self.session.get(test_url, timeout=3)
                # Look for indicators of successful unauthorized access
                if response.status_code == 200 and len(response.text) > 100:
                    self.vulnerabilities.append({
                        'type': 'Potential IDOR',
                        'endpoint': test_url,
                        'status_code': response.status_code,
                        'risk': 'HIGH'
                    })
            except:
                pass

    def _test_data_exposure(self, endpoint):
        """Test for excessive data exposure"""
        try:
            response = self.session.get(endpoint, timeout=3)
            if response.status_code == 200:
                content = response.text.lower()
                sensitive_keywords = ['password', 'ssn', 'credit', 'token', 'key']

                exposed_data = [kw for kw in sensitive_keywords if kw in content]
                if exposed_data:
                    self.vulnerabilities.append({
                        'type': 'Sensitive Data Exposure',
                        'endpoint': endpoint,
                        'exposed_data': exposed_data,
                        'risk': 'MEDIUM'
                    })
        except:
            pass

    def _test_rate_limiting(self, endpoint):
        """Test for missing rate limiting"""
        try:
            # Send multiple rapid requests
            responses = []
            for i in range(10):
                response = self.session.get(endpoint, timeout=3)
                responses.append(response.status_code)
                time.sleep(0.1)  # Small delay

            # If all succeed, might indicate missing rate limiting
            success_count = sum(1 for code in responses if code == 200)
            if success_count >= 8:  # 80% success rate
                self.vulnerabilities.append({
                    'type': 'Potential Missing Rate Limiting',
                    'endpoint': endpoint,
                    'success_rate': f"{success_count}/10",
                    'risk': 'LOW'
                })
        except:
            pass

    def generate_report(self):
        """Generate a comprehensive security report"""
        print("\n📋 SECURITY ANALYSIS REPORT")
        print("=" * 50)

        print(f"\n🎯 Target: {self.base_url}")
        print(f"🔍 Endpoints Discovered: {len(self.discovered_endpoints)}")
        print(f"⚠️  Vulnerabilities Found: {len(self.vulnerabilities)}")

        if self.discovered_endpoints:
            print(f"\n🌐 DISCOVERED ENDPOINTS:")
            for i, endpoint in enumerate(self.discovered_endpoints[:10], 1):
                print(f"  {i}. {endpoint}")
            if len(self.discovered_endpoints) > 10:
                print(f"  ... and {len(self.discovered_endpoints) - 10} more")

        if self.vulnerabilities:
            print(f"\n🚨 VULNERABILITIES DETECTED:")
            risk_levels = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
            for vuln in self.vulnerabilities:
                risk_levels[vuln['risk']].append(vuln)

            for risk, vulns in risk_levels.items():
                if vulns:
                    print(f"\n  {risk} RISK ({len(vulns)} findings):")
                    for vuln in vulns:
                        print(f"    • {vuln['type']} - {vuln['endpoint']}")

        # Export to CSV
        self._export_to_csv()

        return {
            'endpoints': self.discovered_endpoints,
            'vulnerabilities': self.vulnerabilities
        }

    def _export_to_csv(self):
        """Export findings to CSV files"""
        # Export endpoints
        if self.discovered_endpoints:
            endpoints_df = pd.DataFrame({'endpoint': self.discovered_endpoints})
            endpoints_df.to_csv('discovered_endpoints.csv', index=False)
            print("\n💾 Endpoints saved to 'discovered_endpoints.csv'")

        # Export vulnerabilities
        if self.vulnerabilities:
            vulns_df = pd.DataFrame(self.vulnerabilities)
            vulns_df.to_csv('vulnerabilities_found.csv', index=False)
            print("💾 Vulnerabilities saved to 'vulnerabilities_found.csv'")

def main():
    parser = argparse.ArgumentParser(description='Shadow API Hunter - Discover hidden APIs and test for vulnerabilities')
    parser.add_argument('--target', required=True, help='Target URL to scan')
    parser.add_argument('--auth-token', help='Authentication token (Bearer)')
    parser.add_argument('--output', default='report', help='Output file prefix')

    args = parser.parse_args()

    print("🚀 Starting Shadow API Hunter...")
    hunter = ShadowAPIHunter(args.target, args.auth_token)

    # Discover endpoints
    endpoints = hunter.crawl_for_endpoints()

    # Test for vulnerabilities
    hunter.test_vulnerabilities()

    # Generate report
    report = hunter.generate_report()

    return report

if __name__ == "__main__":
    report = main()
