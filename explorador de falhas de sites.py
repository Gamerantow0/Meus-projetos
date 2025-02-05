import logging
import requests
import ssl
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import os
import json
import re

class SecurityScanner:
    def __init__(self):
        self.logger = self._setup_logging()
        self.report_dir = "security_reports"
        os.makedirs(self.report_dir, exist_ok=True)

    def _setup_logging(self):
        logging_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(level=logging.INFO, format=logging_format)
        return logging.getLogger('security_scanner')

    def check_ssl(self, hostname):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {"ssl_info": cert}
        except Exception as e:
            self.logger.error(f"SSL check failed for {hostname}: {e}")
            return {"ssl_info": str(e)}

    def check_headers(self, url):
        try:
            response = requests.get(url)
            return {"response_headers": dict(response.headers)}
        except Exception as e:
            self.logger.error(f"Header check failed for {url}: {e}")
            return {"response_headers": str(e)}

    def check_vulnerabilities(self, url):
        findings = []
        try:
            response = requests.get(url)
            if "X-Content-Type-Options" not in response.headers:
                findings.append("Missing X-Content-Type-Options header")
            if "X-Frame-Options" not in response.headers:
                findings.append("Missing X-Frame-Options header")
            if "Content-Security-Policy" not in response.headers:
                findings.append("Missing Content-Security-Policy header")
            if "Strict-Transport-Security" not in response.headers:
                findings.append("Missing Strict-Transport-Security header")
        except Exception as e:
            self.logger.error(f"Vulnerability check failed for {url}: {e}")
            findings.append(str(e))
        return {"findings": findings}

    def check_dns_records(self, hostname):
        try:
            result = dns.resolver.resolve(hostname, 'A')
            return {"dns_info": [str(ip) for ip in result]}
        except Exception as e:
            self.logger.error(f"DNS check failed for {hostname}: {e}")
            return {"dns_info": str(e)}

    def check_cookies(self, url):
        try:
            response = requests.get(url)
            return {"cookies": response.cookies.get_dict()}
        except Exception as e:
            self.logger.error(f"Cookie check failed for {url}: {e}")
            return {"cookies": str(e)}

    def sanitize_filename(self, url):
        return re.sub(r'[^a-zA-Z0-9]', '_', url)

    def generate_html_report(self, report, url):
        sanitized_url = self.sanitize_filename(url)
        report_file = os.path.join(self.report_dir, f"{sanitized_url}_report.html")
        with open(report_file, 'w') as f:
            f.write(f"""
            <html>
            <head>
                <title>Security Report for {url}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    h1 {{ color: #333; }}
                    h2 {{ color: #555; }}
                    pre {{ background: #f4f4f4; padding: 10px; border: 1px solid #ddd; }}
                    ul {{ list-style-type: none; padding: 0; }}
                    li {{ background: #f9f9f9; margin: 5px 0; padding: 10px; border: 1px solid #ddd; }}
                    .finding {{ cursor: pointer; }}
                    .evidence {{ display: none; }}
                </style>
                <script>
                    function toggleEvidence(id) {{
                        var evidence = document.getElementById(id);
                        if (evidence.style.display === "none") {{
                            evidence.style.display = "block";
                        }} else {{
                            evidence.style.display = "none";
                        }}
                    }}
                </script>
            </head>
            <body>
                <h1>Security Report for {url}</h1>
                <h2>SSL Information</h2>
                <pre>{json.dumps(report['ssl_info'], indent=2)}</pre>
                <h2>Response Headers</h2>
                <pre>{json.dumps(report['response_headers'], indent=2)}</pre>
                <h2>DNS Information</h2>
                <pre>{json.dumps(report['dns_info'], indent=2)}</pre>
                <h2>Cookies</h2>
                <pre>{json.dumps(report['cookies'], indent=2)}</pre>
                <h2>Findings</h2>
                <ul>
            """)
            for i, finding in enumerate(report['findings']):
                f.write(f"""
                <li class="finding" onclick="toggleEvidence('evidence_{i}')">
                    {finding}
                    <div class="evidence" id="evidence_{i}">
                        <pre>{json.dumps(report, indent=2)}</pre>
                    </div>
                </li>
                """)
            f.write("""
                </ul>
            </body>
            </html>
            """)
        return report_file

    def scan_target(self, url):
        hostname = url.split("//")[-1].split("/")[0]
        report = {}

        with ThreadPoolExecutor(max_workers=5) as executor:
            ssl_future = executor.submit(self.check_ssl, hostname)
            headers_future = executor.submit(self.check_headers, url)
            vulns_future = executor.submit(self.check_vulnerabilities, url)
            dns_future = executor.submit(self.check_dns_records, hostname)
            cookies_future = executor.submit(self.check_cookies, url)

            report["ssl_info"] = ssl_future.result()
            report["response_headers"] = headers_future.result()
            report["findings"] = vulns_future.result()["findings"]
            report["dns_info"] = dns_future.result()
            report["cookies"] = cookies_future.result()

        report_file = self.generate_html_report(report, url)
        self.logger.info(f"Scan completed. Report saved to: {report_file}")
        return report

def main():
    try:
        scanner = SecurityScanner()
        url_to_scan = input("Enter the URL to scan (e.g., https://example.com): ")
        report = scanner.scan_target(url_to_scan)
        print("\nScan completed successfully!")
        print(f"Reports are saved in the 'security_reports' directory")
    except Exception as e:
        print(f"Error during scan: {str(e)}")

if __name__ == "__main__":
    main()