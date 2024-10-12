import requests
import validators
import time
import logging

class XSScanner:
    def __init__(self, target_url):
        self.set_up_logging()
        self.validate_url(target_url)
        self.target_url = target_url
        self.allowed_domains = ["example.com", "yourdomain.com"]  
        self.payloads = [
            "<script>alert('XSS Test')</script>",
            "'><img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe/src='javascript:alert(\"XSS\")'>"
        ]
        self.check_domain()

    def set_up_logging(self):
        logging.basicConfig(filename='xss_scan.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def validate_url(self, url):
        if not validators.url(url):
            logging.error("Invalid URL provided.")
            raise ValueError("Invalid URL. Please enter a valid URL.")

    def check_domain(self):
        if not any(domain in self.target_url for domain in self.allowed_domains):
            logging.error("Domain not allowed: %s", self.target_url)
            raise ValueError("Domain not allowed.")

    def scan(self):
        logging.info("Starting XSS scan on %s", self.target_url)
        for payload in self.payloads:
            self.check_payload(payload)
            time.sleep(1)  

    def check_payload(self, payload):
        full_url = self.target_url + payload
        try:
            response = requests.get(full_url)
            response.raise_for_status()
            if payload in response.text:
                logging.info("XSS vulnerability detected at: %s", full_url)
                print(f"XSS vulnerability detected at: {full_url}")
                self.log_vulnerability(full_url)
        except requests.exceptions.RequestException as e:
            logging.error("Request failed: %s", e)
            print(f"Request failed: {e}")

    def log_vulnerability(self, url):
        with open('xss_results.txt', 'a') as f:
            f.write(f"XSS vulnerability detected at: {url}\n")

if __name__ == "__main__":
    target = input("Enter the URL to scan for XSS: ")
    try:
        scanner = XSScanner(target)
        scanner.scan()
    except ValueError as ve:
        print(ve)
