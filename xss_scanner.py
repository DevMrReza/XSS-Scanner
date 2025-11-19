import time
import logging
import requests
import validators


class XSSScanner:
    def __init__(self, target_url: str):
        self._set_up_logging()
        self._validate_url(target_url)

        self.target_url = target_url
        self.allowed_domains = ["example.com", "yourdomain.com"]

        self.payloads = [
            "<script>alert('XSS Test')</script>",
            "'><img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe/src='javascript:alert(\"XSS\")'>"
        ]

        self._check_domain()
        logging.info("Initialized scanner for %s", self.target_url)

    def _set_up_logging(self) -> None:
        logging.basicConfig(
            filename="xss_scan.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

    def _validate_url(self, url: str) -> None:
        if not validators.url(url):
            logging.error("Invalid URL provided: %s", url)
            raise ValueError("Invalid URL. Please enter a valid URL (including http/https).")

    def _check_domain(self) -> None:
        if not any(domain in self.target_url for domain in self.allowed_domains):
            logging.error("Domain not allowed: %s", self.target_url)
            raise ValueError("Domain not allowed. Update allowed_domains in the script.")

    def scan(self) -> None:
        logging.info("Starting XSS scan on %s", self.target_url)
        print(f"[*] Starting XSS scan on: {self.target_url}\n")

        for payload in self.payloads:
            self._check_payload(payload)
            time.sleep(1)

        print("\n[*] Scan finished. Check xss_results.txt and xss_scan.log for details.")

    def _check_payload(self, payload: str) -> None:
        full_url = f"{self.target_url}{payload}"
        print(f"[+] Testing payload on: {full_url}")

        try:
            response = requests.get(full_url, timeout=10)
            response.raise_for_status()

            if payload in response.text:
                message = f"XSS vulnerability detected at: {full_url}"
                logging.info(message)
                print(f"[!] {message}")
                self._log_vulnerability(full_url)
            else:
                logging.info("No XSS reflected at: %s", full_url)

        except requests.exceptions.RequestException as error:
            logging.error("Request failed: %s", error)
            print(f"[x] Request failed: {error}")

    def _log_vulnerability(self, url: str) -> None:
        with open("xss_results.txt", "a", encoding="utf-8") as f:
            f.write(f"XSS vulnerability detected at: {url}\n")


if __name__ == "__main__":
    target = input("Enter the URL to scan for XSS: ").strip()

    try:
        scanner = XSSScanner(target)
        scanner.scan()
    except ValueError as e:
        print(f"[!] {e}")
