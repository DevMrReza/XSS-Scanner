# 🚀 XSS Scanner

A lightweight yet powerful Python-based **XSS (Cross-Site Scripting) scanner** for security researchers and developers who want to test and harden their web applications against common XSS vulnerabilities.

> ⚠️ **Legal Notice:** This tool is intended **only** for testing applications you own or have explicit permission to test. Misuse may be illegal.

---

## ✨ Features

- 🔍 **Automated XSS Testing** — Tests the target with common payloads and checks reflection.
- 📊 **Clear Reporting** — Saves logs in `xss_scan.log` and vulnerable URLs in `xss_results.txt`.
- 🖥️ **Simple CLI Workflow** — Run the script and enter your target, that's it.
- 🔧 **Extensible Payloads** — Add/modify payloads easily.
- 🛡️ **Domain Allowlist** — Prevents unauthorized scans.

---

## 📦 Requirements

- Python 3.x  
- Libraries:
  - `requests`
  - `validators`

Install:

```bash
pip install requests validators
````

---

## 🔧 Installation

```bash
git clone https://github.com/DevMrReza/XSS-Scanner.git
cd XSS-Scanner
```

---

## ▶️ Usage

```bash
python xss_scanner.py
```

When prompted, enter a target URL such as:

```
https://example.com/search?q=
```

💡 **Tip:** Best results come from URLs with parameters (`?q=`, `?id=`, etc.)

---

## ⚙️ Configuration

Inside the script, adjust which domains are allowed:

```python
self.allowed_domains = ["example.com", "yourdomain.com"]
```

Customize or add new payloads:

```python
self.payloads = [
    "<script>alert('XSS')</script>",
    "'><img src=x onerror=alert('XSS')>"
]
```

---

## 📁 Output Files

### **xss_scan.log**

Contains:

* Request events
* Activity logs
* Errors

### **xss_results.txt**

Contains:

* URLs where the payload was reflected
* Possible XSS findings

---

## 📸 Example Output

```
[*] Starting XSS scan on: https://example.com/?q=
[+] Testing payload on: https://example.com/?q=<script>alert('XSS')</script>
[!] XSS vulnerability detected at: https://example.com/?q=<script>alert('XSS')</script>
```

---

## ⚖️ Disclaimer

This tool is intended for **ethical hacking, research, and educational use only**.
You are responsible for complying with all laws.
The author assumes **no liability** for misuse.

---
