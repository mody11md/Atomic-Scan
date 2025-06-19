#  Atomic-Scanner – Recon Toolkit

> **Educational Purpose Only:** This tool was developed as part of a project and is intended solely for educational and ethical use.

---

## 🔍 Overview

Atomic-Scan is a fast, modular, and easy-to-use reconnaissance toolkit designed to streamline common information-gathering tasks during penetration testing or bug bounty hunting. It integrates various functionalities into one script, reducing the need to switch between multiple tools.

                █████╗ ████████╗ ██████╗ ███╗   ███╗██╗ ██████╗     ███████╗  ██████╗  █████╗ ███╗   ██╗
               ██╔══██╗╚══██╔══╝██╔═══██╗████╗ ████║██║██╔════╝     ██╔════╝ ██╔════╝ ██╔══██╗████╗  ██║
               ███████║   ██║   ██║   ██║██╔████╔██║██║██║          ███████║ ██║      ███████║██╔██╗ ██║
               ██╔══██║   ██║   ██║   ██║██║╚██╔╝██║██║██║   ██║    ╔══╝  ██ ██║   ██║██╔══██║██║╚██╗██║
               ██║  ██║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║╚██████╔╝    ███████╗╚ ██████╔╝██║  ██║██║ ╚████║
               ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝ ╚═════╝      ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
           
                                          ⚡ Fast • Modular • Recon Toolkit ⚡
### Features:
- WHOIS Lookup
- DNS Enumeration (A, MX, TXT, NS records)
- Subdomain Enumeration using CRT.SH API
- Simple Port Scanning
- Banner Grabbing
- Wappalyzer Technology Detection
- Directory Enumeration

---

## 📦 Installation

### Clone the Repository
```bash
git clone https://github.com/mody11md/Atomic-Scan.git
cd Atomic-Scanner
```
### Install Required Packages
```python
pip install python-Wappalyzer dnspython python-whois requests pyppeteer whatweb
```
---
## Usage
```python
python3 atomic.py <domain> [flags]
```
| Flag        | Description                              |
|-------------|------------------------------------------|
| `--whois`   | Perform basic WHOIS lookup               |
| `--dnsenum` | Perform DNS Enumeration                  |
| `--crtenum` | Subdomain Enumeration using CRT.SH API   |
| `--direnum` | Directory Enumeration                    |
| `--portscan`| Port Scanning                            |
| `--V`       | Banner Grabbing                          |
| `--W`       | Wappalyzer Lookup                        |
| `--what`    | Technology Detection using WhatWeb       |
| `--all`     | Run all operations at once               |
### Example Commands
**Basic usage:**
```python
python3 atomic.py example.com --whois --dnsenum --V
```
**Full scan:**
```python
python3 atomic.py example.com --all
```
---
## Output & Reporting
All results are printed to the console and saved in Report.txt for future reference.
