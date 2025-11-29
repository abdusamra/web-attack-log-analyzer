# Web Attack Log Analyzer

A Python tool that scans web server access logs, detects suspicious patterns like SQL injection, XSS, path traversal, and command injection, and generates a clean Markdown report.

This project is built to help with security analysis, forensic investigations, and general log intelligence.  
Simple to use, easy to extend, and works on any standard Apache/Nginx-style access log.

---

## Features

- Detects common web attacks:
  - SQL injection  
  - XSS  
  - Path traversal  
  - File inclusion  
  - Command injection  
  - Bad bots and scanners  
  - Admin enumeration  
- Summarizes HTTP methods and status codes  
- Flags suspicious IPs  
- Generates a readable Markdown report  
- Colorful CLI output  
- Works on Python 3.12+ / 3.14  

---

## Project Structure

web-attack-log-analyzer/
│
├── main.py
├── requirements.txt
├── README.md
│
└── sample-logs/
├── apache-clean.log
├── apache-attack.log


---

## Installation

Create and activate a virtual environment:

```bash
python -m venv venv
.\venv\Scripts\activate    # Windows


Install required dependencies:

pip install -r requirements.txt

Usage

Analyze a log file:

python main.py --log-file sample-logs/apache-clean.log


Generate a Markdown report:

python main.py --log-file sample-logs/apache-attack.log --output attack-report.md

Example Terminal Output
Analyzing log file...
Total requests analyzed: 5
Suspicious events detected: 9
Report saved to attack-report.md

Example Report (Markdown)
# Web Attack Log Report

Total requests: **5**

## Suspicious IPs
- 10.0.0.12: 3 suspicious requests
- 103.15.22.77: 1 suspicious request

## Detected Attacks
### SQL Injection
- IP: 10.0.0.12
  - Pattern: union
  - Request: GET /index.php?id=1 union select 1,2 HTTP/1.1

Sample Logs

Two example logs are included:

apache-clean.log — normal traffic

apache-attack.log — multiple real-world attack patterns

These help you test the tool without needing your own logs.

Roadmap

Planned improvements:

HTML report with charts

Export suspicious IPs as CSV

JSON log support

Add severity scoring

Lookups against IP reputation feeds

License

MIT License — free to use, modify, and share.

Why This Project Matters

This tool demonstrates real cybersecurity skills:

log parsing

attack pattern detection

report generation

CLI tool design

practical security analysis