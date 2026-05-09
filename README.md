# Network Port Scanner & Vulnerability Reporter
### INSA Summer Camp — Cybersecurity Track Project

---

## Overview
A Python command-line tool that scans open TCP ports on a target host, grabs service banners to identify running software, classifies risk levels, and generates a professional HTML vulnerability report.

---

## Requirements
- Python 3.7+
- No external libraries required (uses only Python standard library)

Optional (for advanced features):
```
pip install colorama    # colored terminal output
pip install jinja2      # advanced HTML templating
```

---

## Usage

```bash
# Basic scan (ports 1–1024)
python port_scanner.py 192.168.56.101

# Custom port range
python port_scanner.py 192.168.56.101 -p 1-65535

# Specific ports
python port_scanner.py 192.168.56.101 -p 22,80,443,3306

# Control thread count (faster = more threads)
python port_scanner.py 192.168.56.101 -p 1-1024 -t 200

# Skip HTML report
python port_scanner.py 192.168.56.101 --no-report
```

---

## Project Structure

```
port_scanner/
├── port_scanner.py       ← Main script (all-in-one)
├── report_<ip>_<date>.html   ← Auto-generated scan report
└── README.md
```

---

## Features
- Multi-threaded TCP port scanning (100 threads default)
- Banner grabbing for service fingerprinting
- Risk classification: CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
- HTML report with color-coded severity table
- Mandatory ethical consent prompt before scanning

---

## Safe Testing Environment
Download **Metasploitable 2** from Rapid7 to test safely:
https://sourceforge.net/projects/metasploitable/

Set it up on VirtualBox with a Host-Only adapter. It will never connect to the internet.

---

## Legal Disclaimer
> Only use this tool on systems you own or have **explicit written authorization** to scan.
> Unauthorized port scanning may be illegal in your jurisdiction.
> This project is for educational purposes only.

---

*Project by [Your Name] — INSA Summer Camp Cybersecurity Track*
