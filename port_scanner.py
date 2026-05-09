#!/usr/bin/env python3
"""
======================================================
  Network Port Scanner & Vulnerability Reporter
  INSA Summer Camp — Cybersecurity Track
======================================================
  Description : Scans open TCP ports, grabs service
                banners, and generates an HTML report.
  Author      : [Your Name]
  Language    : Python 3
  Usage       : python port_scanner.py <target> [options]
  Example     : python port_scanner.py 192.168.56.101 -p 1-1024 -t 100
======================================================
  !! LEGAL DISCLAIMER !!
  Only use this tool on systems you own or have
  explicit written permission to test. Unauthorized
  scanning may be illegal in your jurisdiction.
======================================================
"""

import socket
import threading
import argparse
import sys
import datetime
from queue import Queue

# ─────────────────────────────────────────
#  KNOWN SERVICES DATABASE
#  Maps port → (service_name, risk_level, reason)
# ─────────────────────────────────────────
KNOWN_SERVICES = {
    21:   ("FTP",        "HIGH",   "Transmits credentials in plaintext"),
    22:   ("SSH",        "MEDIUM", "Secure but vulnerable to brute-force"),
    23:   ("Telnet",     "HIGH",   "Completely unencrypted protocol"),
    25:   ("SMTP",       "MEDIUM", "Mail server, check for open relay"),
    53:   ("DNS",        "MEDIUM", "DNS amplification attack risk"),
    80:   ("HTTP",       "MEDIUM", "Web server, large attack surface"),
    110:  ("POP3",       "HIGH",   "Plaintext mail retrieval"),
    111:  ("RPCBind",    "HIGH",   "Remote procedure call, often exploitable"),
    135:  ("MS-RPC",     "HIGH",   "Windows RPC, many known CVEs"),
    139:  ("NetBIOS",    "HIGH",   "Legacy Windows sharing, easily exploited"),
    143:  ("IMAP",       "MEDIUM", "Mail access, check for plaintext auth"),
    443:  ("HTTPS",      "LOW",    "Encrypted web — check certificate validity"),
    445:  ("SMB",        "HIGH",   "EternalBlue / WannaCry attack vector"),
    512:  ("rexec",      "HIGH",   "Remote execution, deprecated and insecure"),
    513:  ("rlogin",     "HIGH",   "Insecure remote login"),
    514:  ("rsh",        "HIGH",   "Remote shell without authentication"),
    1099: ("Java-RMI",   "HIGH",   "Java RMI deserialization exploits"),
    1524: ("Bindshell",  "CRITICAL","Metasploitable backdoor"),
    2049: ("NFS",        "HIGH",   "Network File System, check exports"),
    3306: ("MySQL",      "HIGH",   "Database exposed to network"),
    3632: ("distcc",     "HIGH",   "Remote code execution via distcc"),
    5432: ("PostgreSQL", "HIGH",   "Database exposed to network"),
    5900: ("VNC",        "HIGH",   "Remote desktop, check authentication"),
    6000: ("X11",        "HIGH",   "X Window System, no auth by default"),
    6667: ("IRC",        "MEDIUM", "IRC often used for C2 botnets"),
    8009: ("AJP",        "HIGH",   "Ghostcat vulnerability (CVE-2020-1938)"),
    8080: ("HTTP-Alt",   "MEDIUM", "Alternate web server"),
    8180: ("HTTP-Alt",   "MEDIUM", "Tomcat default port"),
    8443: ("HTTPS-Alt",  "LOW",    "Alternate HTTPS port"),
}

RISK_COLORS = {
    "CRITICAL": "#8B0000",
    "HIGH":     "#E74C3C",
    "MEDIUM":   "#F39C12",
    "LOW":      "#27AE60",
    "INFO":     "#2980B9",
    "UNKNOWN":  "#95A5A6",
}

open_ports = []
banners    = {}
lock       = threading.Lock()
port_queue = Queue()


# ─────────────────────────────────────────
#  BANNER GRABBING
# ─────────────────────────────────────────
def grab_banner(ip, port):
    """Attempt to grab the service banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))

        # Send probe for HTTP ports, otherwise just read
        if port in (80, 8080, 8180, 8443, 443):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        # Return only the first meaningful line
        first_line = banner.split("\n")[0][:120]
        return first_line if first_line else "No banner"

    except Exception:
        return "No banner"


# ─────────────────────────────────────────
#  SCANNER WORKER
# ─────────────────────────────────────────
def scan_worker(ip):
    """Worker thread: pull ports from queue and scan."""
    while not port_queue.empty():
        port = port_queue.get()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:  # Port is open
                banner = grab_banner(ip, port)
                with lock:
                    open_ports.append(port)
                    banners[port] = banner

        except Exception:
            pass
        finally:
            port_queue.task_done()


# ─────────────────────────────────────────
#  HTML REPORT GENERATOR
# ─────────────────────────────────────────
def generate_html_report(target, scan_time, port_range):
    """Generate a styled HTML vulnerability report."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = ""
    for port in sorted(open_ports):
        service, risk, reason = KNOWN_SERVICES.get(
            port, ("Unknown", "UNKNOWN", "Service not in local database")
        )
        banner  = banners.get(port, "N/A")
        color   = RISK_COLORS.get(risk, "#95A5A6")
        badge   = f'<span style="background:{color};color:white;padding:2px 10px;border-radius:4px;font-size:12px">{risk}</span>'
        rows += f"""
        <tr>
            <td><strong>{port}</strong></td>
            <td>{service}</td>
            <td>{badge}</td>
            <td style="font-family:monospace;font-size:12px;color:#555">{banner[:100]}</td>
            <td>{reason}</td>
        </tr>"""

    summary_counts = {}
    for port in open_ports:
        _, risk, _ = KNOWN_SERVICES.get(port, ("", "UNKNOWN", ""))
        summary_counts[risk] = summary_counts.get(risk, 0) + 1

    summary_html = " &nbsp;|&nbsp; ".join(
        f'<span style="color:{RISK_COLORS[r]};font-weight:bold">{r}: {c}</span>'
        for r, c in sorted(summary_counts.items())
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Scan Report — {target}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 40px; background: #f4f6f9; color: #333; }}
  .header {{ background: linear-gradient(135deg, #1F4E79, #2E75B6); color: white;
             padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
  .header h1 {{ margin: 0; font-size: 28px; }}
  .header p  {{ margin: 5px 0 0; opacity: 0.85; }}
  .meta {{ display: flex; gap: 30px; margin-bottom: 25px; flex-wrap: wrap; }}
  .meta-box {{ background: white; border-radius: 8px; padding: 15px 25px;
               box-shadow: 0 2px 6px rgba(0,0,0,.08); flex: 1; min-width: 150px; }}
  .meta-box .label {{ font-size: 11px; color: #888; text-transform: uppercase; }}
  .meta-box .value {{ font-size: 22px; font-weight: bold; color: #1F4E79; }}
  table {{ width: 100%; border-collapse: collapse; background: white;
           border-radius: 10px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.08); }}
  th {{ background: #1F4E79; color: white; padding: 12px 15px; text-align: left; font-size: 13px; }}
  td {{ padding: 11px 15px; border-bottom: 1px solid #eee; font-size: 13px; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f0f7ff; }}
  .footer {{ margin-top: 30px; font-size: 12px; color: #999; text-align: center; }}
  .disclaimer {{ background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px;
                 padding: 12px 20px; margin-bottom: 25px; font-size: 13px; }}
</style>
</head>
<body>

<div class="header">
  <h1>&#128274; Network Port Scanner — Vulnerability Report</h1>
  <p>Target: <strong>{target}</strong> &nbsp;|&nbsp; Generated: {now}</p>
</div>

<div class="disclaimer">
  <strong>&#9888; Disclaimer:</strong> This scan was performed on an authorized test system only.
  Unauthorized port scanning may violate local and international law.
</div>

<div class="meta">
  <div class="meta-box"><div class="label">Target Host</div><div class="value">{target}</div></div>
  <div class="meta-box"><div class="label">Open Ports</div><div class="value">{len(open_ports)}</div></div>
  <div class="meta-box"><div class="label">Port Range</div><div class="value">{port_range}</div></div>
  <div class="meta-box"><div class="label">Scan Duration</div><div class="value">{scan_time:.1f}s</div></div>
</div>

<p><strong>Risk Summary:</strong> &nbsp;{summary_html}</p>

<table>
  <thead>
    <tr>
      <th>Port</th>
      <th>Service</th>
      <th>Risk Level</th>
      <th>Banner</th>
      <th>Finding</th>
    </tr>
  </thead>
  <tbody>
    {rows if rows else '<tr><td colspan="5" style="text-align:center;color:#888">No open ports found.</td></tr>'}
  </tbody>
</table>

<div class="footer">
  Generated by Network Port Scanner v1.0 &nbsp;|&nbsp; INSA Summer Camp — Cybersecurity Track
</div>
</body>
</html>"""

    filename = f"report_{target.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w") as f:
        f.write(html)
    return filename


# ─────────────────────────────────────────
#  PLAIN TEXT REPORT
# ─────────────────────────────────────────
def print_report(target, scan_time):
    """Print a summary to the terminal."""
    print("\n" + "=" * 60)
    print(f"  SCAN COMPLETE — {target}")
    print("=" * 60)
    print(f"  Open ports found : {len(open_ports)}")
    print(f"  Scan duration    : {scan_time:.2f} seconds")
    print("-" * 60)
    print(f"  {'PORT':<8} {'SERVICE':<14} {'RISK':<10} BANNER")
    print("-" * 60)

    for port in sorted(open_ports):
        service, risk, _ = KNOWN_SERVICES.get(port, ("Unknown", "UNKNOWN", ""))
        banner = banners.get(port, "N/A")[:50]
        print(f"  {port:<8} {service:<14} {risk:<10} {banner}")

    print("=" * 60)


# ─────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Network Port Scanner & Vulnerability Reporter — INSA Summer Camp"
    )
    parser.add_argument("target",           help="Target IP or hostname")
    parser.add_argument("-p", "--ports",    default="1-1024",
                        help="Port range, e.g. 1-1024 (default) or 22,80,443")
    parser.add_argument("-t", "--threads",  type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--no-report",      action="store_true",
                        help="Skip HTML report generation")

    args = parser.parse_args()
    target = args.target

    # ── Resolve hostname ──
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve hostname: {target}")
        sys.exit(1)

    # ── Ethical consent prompt ──
    print("\n" + "!" * 60)
    print("  WARNING: Unauthorized port scanning may be illegal.")
    print("  Only scan systems you own or have permission to test.")
    print("!" * 60)
    confirm = input(f"\n  Target: {ip}\n  Confirm you have authorization? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[ABORTED] Scan cancelled.")
        sys.exit(0)

    # ── Parse port range ──
    ports_to_scan = []
    if "-" in args.ports:
        start, end = args.ports.split("-")
        ports_to_scan = list(range(int(start), int(end) + 1))
    else:
        ports_to_scan = [int(p) for p in args.ports.split(",")]

    for port in ports_to_scan:
        port_queue.put(port)

    port_range_str = args.ports
    print(f"\n[*] Scanning {ip} | Ports: {port_range_str} | Threads: {args.threads}")
    print("[*] Please wait...\n")

    # ── Launch threads ──
    start_time = datetime.datetime.now()
    threads = []
    for _ in range(min(args.threads, len(ports_to_scan))):
        t = threading.Thread(target=scan_worker, args=(ip,))
        t.daemon = True
        t.start()
        threads.append(t)

    port_queue.join()
    scan_time = (datetime.datetime.now() - start_time).total_seconds()

    # ── Output results ──
    print_report(ip, scan_time)

    if not args.no_report:
        report_file = generate_html_report(ip, scan_time, port_range_str)
        print(f"\n[+] HTML report saved: {report_file}")
        print("[*] Open the HTML file in your browser to view the full report.\n")


if __name__ == "__main__":
    main()
