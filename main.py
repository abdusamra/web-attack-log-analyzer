import argparse
from pathlib import Path
from collections import Counter, defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

# ---------------------------------------
# Attack pattern database
# ---------------------------------------
ATTACK_PATTERNS = {
    "SQL Injection": [
        "union", "select", "sleep(", "' or 1=1", "--", "#", "%27",
        "information_schema", "benchmark(", "order by", "or true", "or 1=1"
    ],
    "XSS": [
        "<script", "onerror=", "alert(", "document.cookie",
        "%3cscript%3e", "javascript:"
    ],
    "Path Traversal": [
        "../", "..%2f", "..%5c", "/etc/passwd",
        "/proc/self/environ", "c:\\windows"
    ],
    "File Inclusion": [
        "php://input", "php://filter", "data://", "expect://",
        "base64_", "include", "require"
    ],
    "Command Injection": [
        "wget ", "curl ", "chmod", "cat /", ";ls", ";pwd", ";id",
        "||", "&&"
    ],
    "Bad Bots / Scanners": [
        "sqlmap", "nmap", "acunetix", "wpscan",
        "nikto", "fimap"
    ],
    "Admin Enumeration": [
        "/admin", "/phpmyadmin", "/wp-login",
        "/shell", "/dashboard"
    ]
}

# ---------------------------------------
# CLI argument parser
# ---------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Web Attack Log Analyzer v1.0"
    )
    parser.add_argument(
        "--log-file",
        required=True,
        help="Path to web server access log file"
    )
    parser.add_argument(
        "--output",
        help="Path to save Markdown report"
    )
    return parser.parse_args()


# ---------------------------------------
# Attack detection
# ---------------------------------------
def detect_attacks(line):
    findings = []
    lower = line.lower()

    for attack_type, patterns in ATTACK_PATTERNS.items():
        for p in patterns:
            if p in lower:
                findings.append((attack_type, p))
    return findings


# ---------------------------------------
# Log analyzer core
# ---------------------------------------
def analyze(log_path: Path):
    method_counter = Counter()
    status_counter = Counter()
    suspicious_ips = Counter()
    attack_details = defaultdict(list)
    total_requests = 0

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            original_line = line.strip()
            if not original_line:
                continue

            total_requests += 1
            parts = original_line.split()

            # Extract IP
            ip = parts[0] if parts else "unknown"

            # Detect HTTP method
            methods = {"get", "post", "put", "delete", "head", "options"}
            method = next((p.upper() for p in parts if p.lower() in methods), None)
            if method:
                method_counter[method] += 1

            # Detect status code (last 3-digit number)
            status = next((p for p in reversed(parts) if p.isdigit() and len(p) == 3), None)
            if status:
                status_counter[status] += 1

            # Attack detection
            findings = detect_attacks(original_line)
            for attack_type, pattern in findings:
                suspicious_ips[ip] += 1
                attack_details[attack_type].append((ip, pattern, original_line))

    return {
        "total": total_requests,
        "methods": method_counter,
        "statuses": status_counter,
        "suspicious_ips": suspicious_ips,
        "attack_details": attack_details,
    }


# ---------------------------------------
# Markdown report writer
# ---------------------------------------
def write_report(stats, output: Path):
    with output.open("w", encoding="utf-8") as f:
        f.write("# Web Attack Log Report\n\n")
        f.write(f"Total requests: **{stats['total']}**\n\n")

        f.write("## HTTP Methods\n")
        if stats["methods"]:
            for m, c in stats["methods"].most_common():
                f.write(f"- {m}: {c}\n")
        else:
            f.write("- No methods parsed\n")
        f.write("\n")

        f.write("## Status Codes\n")
        if stats["statuses"]:
            for s, c in stats["statuses"].most_common():
                f.write(f"- {s}: {c}\n")
        else:
            f.write("- No status codes parsed\n")
        f.write("\n")

        f.write("## Suspicious IPs\n")
        if stats["suspicious_ips"]:
            for ip, count in stats["suspicious_ips"].most_common():
                f.write(f"- {ip}: {count} suspicious requests\n")
        else:
            f.write("No suspicious activity detected.\n")
        f.write("\n")

        f.write("## Detected Attacks\n")
        if stats["attack_details"]:
            for attack_type, entries in stats["attack_details"].items():
                f.write(f"### {attack_type}\n")
                for ip, pattern, line in entries[:10]:
                    f.write(f"- **IP:** {ip}\n")
                    f.write(f"  - Pattern: `{pattern}`\n")
                    f.write(f"  - Request: `{line}`\n")
                f.write("\n")
        else:
            f.write("No attacks found.\n")


# ---------------------------------------
# Main entry
# ---------------------------------------
def main():
    args = parse_args()
    log_path = Path(args.log_file)

    print(Fore.CYAN + "Analyzing log file...")
    stats = analyze(log_path)

    print(Fore.GREEN + f"Total requests analyzed: {stats['total']}")

    attack_count = sum(len(v) for v in stats["attack_details"].values())
    if attack_count > 0:
        print(Fore.RED + f"Suspicious events detected: {attack_count}")
    else:
        print(Fore.YELLOW + "No suspicious activity found.")

    if args.output:
        write_report(stats, Path(args.output))
        print(Fore.GREEN + f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
