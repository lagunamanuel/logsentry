import argparse
import time

from logsentry.parser import extract_ips_from_log
from logsentry.api import check_ip_virustotal


def main():
    """
    Main entry point for LogSentry.
    Parses arguments, extracts IPs, and queries the VirusTotal API.
    """
    parser = argparse.ArgumentParser(description="LogSentry: CLI tool to analyze log IPs.")
    parser.add_argument("-l", "--log", required=True, help="Path to the log file to analyze")
    parser.add_argument("-t", "--threshold", type=int, default=5,
                        help="Minimum number of failed attempts to consider an IP suspicious")

    args = parser.parse_args()

    print(f"[*] Analyzing log file: {args.log}")
    ips = extract_ips_from_log(args.log, args.threshold)

    print(f"[*] Found {len(ips)} unique IPs.")

    total = len(ips)
    for index, ip in enumerate(ips):
        print(f"\n[*] Checking IP: {ip}...")
        vt_data = check_ip_virustotal(ip)

        if vt_data and "data" in vt_data:
            stats = vt_data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)

            if malicious > 0:
                print(f"[!] Suspicious IP detected: {ip} -> VirusTotal: {malicious} engines flagged as malicious")
            else:
                print(f"[-] IP {ip} -> VirusTotal: clean")
        else:
            print(f"[-] Could not retrieve data for {ip}")
        if index < total-1:
            for remaining in range(15, 0, -1):
                print(f"\r[!] Rate limit: waiting {remaining}s...", end="", flush=True)
                time.sleep(1)
            print()


if __name__ == "__main__":
    main()
