import argparse
from logsentry.parser import extract_ips_from_log
from logsentry.api import check_ip_virustotal


def main():
    """
    Main entry point for LogSentry.
    Parses arguments, extracts IPs, and queries the VirusTotal API.
    """
    parser = argparse.ArgumentParser(description="LogSentry: CLI tool to analyze log IPs.")
    parser.add_argument("--log", required=True, help="Path to the log file to analyze")

    args = parser.parse_args()

    print(f"[*] Analyzing log file: {args.log}")
    raw_ips = extract_ips_from_log(args.log)

    unique_ips = list(set(raw_ips))
    print(f"[*] Found {len(unique_ips)} unique IPs.")

    for ip in unique_ips:
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


if __name__ == "__main__":
    main()