import argparse
import time
import os

from logsentry.parser import extract_ips_from_log
from logsentry.api import check_ip_virustotal


def main() -> None:
    """
    Main entry point for LogSentry.

    Handles argument parsing, environment variable validation,
    extracts suspicious IPs from the provided log file, and
    orchestrates the VirusTotal API checks.
    """

    banner = r"""
         _                ____             _                  
        | |    ___   __ _/ ___|  ___ _ __ | |_ _ __ _   _ 
        | |   / _ \ / _` \___ \ / _ \ '_ \| __| '__| | | |
        | |__| (_) | (_| |___) |  __/ | | | |_| |  | |_| |
        |_____\___/ \__, |____/ \___|_| |_|\__|_|   \__, |
                    |___/                           |___/ 
        """
    print(banner)

    parser = argparse.ArgumentParser(description="LogSentry: CLI tool to analyze log IPs.")
    parser.add_argument("-l", "--log", required=True, help="Path to the log file to analyze")
    parser.add_argument("-t", "--threshold", type=int, default=5,
                        help="Minimum number of failed attempts to consider an IP suspicious")
    parser.add_argument("--no-vt", action="store_true", help="Skip VirusTotal lookups")
    parser.add_argument("--premium", action="store_true", help="ONLY PREMIUM API: skips waiting time between api calls")
    parser.add_argument("-o", "--output", help="Export results to a CSV file with the given filename")

    args = parser.parse_args()

    print(f"[*] Analyzing log file: {args.log}")

    if not args.no_vt and not os.environ.get("VT_API_KEY"):
        print("[!] Error: VT_API_KEY environment variable is not set.")
        print("[-] Please set it first: export VT_API_KEY='your_api_key'")
        print("[-] Or run the tool with --no-vt for local mode.")
        return

    ips = extract_ips_from_log(args.log, args.threshold)

    print(f"[*] Found {len(ips)} unique IPs.")

    total = len(ips)
    results = []

    for index, ip in enumerate(ips):
        if args.no_vt:  # Fast path: Just announce IP is found, no API calls.
            print(f"[*] IP {ip} found (Skipping VirusTotal)")
            results.append({"ip": ip, "malicious_engines": "N/A"})
        else:
            print(f"\n[*] Checking IP: {ip}...")
            vt_data = check_ip_virustotal(ip)
            result = evaluate_vt_data(ip, vt_data)
            results.append(result)

        if index < total - 1 and not args.premium:
            for remaining in range(15, 0, -1):
                print(f"\r[!] Rate limit: waiting {remaining}s...", end="", flush=True)
                time.sleep(1)
            print()

    if args.output and results:
        # Deferred import: reporter is only needed when --output is set
        from logsentry.reporter import export_to_csv
        export_to_csv(results, args.output)
        print(f"\n[*] Results exported to {args.output}")


def evaluate_vt_data(ip: str, vt_data: dict) -> dict:
    """
    Evaluates the VirusTotal API response, prints the results,
    and returns a summary dict for reporting purposes.

    Args:
        ip (str): The IP address that was checked.
        vt_data (dict): The JSON response payload from VirusTotal.

    Returns:
        dict: A dictionary with 'ip' and 'malicious_engines' keys.
    """
    malicious = 0

    if vt_data and "data" in vt_data:
        stats = vt_data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)

        if malicious > 0:
            print(f"[!] Suspicious IP detected: {ip} -> VirusTotal: {malicious} engines flagged as malicious")
        else:
            print(f"[-] IP {ip} -> VirusTotal: clean")
    else:
        print(f"[-] Could not retrieve data for {ip}")

    return {"ip": ip, "malicious_engines": malicious}


if __name__ == "__main__":
    main()