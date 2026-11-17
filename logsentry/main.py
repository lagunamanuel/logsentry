import argparse
import time
import os

from logsentry.parser import extract_ips_from_log, is_public_ip
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
    parser.add_argument("-w", "--window", type=int, default=None, metavar="SECONDS",
                        help="Require the failed-login threshold per IP within this many seconds")
    parser.add_argument("--no-vt", action="store_true", help="Skip VirusTotal lookups")
    parser.add_argument("--premium", action="store_true", help="ONLY PREMIUM API: skips waiting time between api calls")
    parser.add_argument("-o", "--output", help="Export results to a CSV file with the given filename")

    args = parser.parse_args()

    if args.window is not None and args.window <= 0:
        parser.exit(
            2,
            "[!] Error: --window must be a positive number of seconds\n",
        )

    if args.threshold <= 0:
        parser.exit(
            2,
            "[!] Error: --threshold must be positive\n",
        )
    if args.output:
        try:
            same_file = (
                    os.path.realpath(args.log)
                    == os.path.realpath(args.output)
            )
            if (
                    not same_file
                    and os.path.exists(args.log)
                    and os.path.exists(args.output)
            ):
                same_file = os.path.samefile(args.log, args.output)
        except OSError as exc:
            parser.exit(2, f"[!] Error: Cannot compare input/output paths: {exc}\n")

        if same_file:
            parser.exit(
                2,
                "[!] Error: --output must not refer to the input log file\n",
            )

    print(f"[*] Analyzing log file: {args.log}")

    if not args.no_vt and not os.environ.get("VT_API_KEY"):
        parser.exit(
            2,
            "[!] Error: VT_API_KEY environment variable is not set.\n"
            "[*] Set VT_API_KEY or use --no-vt for local mode.\n",
        )

    try:
        ips = extract_ips_from_log(
            args.log,
            args.threshold,
            window_seconds=args.window,
        )
    except ValueError as exc:
        parser.exit(2, f"[!] Error: {exc}\n")

    print(f"[*] Found {len(ips)} unique IPs.")

    total = len(ips)
    results = []

    for index, ip in enumerate(ips):
        if args.no_vt:  # Fast path: Just announce IP is found, no API calls.
            print(f"[*] IP {ip} found (Skipping VirusTotal)")
            results.append({"ip": ip, "malicious_engines": "N/A"})
        elif not is_public_ip(ip):
            print(f"[*] IP {ip} is not publicly routable, skipping VirusTotal")
            results.append({"ip": ip, "malicious_engines": "N/A"})
        else:
            print(f"\n[*] Checking IP: {ip}...")
            vt_data = check_ip_virustotal(ip)
            result = evaluate_vt_data(ip, vt_data)
            results.append(result)

        if index < total - 1 and not args.premium and not args.no_vt and is_public_ip(ip):
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
    Evaluates a VirusTotal response and returns a reporting summary.

    Returns 'N/A' when a valid malicious-engine count is unavailable,
    so failed lookups cannot be confused with zero detections.

    Args:
        ip (str): The IP address that was checked.
        vt_data (dict): The JSON response payload from VirusTotal.

    Returns:
        dict: A summary with 'ip' and 'malicious_engines' keys.
    """
    try:
        malicious = vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
    except (KeyError, TypeError):
        malicious = None

    if (
            not isinstance(malicious, int)
            or isinstance(malicious, bool)
            or malicious < 0
    ):
        print(f"[!] Error: Could not retrieve valid VirusTotal data for {ip}")
        return {"ip": ip, "malicious_engines": "N/A"}

    if malicious > 0:
        print(
            f"[!] Suspicious IP detected: {ip} -> "
            f"VirusTotal: {malicious} engines flagged as malicious"
        )
    else:
        print(f"[-] IP {ip} -> VirusTotal: clean")

    return {"ip": ip, "malicious_engines": malicious}


if __name__ == "__main__":
    main()
