import re

from collections import Counter


def extract_ips_from_log(log_path: str, threshold: int = 5) -> list:
    """
    Reads a text log file and extracts valid IPv4 addresses
    that exceed the given failure threshold.
    """


    ip_counts = {}
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    try:
        with open(log_path, 'r') as file:

            ip_counts = Counter()
            for line in file:
                ip_counts.update(re.findall(ipv4_pattern, line))

            return [ip for ip, count in ip_counts.items() if count >= threshold]

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_path}")

        return []
