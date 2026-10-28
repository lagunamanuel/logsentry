import re

from collections import Counter

# Markers that identify a failed SSH authentication attempt in auth logs
FAILED_LOGIN_MARKERS = ("Failed password", "Invalid user")


def is_failed_login(line: str) -> bool:
    """
    Returns True if the log line records a failed authentication attempt.

    Args:
        line (str): A single line from the log file.

    Returns:
        bool: True if the line contains a known failed-login marker.
    """
    return any(marker in line for marker in FAILED_LOGIN_MARKERS)


def extract_ips_from_log(log_path: str, threshold: int = 5) -> list:
    """
    Reads a text log file and extracts valid IPv4 addresses
    that exceed the given failure threshold.

    Args:
        log_path (str): Path to the log file
        threshold (int): Minimum number of occurrences required to extract an IP.

    Returns:
        list: A list of string IPv4 addresses that met or exceeded the threshold.
    """


                #            250-255|200-249 |0-199         *3    250-255|200-249 |0-199
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    try:
        with open(log_path, 'r') as file:

            ip_counts = Counter()
            for line in file:
                if is_failed_login(line):
                    ip_counts.update(re.findall(ipv4_pattern, line))

            return [ip for ip, count in ip_counts.items() if count >= threshold]

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_path}")

        return []
