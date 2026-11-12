import re

from collections import Counter
import ipaddress
from datetime import datetime
from typing import Optional

# Markers that identify a failed SSH authentication attempt in auth logs
FAILED_LOGIN_MARKERS = ("Failed password", "Invalid user")

# Matches an IPv4 address, validating each octet is between 0-255:
# (250-255 | 200-249 | 0-199) three times followed by a dot, then once more
IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# Classic syslog timestamp, e.g. "Jul 20 08:12:01" (the log line carries no year)
SYSLOG_TIMESTAMP = re.compile(r'^(' + '|'.join(MONTHS) + r')\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})')

# ISO 8601 timestamp, e.g. "2026-07-20T08:12:01+02:00"
ISO_TIMESTAMP = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?')


def is_failed_login(line: str) -> bool:
    """
    Returns True if the log line records a failed authentication attempt.

    Args:
        line (str): A single line from the log file.

    Returns:
        bool: True if the line contains a known failed-login marker.
    """
    return any(marker in line for marker in FAILED_LOGIN_MARKERS)


def is_public_ip(ip: str) -> bool:
    """
    Returns True if the IP is globally routable on the internet.


    Private ranges (192.168.x.x, 10.x.x.x...), loopback and reserved
    blocks return False. Strings that are not valid IPs also return False.

    Args:
        ip (str): The IPv4 address to classify.

    Returns:
        bool: True if the address is public, False otherwise.
    """
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def parse_timestamp(line: str, year: Optional[int] = None) -> Optional[datetime]:
    """
    Extracts the timestamp at the start of a log line.

    Supports classic syslog ("Jul 20 08:12:01") and ISO 8601
    ("2026-07-20T08:12:01+02:00") formats. Syslog lines carry no year,
    so `year` is used (defaults to the current year).

    Args:
        line (str): A single line from the log file.
        year (Optional[int]): Year to assume for syslog timestamps.

    Returns:
        Optional[datetime]: The parsed timestamp, or None if the line has
        no recognisable timestamp.
    """
    iso = ISO_TIMESTAMP.match(line)
    if iso:
        try:
            # fromisoformat rejects a trailing "Z" before Python 3.11
            return datetime.fromisoformat(iso.group().replace("Z", "+00:00"))
        except ValueError:
            return None

    syslog = SYSLOG_TIMESTAMP.match(line)
    if syslog:
        month, day, hour, minute, second = syslog.groups()
        try:
            return datetime(year or datetime.now().year, MONTHS.index(month) + 1,
                            int(day), int(hour), int(minute), int(second))
        except ValueError:
            return None

    return None


def extract_ips_from_log(log_path: str, threshold: int = 5) -> list:
    """
    Reads a text log file and extracts valid IPv4 addresses found in
    failed-login lines (see `is_failed_login`) that reach the given threshold.

    Args:
        log_path (str): Path to the log file
        threshold (int): Minimum number of failed-login occurrences required to extract an IP.

    Returns:
        list: A list of string IPv4 addresses that met or exceeded the threshold.
    """


    try:
        with open(log_path, 'r') as file:

            ip_counts = Counter()
            for line in file:
                if is_failed_login(line):
                    ip_counts.update(re.findall(IPV4_PATTERN, line))

            return [ip for ip, count in ip_counts.items() if count >= threshold]

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_path}")

        return []
