import re

from collections import Counter
import ipaddress
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass

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

# Matches failed/accepted SSH authentication lines, capturing username and IP:
#   "Failed password for root from 1.2.3.4"
#   "Failed password for invalid user admin from 1.2.3.4"
#   "Accepted publickey for manuel from 1.2.3.4"
#   "Invalid user admin from 1.2.3.4"
EVENT_PATTERN = re.compile(
    r'(?:(?P<kind>Failed|Accepted) \S+ for (?:invalid user )?|Invalid user )'
    r'(?P<username>\S+) from (?P<ip>' + IPV4_PATTERN + r')'
)


@dataclass(frozen=True)
class LogEvent:
    """A parsed SSH authentication event."""
    ip: str
    kind: str  # "failed" or "accepted"
    username: str
    timestamp: Optional[datetime]


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


def parse_event(line: str, year: Optional[int] = None) -> Optional[LogEvent]:
    """
    Parses a single log line into a LogEvent.

    Recognises failed and accepted SSH authentication lines, including
    attempts against non-existent users ("Invalid user ...").

    Args:
        line (str): A single line from the log file.
        year (Optional[int]): Year to assume for syslog timestamps.

    Returns:
        Optional[LogEvent]: The parsed event, or None if the line is not
        an authentication event.
    """
    match = EVENT_PATTERN.search(line)
    if not match:
        return None

    kind = "accepted" if match.group("kind") == "Accepted" else "failed"
    return LogEvent(
        ip=match.group("ip"),
        kind=kind,
        username=match.group("username"),
        timestamp=parse_timestamp(line, year),
    )


def parse_events(log_path: str, year: Optional[int] = None) -> list[LogEvent]:
    """
    Reads an SSH authentication log into structured events.

    Preserves file order and events without timestamps.
    Lines not recognised by parse_event are ignored.

    Args:
        log_path (str): Path to the log file.
        year (Optional[int]): Year to assume for syslog timestamps.

    Returns:
        list[LogEvent]: Failed and accepted authentication events.

    Raises:
        OSError: If the log file cannot be opened or read.
    """
    if year is None:
        year = datetime.now().year

    events = []

    with open(log_path, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_event(line, year)
            if event is not None:
                events.append(event)

    return events

def has_burst(
    timestamps: list[datetime],
    threshold: int,
    window_seconds: int,
) -> bool:
    """
    Checks whether enough timestamps fall within a time window.

    The caller must supply failed-login timestamps for a single IP.
    The window boundary is inclusive. Input order is not modified.

    Args:
        timestamps (list[datetime]): Timestamps to examine.
        threshold (int): Minimum number of occurrences.
        window_seconds (int): Maximum duration between first and last occurrence.

    Returns:
        bool: True if any group reaches the threshold within the window.

    Raises:
        ValueError: If threshold or window_seconds is not positive, or
            timezone-aware and naive timestamps are mixed.
    """
    if threshold <= 0:
        raise ValueError("threshold must be positive")

    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    awareness = {timestamp.utcoffset() is not None for timestamp in timestamps}
    if len(awareness) > 1:
        raise ValueError("Cannot mix timezone-aware and naive timestamps")

    ordered = sorted(timestamps)
    window = timedelta(seconds=window_seconds)

    for end in range(threshold - 1, len(ordered)):
        start = end - threshold + 1
        if ordered[end] - ordered[start] <= window:
            return True

    return False


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
