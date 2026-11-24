import re

from collections import Counter, defaultdict
import ipaddress
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass

# Markers that identify a failed SSH authentication attempt in auth logs
FAILED_LOGIN_MARKERS = ("Failed password", "Invalid user")



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
# Capture the complete source token; parse_event validates it as IPv4.
EVENT_PATTERN = re.compile(
    r'(?:(?P<kind>Failed|Accepted) \S+ for (?:invalid user )?|Invalid user )'
    r'(?P<username>\S+) from (?P<ip>\S+)'
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
    Returns True for globally routable unicast addresses.

    Non-global addresses and multicast addresses are excluded from
    VirusTotal lookups. Invalid strings also return False.

    Args:
        ip (str): The IP address to classify.

    Returns:
        bool: Whether the address is eligible for a public-IP lookup.
    """
    try:
        address = ipaddress.ip_address(ip)
        return address.is_global and not address.is_multicast
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

    raw_ip = match.group("ip")
    try:
        address = ipaddress.IPv4Address(raw_ip)
    except ValueError:
        return None

    if str(address) != raw_ip:
        return None

    kind = "accepted" if match.group("kind") == "Accepted" else "failed"
    return LogEvent(
        ip=raw_ip,
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

# Match the SSH process after a supported timestamp.
_SSH_PROCESS = re.compile(r"\s+(\S+) sshd\[(\d+)\]:\s+")
_SOURCE_PORT = re.compile(r"\s+port ([0-9]+)(?=\s|$)")
_CONNECTION_END = (
    "Connection closed",
    "Connection reset",
    "Disconnected from",
    "Received disconnect",
)
_INVALID_USER_MATCH_SECONDS = 5


def _iter_failed_entries(lines, *, window_mode):
    """Yield (line number, failed event, replaced line number or None)."""
    pending = {}
    year = datetime.now().year

    for line_number, line in enumerate(lines):
        stamp = ISO_TIMESTAMP.match(line) or SYSLOG_TIMESTAMP.match(line)
        process = _SSH_PROCESS.match(line, stamp.end()) if stamp else None
        key = process.groups() if process else None
        message = line[process.end():] if process else ""

        if key is not None and message.startswith(_CONNECTION_END):
            pending.pop(key, None)
            continue

        event = parse_event(line, year)
        if event is None:
            continue

        replaced = None
        match = EVENT_PATTERN.match(message) if process else None

        if key is not None and match is not None:
            # Any subsequent authentication entry consumes the prior candidate.
            previous = pending.pop(key, None)
            port_match = _SOURCE_PORT.match(message, match.end())
            port = int(port_match.group(1)) if port_match else None

            if message.startswith("Invalid user ") and event.timestamp is not None:
                pending[key] = (line_number, event, port)
            elif (
                previous is not None
                and message.startswith("Failed password for invalid user ")
                and event.timestamp is not None
            ):
                prior_line, prior_event, prior_port = previous
                prior_time = prior_event.timestamp
                current_time = event.timestamp

                if (
                    prior_event.ip == event.ip
                    and prior_event.username == event.username
                    and (prior_port is None or port is None or prior_port == port)
                    and (prior_time.utcoffset() is None)
                    == (current_time.utcoffset() is None)
                    and timedelta(0) <= current_time - prior_time
                    <= timedelta(seconds=_INVALID_USER_MATCH_SECONDS)
                ):
                    replaced = prior_line

        if event.kind == "failed" and (window_mode or is_failed_login(line)):
            yield line_number, event, replaced

def extract_ips_from_log(
        log_path: str,
        threshold: int = 5,
        *,
        window_seconds: Optional[int] = None,
) -> list:
    """
    Extracts IPs whose failed-login occurrences reach the threshold.

    Without a window, counts source IPs from supported failed-password
    and invalid-user events. With a window, counts structured failed
    events with timestamps, grouped by source IP.

    Args:
        log_path (str): Path to the UTF-8 log file.
        threshold (int): Minimum number of failed-login occurrences.
        window_seconds (Optional[int]): Maximum duration of a burst.
            None disables time-window detection.

    Returns:
        list: IPs that reach the threshold.

    Raises:
        ValueError: If detection parameters are invalid or timestamps
            for an IP mix timezone-aware and naive datetimes.
        OSError: If the log file cannot be opened or read.
        UnicodeDecodeError: If the log is not valid UTF-8.
    """
    if threshold <= 0:
        raise ValueError("threshold must be positive")

    if window_seconds is not None and window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    with open(log_path, "r", encoding="utf-8") as file:
        entries = _iter_failed_entries(
            file, window_mode=window_seconds is not None,
        )

        if window_seconds is not None:
            timestamps_by_ip = defaultdict(dict)

            for line_number, event, replaced in entries:
                if event.timestamp is None:
                    continue

                timestamps = timestamps_by_ip[event.ip]
                if replaced is not None:
                    del timestamps[replaced]
                timestamps[line_number] = event.timestamp

            return [
                ip
                for ip, timestamps in timestamps_by_ip.items()
                if has_burst(list(timestamps.values()), threshold, window_seconds)
            ]

        ip_counts = Counter()
        for _, event, replaced in entries:
            if replaced is None:
                ip_counts[event.ip] += 1

        return [
            ip for ip, count in ip_counts.items()
            if count >= threshold
        ]