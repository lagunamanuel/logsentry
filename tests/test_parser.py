from datetime import datetime, timedelta, timezone

from logsentry.parser import (
    LogEvent,
    extract_ips_from_log,
    is_failed_login,
    is_public_ip,
    parse_event,
    parse_timestamp,
)

def test_extract_ips_above_threshold(tmp_path):
    """IPs occurring at or above the threshold should be flagged as suspicious."""
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "Failed password from 1.2.3.4\n"
        "Failed password from 1.2.3.4\n"
        "Failed password from 1.2.3.4\n"
    )
    result = extract_ips_from_log(str(log_file), threshold=2)
    assert result == ["1.2.3.4"]


def test_extract_ips_below_threshold_excluded(tmp_path):
    """IPs occurring fewer times than the threshold should be excluded."""
    log_file = tmp_path / "test.log"
    log_file.write_text("Failed password from 5.6.7.8\n")
    result = extract_ips_from_log(str(log_file), threshold=2)
    assert result == []


def test_extract_ips_invalid_octets_ignored(tmp_path):
    """Malformed IPs with octets above 255 should not be matched by the regex."""
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "Bad IP 999.999.999.999\n"
        "Bad IP 999.999.999.999\n"
    )
    result = extract_ips_from_log(str(log_file), threshold=1)
    assert result == []


def test_extract_ips_file_not_found():
    """A missing log file should return an empty list instead of raising."""
    result = extract_ips_from_log("nonexistent.log", threshold=1)
    assert result == []


def test_is_failed_login_failed_password():
    """A 'Failed password' line should be recognised as a failed login."""
    assert is_failed_login("sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2")


def test_is_failed_login_invalid_user():
    """An 'Invalid user' line should be recognised as a failed login."""
    assert is_failed_login("sshd[1]: Invalid user admin from 1.2.3.4 port 22")


def test_is_failed_login_accepted_login_is_not_failed():
    """A successful login must not be flagged, even though it contains an IP."""
    assert not is_failed_login("sshd[1]: Accepted password for manuel from 192.168.1.10 port 22 ssh2")


def test_is_failed_login_unrelated_line():
    """Lines containing an IP but unrelated to authentication should be ignored."""
    assert not is_failed_login("kernel: eth0 link up, peer 10.0.0.1")


def test_extract_ips_ignores_successful_logins(tmp_path):
    """IPs that only appear in successful logins must not be flagged, even above the threshold."""
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "sshd: Failed password for root from 1.2.3.4 port 22 ssh2\n" * 3
        + "sshd: Accepted password for manuel from 192.168.1.10 port 22 ssh2\n" * 8
    )
    result = extract_ips_from_log(str(log_file), threshold=3)
    assert result == ["1.2.3.4"]


def test_is_public_ip_public_address():
    """A globally routable address should be classified as public."""
    assert is_public_ip("8.8.8.8")


def test_is_public_ip_private_ranges():
    """RFC 1918 private ranges should not be classified as public."""
    assert not is_public_ip("192.168.1.10")
    assert not is_public_ip("10.0.0.5")
    assert not is_public_ip("172.16.0.1")


def test_is_public_ip_loopback():
    """The loopback address should not be classified as public."""
    assert not is_public_ip("127.0.0.1")


def test_is_public_ip_reserved_documentation_range():
    """Reserved documentation ranges (TEST-NET) should not be classified as public."""
    assert not is_public_ip("198.51.100.23")


def test_is_public_ip_invalid_string():
    """Strings rejected by ipaddress (e.g. leading zeros) should return False, not raise."""
    assert not is_public_ip("001.2.3.4")

def test_parse_timestamp_syslog_uses_given_year():
    """Syslog timestamps carry no year, so the provided year should be applied."""
    result = parse_timestamp("Jul 20 08:12:01 srv sshd[1]: Failed password", year=2026)
    assert result == datetime(2026, 7, 20, 8, 12, 1)


def test_parse_timestamp_syslog_single_digit_day():
    """Syslog pads single-digit days with an extra space, which should still parse."""
    result = parse_timestamp("Jul  5 08:12:01 srv sshd[1]: x", year=2026)
    assert result == datetime(2026, 7, 5, 8, 12, 1)


def test_parse_timestamp_syslog_defaults_to_current_year():
    """Without an explicit year, syslog timestamps should default to the current year."""
    result = parse_timestamp("Jul 20 08:12:01 srv sshd[1]: x")
    assert result.year == datetime.now().year


def test_parse_timestamp_iso_with_offset():
    """ISO 8601 timestamps with a UTC offset should keep their timezone."""
    result = parse_timestamp("2026-07-20T08:12:01+02:00 srv sshd[1]: x")
    assert result == datetime(2026, 7, 20, 8, 12, 1, tzinfo=timezone(timedelta(hours=2)))


def test_parse_timestamp_iso_zulu():
    """A trailing 'Z' should be interpreted as UTC."""
    result = parse_timestamp("2026-07-20T08:12:01Z srv sshd[1]: x")
    assert result == datetime(2026, 7, 20, 8, 12, 1, tzinfo=timezone.utc)


def test_parse_timestamp_iso_fractional_seconds():
    """Fractional seconds in ISO 8601 timestamps should be preserved."""
    result = parse_timestamp("2026-07-20T08:12:01.123456+02:00 srv sshd[1]: x")
    assert result == datetime(2026, 7, 20, 8, 12, 1, 123456, tzinfo=timezone(timedelta(hours=2)))


def test_parse_timestamp_no_timestamp_returns_none():
    """Lines without a leading timestamp should return None."""
    assert parse_timestamp("sshd[1]: Failed password for root") is None


def test_parse_timestamp_invalid_date_returns_none():
    """Impossible dates (e.g. Feb 30) should return None instead of raising."""
    assert parse_timestamp("Feb 30 08:12:01 srv sshd[1]: x", year=2026) is None

def test_parse_event_failed_password():
    """A failed password should produce an event with its IP, user and timestamp."""
    line = (
        "Jul 20 08:12:01 srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2"
    )

    result = parse_event(line, year=2026)

    assert result == LogEvent(
        ip="1.2.3.4",
        kind="failed",
        username="root",
        timestamp=datetime(2026, 7, 20, 8, 12, 1),
    )


def test_parse_event_failed_password_invalid_user():
    """The 'invalid user' prefix should not become part of the username."""
    line = (
        "Jul 20 08:12:02 srv sshd[1]: "
        "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
    )

    result = parse_event(line, year=2026)

    assert result == LogEvent(
        ip="1.2.3.4",
        kind="failed",
        username="admin",
        timestamp=datetime(2026, 7, 20, 8, 12, 2),
    )


def test_parse_event_invalid_user():
    """An 'Invalid user' line should be classified as a failed event."""
    line = (
        "Jul 20 08:12:03 srv sshd[1]: "
        "Invalid user test from 1.2.3.4 port 22"
    )

    result = parse_event(line, year=2026)

    assert result == LogEvent(
        ip="1.2.3.4",
        kind="failed",
        username="test",
        timestamp=datetime(2026, 7, 20, 8, 12, 3),
    )


def test_parse_event_accepted_password():
    """A successful password login should be classified as accepted."""
    line = (
        "Jul 20 08:12:04 srv sshd[1]: "
        "Accepted password for manuel from 192.168.1.10 port 22 ssh2"
    )

    result = parse_event(line, year=2026)

    assert result == LogEvent(
        ip="192.168.1.10",
        kind="accepted",
        username="manuel",
        timestamp=datetime(2026, 7, 20, 8, 12, 4),
    )


def test_parse_event_accepted_publickey():
    """Successful public-key authentication should also be recognised."""
    line = (
        "Jul 20 08:12:05 srv sshd[1]: "
        "Accepted publickey for manuel from 192.168.1.10 port 22 ssh2"
    )

    result = parse_event(line, year=2026)

    assert result == LogEvent(
        ip="192.168.1.10",
        kind="accepted",
        username="manuel",
        timestamp=datetime(2026, 7, 20, 8, 12, 5),
    )


def test_parse_event_unrelated_line_returns_none():
    """Lines unrelated to SSH authentication should not produce events."""
    line = "Jul 20 08:12:06 srv kernel: eth0 link up, peer 1.2.3.4"

    assert parse_event(line, year=2026) is None


def test_parse_event_without_timestamp():
    """An authentication event without a timestamp should still be preserved."""
    line = "sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"

    result = parse_event(line)

    assert result == LogEvent(
        ip="1.2.3.4",
        kind="failed",
        username="root",
        timestamp=None,
    )


def test_parse_event_invalid_ip_returns_none():
    """An authentication line with invalid IPv4 octets should be ignored."""
    line = (
        "Jul 20 08:12:07 srv sshd[1]: "
        "Failed password for root from 999.999.999.999 port 22 ssh2"
    )

    assert parse_event(line, year=2026) is None