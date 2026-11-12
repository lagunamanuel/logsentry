from datetime import datetime, timedelta, timezone
import pytest
from logsentry.parser import (
    LogEvent,
    extract_ips_from_log,
    has_burst,
    is_failed_login,
    is_public_ip,
    parse_event,
    parse_timestamp,
    parse_events,

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

def test_parse_events_reads_authentication_events_in_file_order(tmp_path):
    """Failed and accepted events should retain their order and parsed fields."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Jul 20 08:12:02 srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "\n"
        "Jul 20 08:12:03 srv kernel: eth0 link up\n"
        "Jul 20 08:12:01 srv sshd[1]: "
        "Accepted publickey for manuel from 192.168.1.10 port 22 ssh2\n",
        encoding="utf-8",
    )

    result = parse_events(str(log_file), year=2026)

    assert result == [
        LogEvent(
            ip="1.2.3.4",
            kind="failed",
            username="root",
            timestamp=datetime(2026, 7, 20, 8, 12, 2),
        ),
        LogEvent(
            ip="192.168.1.10",
            kind="accepted",
            username="manuel",
            timestamp=datetime(2026, 7, 20, 8, 12, 1),
        ),
    ]


def test_parse_events_preserves_events_without_timestamp(tmp_path):
    """Missing timestamps should not cause authentication events to be discarded."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "sshd[1]: Invalid user admin from 1.2.3.4 port 22\n",
        encoding="utf-8",
    )

    result = parse_events(str(log_file), year=2026)

    assert result == [
        LogEvent(
            ip="1.2.3.4",
            kind="failed",
            username="admin",
            timestamp=None,
        ),
    ]


def test_parse_events_empty_file_returns_empty_list(tmp_path):
    """An empty log should produce no authentication events."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")

    assert parse_events(str(log_file), year=2026) == []


def test_parse_events_missing_file_raises(tmp_path):
    """A missing log should raise rather than look like an empty log."""
    log_file = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError):
        parse_events(str(log_file), year=2026)

@pytest.mark.parametrize(
    "offsets, threshold, window_seconds, expected",
    [
        pytest.param([], 3, 60, False, id="empty"),
        pytest.param([0, 10], 3, 60, False, id="below-threshold"),
        pytest.param([0, 20, 40], 3, 60, True, id="within-window"),
        pytest.param([0, 40, 80], 3, 60, False, id="outside-window"),
        pytest.param([0, 30, 60], 3, 60, True, id="exact-boundary"),
        pytest.param(
            [0, 30, 60.000001], 3, 60, False, id="just-outside-boundary",
        ),
        pytest.param(
            [0, 100, 110, 120], 3, 30, True, id="burst-later-in-log",
        ),
        pytest.param([40, 0, 20], 3, 60, True, id="unordered"),
        pytest.param([0, 0, 0], 3, 1, True, id="same-timestamp"),
        pytest.param([0], 1, 60, True, id="threshold-one"),
    ],
)
def test_has_burst_detects_time_windows(
    offsets, threshold, window_seconds, expected,
):
    """Detect bursts across boundary cases without modifying the input."""
    base = datetime(2026, 7, 20, 8, 0, 0)
    timestamps = [base + timedelta(seconds=offset) for offset in offsets]
    original = timestamps.copy()

    assert has_burst(timestamps, threshold, window_seconds) is expected
    assert timestamps == original


@pytest.mark.parametrize(
    "threshold, window_seconds",
    [
        (0, 60),
        (-1, 60),
        (3, 0),
        (3, -1),
    ],
)
def test_has_burst_rejects_non_positive_parameters(threshold, window_seconds):
    """Threshold and window duration must both be positive."""
    with pytest.raises(ValueError):
        has_burst([], threshold, window_seconds)


def test_has_burst_compares_different_timezone_offsets():
    """Aware timestamps should be compared by their actual instant."""
    timestamps = [
        datetime(2026, 7, 20, 8, 0, 0, tzinfo=timezone.utc),
        datetime(
            2026, 7, 20, 10, 0, 30,
            tzinfo=timezone(timedelta(hours=2)),
        ),
    ]

    assert has_burst(timestamps, threshold=2, window_seconds=60)


def test_has_burst_rejects_mixed_timezone_awareness():
    """Naive and aware timestamps cannot be compared without a timezone policy."""
    timestamps = [
        datetime(2026, 7, 20, 8, 0, 0),
        datetime(2026, 7, 20, 8, 0, 30, tzinfo=timezone.utc),
    ]

    with pytest.raises(ValueError, match="timezone-aware and naive"):
        has_burst(timestamps, threshold=2, window_seconds=60)

def test_extract_ips_window_groups_failures_by_ip(tmp_path):
    """Only IPs independently reaching the threshold should be returned."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "2026-07-20T08:00:00 srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "2026-07-20T08:00:10 srv sshd[2]: "
        "Failed password for root from 5.6.7.8 port 22 ssh2\n"
        "2026-07-20T08:01:00 srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "2026-07-20T08:00:30 srv sshd[1]: "
        "Failed password for admin from 1.2.3.4 port 22 ssh2\n"
        "2026-07-20T08:00:40 srv sshd[2]: "
        "Failed password for root from 5.6.7.8 port 22 ssh2\n",
        encoding="utf-8",
    )

    result = extract_ips_from_log(
        str(log_file), threshold=3, window_seconds=60,
    )

    assert result == ["1.2.3.4"]


def test_extract_ips_window_ignores_accepted_and_undated_events(tmp_path):
    """Successful logins and failures without timestamps must not form a burst."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "2026-07-20T08:00:00 srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "2026-07-20T08:00:10 srv sshd[1]: "
        "Accepted password for root from 1.2.3.4 port 22 ssh2\n"
        "sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )

    assert extract_ips_from_log(
        str(log_file), threshold=2, window_seconds=60,
    ) == []
    assert extract_ips_from_log(str(log_file), threshold=2) == ["1.2.3.4"]


def test_extract_ips_window_excludes_spread_out_failures(tmp_path):
    """Reaching the total threshold is insufficient when failures are too far apart."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "2026-07-20T08:00:00 srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "2026-07-20T08:02:00 srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "2026-07-20T08:04:00 srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )

    assert extract_ips_from_log(
        str(log_file), threshold=3, window_seconds=60,
    ) == []
    assert extract_ips_from_log(str(log_file), threshold=3) == ["1.2.3.4"]


@pytest.mark.parametrize(
    "threshold, window_seconds",
    [
        (0, 60),
        (-1, 60),
        (3, 0),
        (3, -1),
    ],
)
def test_extract_ips_window_rejects_invalid_parameters(
    tmp_path, threshold, window_seconds,
):
    """Window parameters must be validated even when the log is empty."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("", encoding="utf-8")

    with pytest.raises(ValueError):
        extract_ips_from_log(
            str(log_file),
            threshold=threshold,
            window_seconds=window_seconds,
        )


def test_extract_ips_window_rejects_mixed_timezone_awareness(tmp_path):
    """Timezone ambiguity for the same IP must not be silently resolved."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "2026-07-20T08:00:00 srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "2026-07-20T08:00:30Z srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="timezone-aware and naive"):
        extract_ips_from_log(
            str(log_file), threshold=2, window_seconds=60,
        )


def test_extract_ips_window_missing_file_returns_empty_list(tmp_path):
    """Window mode should preserve the existing missing-file behavior."""
    log_file = tmp_path / "missing.log"

    assert extract_ips_from_log(
        str(log_file), threshold=3, window_seconds=60,
    ) == []