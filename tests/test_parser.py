from logsentry.parser import extract_ips_from_log, is_failed_login

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
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "sshd: Failed password for root from 1.2.3.4 port 22 ssh2\n" * 3
        + "sshd: Accepted password for manuel from 192.168.1.10 port 22 ssh2\n" * 8
    )
    result = extract_ips_from_log(str(log_file), threshold=3)
    assert result == ["1.2.3.4"]