from logsentry.parser import extract_ips_from_log


def test_extract_ips_above_threshold(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "Failed password from 1.2.3.4\n"
        "Failed password from 1.2.3.4\n"
        "Failed password from 1.2.3.4\n"
    )
    result = extract_ips_from_log(str(log_file), threshold=2)
    assert result == ["1.2.3.4"]


def test_extract_ips_below_threshold_excluded(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text("Failed password from 5.6.7.8\n")
    result = extract_ips_from_log(str(log_file), threshold=2)
    assert result == []


def test_extract_ips_invalid_octets_ignored(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "Bad IP 999.999.999.999\n"
        "Bad IP 999.999.999.999\n"
    )
    result = extract_ips_from_log(str(log_file), threshold=1)
    assert result == []


def test_extract_ips_file_not_found():
    result = extract_ips_from_log("nonexistent.log", threshold=1)
    assert result == []