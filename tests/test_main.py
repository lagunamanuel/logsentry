from unittest.mock import patch

import pytest
import requests
from logsentry.main import evaluate_vt_data, main
from unittest.mock import Mock, patch


@pytest.mark.parametrize(
    "extra_args, threshold, window_seconds",
    [
        ([], 5, None),
        (["-t", "3", "--window", "60"], 3, 60),
        (["-t", "3", "-w", "60"], 3, 60),
    ],
)
def test_main_passes_detection_parameters(
        monkeypatch, capsys, extra_args, threshold, window_seconds,
):
    """Forward detection parameters without querying VT in local mode."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        ["logsentry", "-l", "auth.log", "--no-vt"] + extra_args,
    )

    with (
        patch(
            "logsentry.main.extract_ips_from_log",
            return_value=["1.2.3.4"],
        ) as extract,
        patch("logsentry.main.check_ip_virustotal") as check_vt,
    ):
        main()

    extract.assert_called_once_with(
        "auth.log", threshold, window_seconds=window_seconds,
    )
    check_vt.assert_not_called()
    assert "IP 1.2.3.4 found (Skipping VirusTotal)" in capsys.readouterr().out


@pytest.mark.parametrize(
    "extra_args, expected_error",
    [
        (
                ["--window", "0"],
                "[!] Error: --window must be a positive number of seconds",
        ),
        (
                ["--window", "-1"],
                "[!] Error: --window must be a positive number of seconds",
        ),
        (
                ["--window", "abc"],
                "invalid int value: 'abc'",
        ),
        (
                ["--window", "1.5"],
                "invalid int value: '1.5'",
        ),
        (
                ["--window", "60", "--threshold", "0"],
                "[!] Error: --threshold must be positive",
        ),
        (
                ["--window", "60", "--threshold", "-1"],
                "[!] Error: --threshold must be positive",
        ),
        (
                ["-w", "0"],
                "[!] Error: --window must be a positive number of seconds",
        ),
    ],
)
def test_main_rejects_invalid_window_arguments(
        monkeypatch, capsys, extra_args, expected_error,
):
    """Reject invalid arguments before reading the log."""
    monkeypatch.setattr(
        "sys.argv",
        ["logsentry", "-l", "auth.log", "--no-vt"] + extra_args,
    )

    with patch("logsentry.main.extract_ips_from_log") as extract:
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 2
    extract.assert_not_called()
    assert expected_error in capsys.readouterr().err


def test_main_reports_incompatible_timestamps(monkeypatch, capsys):
    """Report timezone ambiguity using the project's error-message style."""
    monkeypatch.setattr(
        "sys.argv",
        ["logsentry", "-l", "auth.log", "--no-vt", "--window", "60"],
    )
    message = "Cannot mix timezone-aware and naive timestamps"

    with patch(
            "logsentry.main.extract_ips_from_log",
            side_effect=ValueError(message),
    ):
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 2
    assert f"[!] Error: {message}" in capsys.readouterr().err


@pytest.mark.parametrize(
    "extra_args, expected_ips",
    [
        ([], ["1.2.3.4", "5.6.7.8"]),
        (["--window", "60"], ["1.2.3.4"]),
        (["-w", "60"], ["1.2.3.4"]),
    ],
)
def test_main_local_scan_and_csv(
        tmp_path, monkeypatch, capsys, extra_args, expected_ips,
):
    """Check real parsing and CSV export with and without a window."""
    log_file = tmp_path / "auth.log"
    output_file = tmp_path / "results.csv"
    log_file.write_text(
        "2026-07-20T08:00:00 srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "2026-07-20T08:00:00 srv sshd[2]: "
        "Failed password for root from 5.6.7.8 port 22 ssh2\n"
        "2026-07-20T08:00:30 srv sshd[1]: "
        "Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "2026-07-20T08:02:00 srv sshd[2]: "
        "Failed password for root from 5.6.7.8 port 22 ssh2\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        [
            "logsentry",
            "-l", str(log_file),
            "-t", "2",
            "--no-vt",
            "-o", str(output_file),
        ] + extra_args,
    )

    with patch("logsentry.main.check_ip_virustotal") as check_vt:
        main()

    check_vt.assert_not_called()
    assert output_file.read_text().splitlines() == [
        "ip,malicious_engines",
        *[f"{ip},N/A" for ip in expected_ips],
    ]
    assert (
            f"Found {len(expected_ips)} unique IPs."
            in capsys.readouterr().out
    )


@pytest.mark.parametrize(
    "vt_data",
    [
        {},
        {"data": {}},
        {"data": {"attributes": {"last_analysis_stats": {}}}},
    ],
)
def test_evaluate_vt_data_unavailable_is_not_clean(capsys, vt_data):
    """Missing VT data must not become zero detections."""
    result = evaluate_vt_data("8.8.8.8", vt_data)

    assert result == {"ip": "8.8.8.8", "malicious_engines": "N/A"}
    output = capsys.readouterr().out
    assert "[!] Error:" in output
    assert "VirusTotal: clean" not in output


@pytest.mark.parametrize("malicious", [-1, "0", None, True])
def test_evaluate_vt_data_rejects_invalid_counts(capsys, malicious):
    """Only non-negative integer engine counts should be accepted."""
    vt_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": malicious},
            },
        },
    }

    result = evaluate_vt_data("8.8.8.8", vt_data)

    assert result == {"ip": "8.8.8.8", "malicious_engines": "N/A"}
    assert "VirusTotal: clean" not in capsys.readouterr().out


@pytest.mark.parametrize("malicious", [0, 3])
def test_evaluate_vt_data_preserves_valid_counts(capsys, malicious):
    """Valid zero and positive detection counts should retain their meaning."""
    vt_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": malicious},
            },
        },
    }

    result = evaluate_vt_data("8.8.8.8", vt_data)

    assert result == {"ip": "8.8.8.8", "malicious_engines": malicious}
    output = capsys.readouterr().out
    if malicious == 0:
        assert "VirusTotal: clean" in output
    else:
        assert "3 engines flagged as malicious" in output


def test_main_exports_failed_vt_lookup_as_unavailable(tmp_path, monkeypatch):
    """A failed VT lookup must be exported as N/A rather than zero."""
    log_file = tmp_path / "auth.log"
    output_file = tmp_path / "results.csv"
    log_file.write_text(
        "sshd[1]: Failed password for root from 8.8.8.8 port 22 ssh2\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("VT_API_KEY", "fake_key")
    monkeypatch.setattr(
        "sys.argv",
        [
            "logsentry",
            "-l", str(log_file),
            "-t", "1",
            "-o", str(output_file),
        ],
    )

    with patch(
            "logsentry.main.check_ip_virustotal",
            return_value={},
    ) as check_vt:
        main()

    check_vt.assert_called_once_with("8.8.8.8")
    assert output_file.read_text().splitlines() == [
        "ip,malicious_engines",
        "8.8.8.8,N/A",
    ]


def test_main_continues_after_vt_timeout(tmp_path, monkeypatch):
    """A failed lookup must not prevent later lookups or CSV export."""
    log_file = tmp_path / "auth.log"
    output_file = tmp_path / "results.csv"
    log_file.write_text(
        "sshd[1]: Failed password for root from 8.8.8.8 port 22 ssh2\n"
        "sshd[2]: Failed password for root from 1.1.1.1 port 22 ssh2\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("VT_API_KEY", "fake_key")
    monkeypatch.setattr(
        "sys.argv",
        [
            "logsentry",
            "-l", str(log_file),
            "-t", "1",
            "-o", str(output_file),
        ],
    )

    successful_response = Mock(status_code=200)
    successful_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0},
            },
        },
    }

    with (
        patch(
            "logsentry.api.requests.get",
            side_effect=[
                requests.exceptions.Timeout("simulated timeout"),
                successful_response,
            ],
        ) as mock_get,
        patch("logsentry.main.time.sleep"),
    ):
        main()

    assert mock_get.call_count == 2
    assert output_file.read_text().splitlines() == [
        "ip,malicious_engines",
        "8.8.8.8,N/A",
        "1.1.1.1,0",
    ]


def test_main_skips_multicast_but_keeps_csv_rows(tmp_path, monkeypatch):
    """Keep multicast results locally while querying VT only for public unicast."""
    log_file = tmp_path / "auth.log"
    output_file = tmp_path / "results.csv"
    log_file.write_text(
        "sshd[1]: Failed password for root from 224.0.0.1 port 22 ssh2\n"
        "sshd[2]: Failed password for root from 239.255.255.250 port 22 ssh2\n"
        "sshd[3]: Failed password for root from 8.8.8.8 port 22 ssh2\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("VT_API_KEY", "fake_key")
    monkeypatch.setattr(
        "sys.argv",
        [
            "logsentry",
            "-l", str(log_file),
            "-t", "1",
            "-o", str(output_file),
        ],
    )

    vt_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0},
            },
        },
    }

    with (
        patch(
            "logsentry.main.check_ip_virustotal",
            return_value=vt_data,
        ) as check_vt,
        patch("logsentry.main.time.sleep") as sleep,
    ):
        main()

    check_vt.assert_called_once_with("8.8.8.8")
    sleep.assert_not_called()
    assert output_file.read_text().splitlines() == [
        "ip,malicious_engines",
        "224.0.0.1,N/A",
        "239.255.255.250,N/A",
        "8.8.8.8,0",
    ]


@pytest.mark.parametrize("window_seconds", [None, 60])
@pytest.mark.parametrize(
    "output_kind",
    ["same_path", "relative_path", "symlink", "hardlink"],
)
def test_main_rejects_output_pointing_to_input(
        tmp_path, monkeypatch, capsys, window_seconds, output_kind,
):
    """Reject equivalent output paths without changing the input log."""
    log_file = tmp_path / "auth.log"
    content = (
        "Jul 20 08:00:00 srv sshd[1]: "
        "Failed password for root from 8.8.8.8 port 22 ssh2\n"
    )
    log_file.write_text(content, encoding="utf-8")

    if output_kind == "same_path":
        output = str(log_file)
    elif output_kind == "relative_path":
        monkeypatch.chdir(tmp_path)
        output = "./auth.log"
    elif output_kind == "symlink":
        output_file = tmp_path / "results.csv"
        output_file.symlink_to(log_file)
        output = str(output_file)
    else:
        import os

        output_file = tmp_path / "results.csv"
        os.link(log_file, output_file)
        output = str(output_file)

    argv = [
        "logsentry",
        "-l", str(log_file),
        "-t", "1",
        "--no-vt",
        "-o", output,
    ]
    if window_seconds is not None:
        argv.extend(["--window", str(window_seconds)])
    monkeypatch.setattr("sys.argv", argv)

    with (
        patch("logsentry.main.extract_ips_from_log") as extract,
        patch("logsentry.main.check_ip_virustotal") as check_vt,
        patch("logsentry.reporter.export_to_csv") as export,
    ):
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 2
    assert (
            "[!] Error: --output must not refer to the input log file"
            in capsys.readouterr().err
    )
    extract.assert_not_called()
    check_vt.assert_not_called()
    export.assert_not_called()
    assert log_file.read_text(encoding="utf-8") == content


@pytest.mark.parametrize("flag", ["-t", "--threshold"])
@pytest.mark.parametrize("threshold", ["0", "-1"])
def test_main_rejects_invalid_threshold_without_window(
        monkeypatch, capsys, flag, threshold,
):
    """Reject non-positive thresholds before reading or querying VT."""
    monkeypatch.setattr(
        "sys.argv",
        ["logsentry", "-l", "auth.log", "--no-vt", flag, threshold],
    )

    with (
        patch("logsentry.main.extract_ips_from_log") as extract,
        patch("logsentry.main.check_ip_virustotal") as check_vt,
    ):
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 2
    extract.assert_not_called()
    check_vt.assert_not_called()
    assert (
            "[!] Error: --threshold must be positive"
            in capsys.readouterr().err
    )


def test_main_rejects_missing_vt_api_key(monkeypatch, capsys):
    """Missing credentials must fail before reading or querying VT."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        ["logsentry", "-l", "auth.log"],
    )

    with (
        patch("logsentry.main.extract_ips_from_log") as extract,
        patch("logsentry.main.check_ip_virustotal") as check_vt,
    ):
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 2
    extract.assert_not_called()
    check_vt.assert_not_called()

    captured = capsys.readouterr()
    assert (
            "[!] Error: VT_API_KEY environment variable is not set."
            in captured.err
    )
    assert "--no-vt" in captured.err
