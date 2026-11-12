from unittest.mock import patch

import pytest

from logsentry.main import main


@pytest.mark.parametrize(
    "extra_args, threshold, window_seconds",
    [
        ([], 5, None),
        (["-t", "3", "--window", "60"], 3, 60),
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
            "argument --window: invalid int value",
        ),
        (
            ["--window", "1.5"],
            "argument --window: invalid int value",
        ),
        (
            ["--window", "60", "--threshold", "0"],
            "[!] Error: --threshold must be positive when --window is used",
        ),
        (
            ["--window", "60", "--threshold", "-1"],
            "[!] Error: --threshold must be positive when --window is used",
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