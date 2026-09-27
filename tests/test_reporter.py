from logsentry.reporter import export_to_csv


def test_export_to_csv_creates_file_with_correct_content(tmp_path):
    """Should write a CSV file with the correct header and data rows."""
    output_file = tmp_path / "results.csv"
    data = [
        {"ip": "1.2.3.4", "malicious_engines": 3},
        {"ip": "5.6.7.8", "malicious_engines": 0},
    ]

    export_to_csv(data, str(output_file))

    content = output_file.read_text()
    assert "ip,malicious_engines" in content
    assert "1.2.3.4,3" in content
    assert "5.6.7.8,0" in content


def test_export_to_csv_empty_data(tmp_path):
    """Should write only the header when data is an empty list."""
    output_file = tmp_path / "empty.csv"
    export_to_csv([], str(output_file))

    content = output_file.read_text()
    assert content.strip() == "ip,malicious_engines"