from unittest.mock import patch, Mock
import pytest
from logsentry.api import check_ip_virustotal


def test_check_ip_missing_api_key(monkeypatch):
    """Should raise EnvironmentError when VT_API_KEY is not set."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(EnvironmentError):
        check_ip_virustotal("1.2.3.4")


@patch("logsentry.api.requests.get")
def test_check_ip_success(mock_get, monkeypatch):
    """Should return the parsed JSON payload on a successful API response."""
    monkeypatch.setenv("VT_API_KEY", "fake_key")
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}}
    mock_get.return_value = mock_response

    result = check_ip_virustotal("1.2.3.4")
    assert result["data"]["attributes"]["last_analysis_stats"]["malicious"] == 3


@patch("logsentry.api.requests.get")
def test_check_ip_api_error(mock_get, monkeypatch):
    """Should return an empty dict when the API responds with a non-200 status."""
    monkeypatch.setenv("VT_API_KEY", "fake_key")
    mock_response = Mock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    result = check_ip_virustotal("1.2.3.4")
    assert result == {}