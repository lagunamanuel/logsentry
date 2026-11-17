from unittest.mock import patch, Mock
import pytest
from logsentry.api import check_ip_virustotal
import requests

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
    mock_get.assert_called_once()
    assert mock_get.call_args.kwargs["timeout"] == (5, 20)


@patch("logsentry.api.requests.get")
def test_check_ip_api_error(mock_get, monkeypatch):
    """Should return an empty dict when the API responds with a non-200 status."""
    monkeypatch.setenv("VT_API_KEY", "fake_key")
    mock_response = Mock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    result = check_ip_virustotal("1.2.3.4")
    assert result == {}

@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectTimeout("connection timed out"),
        requests.exceptions.ReadTimeout("read timed out"),
        requests.exceptions.ConnectionError("connection failed"),
    ],
)
@patch("logsentry.api.requests.get")
def test_check_ip_network_errors_return_empty_dict(
    mock_get, monkeypatch, capsys, error,
):
    """Network failures should be reported without escaping to the caller."""
    monkeypatch.setenv("VT_API_KEY", "fake_key")
    mock_get.side_effect = error

    assert check_ip_virustotal("8.8.8.8") == {}
    assert "[!] Error:" in capsys.readouterr().out


@patch("logsentry.api.requests.get")
def test_check_ip_invalid_json_returns_empty_dict(mock_get, monkeypatch, capsys):
    """A malformed JSON response should not abort the scan."""
    monkeypatch.setenv("VT_API_KEY", "fake_key")
    response = Mock(status_code=200)
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "not JSON", 0,
    )
    mock_get.return_value = response

    assert check_ip_virustotal("8.8.8.8") == {}
    assert "[!] Error:" in capsys.readouterr().out


@pytest.mark.parametrize("payload", [None, [], "unexpected"])
@patch("logsentry.api.requests.get")
def test_check_ip_rejects_non_object_json(
    mock_get, monkeypatch, capsys, payload,
):
    """Valid JSON that is not an object should be treated as unavailable."""
    monkeypatch.setenv("VT_API_KEY", "fake_key")
    response = Mock(status_code=200)
    response.json.return_value = payload
    mock_get.return_value = response

    assert check_ip_virustotal("8.8.8.8") == {}
    assert "[!] Error:" in capsys.readouterr().out