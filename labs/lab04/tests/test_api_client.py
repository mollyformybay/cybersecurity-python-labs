from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client


def test_build_headers_without_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "   ")
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_with_trimmed_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-key  ")
    assert api_client.build_headers()["apiKey"] == "fake-key"


def test_fetch_uses_expected_request(monkeypatch):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = {"vulnerabilities": []}
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    assert api_client.fetch_response("CVE-2099-10001") == {"vulnerabilities": []}
    fake_get.assert_called_once_with(
        api_client.API_URL,
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_http_error_is_safe(monkeypatch):
    response = Mock(spec=requests.Response)
    response.status_code = 500
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(RuntimeError, match="HTTP-помилка 500"):
        api_client.fetch_response("CVE-2099-10001")
