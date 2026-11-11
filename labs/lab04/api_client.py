"""Мережевий клієнт для NVD CVE API 2.0."""

import os
from typing import Any

import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def build_headers() -> dict[str, str]:
    """Побудувати безпечні заголовки запиту, прочитавши ключ під час виклику."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконати один запит NVD і повернути JSON-тіло відповіді."""
    try:
        response = requests.get(
            API_URL,
            params={"cveId": cve_id},
            headers=build_headers(),
            timeout=(3.05, 10),
            allow_redirects=False,
        )
        response.raise_for_status()
    except requests.exceptions.Timeout as error:
        raise RuntimeError("NVD API: перевищено час очікування.") from error
    except requests.exceptions.ConnectionError as error:
        raise RuntimeError("NVD API: помилка з'єднання.") from error
    except requests.exceptions.HTTPError as error:
        status = (
            error.response.status_code if error.response is not None else "невідомий"
        )
        raise RuntimeError(f"NVD API: HTTP-помилка {status}.") from error
    except requests.exceptions.RequestException as error:
        raise RuntimeError("NVD API: помилка мережевого запиту.") from error

    if response.status_code != 200:
        raise RuntimeError(f"NVD API: неочікуваний HTTP-статус {response.status_code}.")

    try:
        return response.json()
    except (ValueError, requests.exceptions.JSONDecodeError) as error:
        raise RuntimeError("NVD API: відповідь не є коректним JSON.") from error
