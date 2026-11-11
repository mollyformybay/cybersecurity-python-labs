import pytest


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Заборонити випадкові мережеві запити та успадкований ключ."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")
