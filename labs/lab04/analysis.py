"""Перевірка відповіді NVD та застосування правила варіанта."""

import math
from typing import Any

RULES: dict[int, dict[str, Any]] = {
    1: {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
    2: {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    3: {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
    4: {"threshold": 8.0, "field": "userInteraction", "expected": "NONE"},
    5: {"threshold": 7.0, "field": "confidentialityImpact", "expected": "HIGH"},
    6: {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
    7: {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"},
    8: {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    9: {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
    10: {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    11: {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    12: {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
    13: {"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"},
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
    15: {"threshold": 8.0, "field": "attackComplexity", "expected": "HIGH"},
}

_ALLOWED = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": {"NONE", "LOW", "HIGH"},
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": {"NONE", "LOW", "HIGH"},
    "integrityImpact": {"NONE", "LOW", "HIGH"},
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}


def _nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"Поле {name} має бути непорожнім рядком.")
    return value


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Повернути перевірений внутрішній запис або None, якщо CVE не знайдено.

    Внутрішній запис містить статус, англійський опис і вибрану Primary CVSS v3.1
    оцінку; мережеві та файлові операції тут не виконуються.
    """
    if not isinstance(payload, dict) or not isinstance(
        payload.get("vulnerabilities"), list
    ):
        raise ValueError("Поле vulnerabilities має бути списком.")  # noqa: TRY004
    vulnerabilities = payload["vulnerabilities"]
    if len(vulnerabilities) > 1:
        raise ValueError("Очікувався нуль або один запис CVE.")
    if not vulnerabilities:
        return None
    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise ValueError("Запис CVE має містити об'єкт cve.")  # noqa: TRY004
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("Ідентифікатор CVE у відповіді не збігається із запитом.")

    status = cve.get("vulnStatus")
    if status is not None:
        status = _nonempty_string(status, "vulnStatus")

    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        raise ValueError("Поле descriptions має бути списком.")  # noqa: TRY004
    english_description = None
    for description in descriptions:
        if not isinstance(description, dict):
            raise ValueError("Елемент descriptions має бути об'єктом.")  # noqa: TRY004
        lang = _nonempty_string(description.get("lang"), "lang")
        value = _nonempty_string(description.get("value"), "value")
        if english_description is None and lang.lower() == "en":
            english_description = value

    record: dict[str, Any] = {
        "description": english_description,
        "vuln_status": status,
        "assessment": None,
    }
    if status is None or status == "Rejected":
        return record

    metrics = cve.get("metrics")
    if metrics is None:
        return record
    if not isinstance(metrics, dict):
        raise ValueError("Поле metrics має бути об'єктом.")  # noqa: TRY004
    metric_list = metrics.get("cvssMetricV31")
    if metric_list is None:
        return record
    if not isinstance(metric_list, list):
        raise ValueError("Поле cvssMetricV31 має бути списком.")  # noqa: TRY004
    if not metric_list:
        return record
    if any(not isinstance(metric, dict) for metric in metric_list):
        raise ValueError("Елементи cvssMetricV31 мають бути об'єктами.")
    assessment = next(
        (m for m in metric_list if m.get("type") == "Primary"), metric_list[0]
    )
    cvss_data = assessment.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise ValueError("Поле cvssData має бути об'єктом.")  # noqa: TRY004
    score = cvss_data.get("baseScore")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 10
    ):
        raise ValueError("baseScore має бути скінченним числом від 0 до 10.")
    for field in ("version", "vectorString"):
        if field in cvss_data:
            _nonempty_string(cvss_data[field], field)
    if "version" in cvss_data and cvss_data["version"] != "3.1":
        raise ValueError("Підтримується лише CVSS версії 3.1.")
    source = assessment.get("source")
    if source is not None:
        source = _nonempty_string(source, "source")
    record["assessment"] = {
        "score": score,
        "source": source,
        "version": cvss_data.get("version"),
        "vector": cvss_data.get("vectorString"),
        "cvss_data": cvss_data,
    }
    return record


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Сформувати стабільний JSON-звіт для обраного варіанта."""
    if isinstance(variant, bool) or variant not in RULES:
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15.")
    rule = dict(RULES[variant])
    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": rule,
        "observed": None,
        "decision": "not_found" if record is None else None,
    }
    if record is None:
        return report
    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]
    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report
    if record["vuln_status"] is None or record["assessment"] is None:
        report["decision"] = "insufficient_data"
        return report
    assessment = record["assessment"]
    data = assessment["cvss_data"]
    report.update(
        cvss_version=assessment["version"],
        score=assessment["score"],
        score_source=assessment["source"],
        vector=assessment["vector"],
    )
    field = rule["field"]
    if field not in data:
        report["decision"] = "insufficient_data"
        return report
    observed = data[field]
    if observed is None or observed not in _ALLOWED[field]:
        raise ValueError(f"Недопустиме значення поля {field}.")
    report["observed"] = observed
    report["decision"] = (
        "review"
        if assessment["score"] >= rule["threshold"] and observed == rule["expected"]
        else "other"
    )
    return report
