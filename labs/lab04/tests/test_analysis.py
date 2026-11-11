import copy
import json
from pathlib import Path

import pytest

from labs.lab04.analysis import build_report, extract_record


@pytest.fixture
def payload():
    path = Path(__file__).parents[1] / "data" / "nvd_sample.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_sample_is_review_for_variant_15(payload):
    record = extract_record(payload, "CVE-2099-10001")
    report = build_report(record, "CVE-2099-10001", 15)
    assert report["decision"] == "other"
    assert report["observed"] == "LOW"


@pytest.mark.parametrize(
    ("score", "expected"),
    [(7.9, "other"), (8.0, "review"), (8.1, "review")],
)
def test_threshold_boundary(payload, score, expected):
    modified = copy.deepcopy(payload)
    modified["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "attackComplexity"
    ] = "HIGH"
    modified["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "baseScore"
    ] = score
    record = extract_record(modified, "CVE-2099-10001")
    assert build_report(record, "CVE-2099-10001", 15)["decision"] == expected


def test_wrong_rule_value_is_other(payload):
    modified = copy.deepcopy(payload)
    modified["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "attackComplexity"
    ] = "LOW"
    record = extract_record(modified, "CVE-2099-10001")
    assert build_report(record, "CVE-2099-10001", 15)["decision"] == "other"


def test_primary_assessment_has_priority(payload):
    metrics = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"]
    secondary = copy.deepcopy(metrics[0])
    secondary["type"] = "Secondary"
    secondary["cvssData"]["baseScore"] = 1.0
    secondary["cvssData"]["attackComplexity"] = "HIGH"
    metrics[0]["cvssData"]["attackComplexity"] = "HIGH"
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        secondary,
        metrics[0],
    ]
    record = extract_record(payload, "CVE-2099-10001")
    assert build_report(record, "CVE-2099-10001", 15)["score"] == 9.8


@pytest.mark.parametrize(
    "status, decision", [("Rejected", "rejected"), (None, "insufficient_data")]
)
def test_status_without_analysis(payload, status, decision):
    cve = payload["vulnerabilities"][0]["cve"]
    if status is None:
        cve.pop("vulnStatus")
    else:
        cve["vulnStatus"] = status
    record = extract_record(payload, "CVE-2099-10001")
    assert build_report(record, "CVE-2099-10001", 15)["decision"] == decision


def test_not_found_has_null_data(payload):
    report = build_report(
        extract_record({"vulnerabilities": []}, "CVE-2099-10001"), "CVE-2099-10001", 15
    )
    assert report["decision"] == "not_found"
    assert report["score"] is None


@pytest.mark.parametrize("bad_score", [True, "9.8", float("nan"), 11])
def test_invalid_score_is_rejected(payload, bad_score):
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "baseScore"
    ] = bad_score
    with pytest.raises(ValueError):
        extract_record(payload, "CVE-2099-10001")
