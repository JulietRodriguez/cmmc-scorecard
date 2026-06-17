"""Tests for the source loaders and auto-detection."""

from __future__ import annotations

import json

import pytest

from cmmc_scorecard.loaders import (
    LoaderError,
    detect_source,
    load_findings,
    load_findings_file,
)
from cmmc_scorecard.models import Severity, Status


def test_load_manual_sample(samples_dir):
    findings = load_findings_file(samples_dir / "manual_sample.json")
    assert findings
    assert all(f.source == "manual" for f in findings)
    assert all(f.control_ids for f in findings)
    # The critical patch finding should be present and high-severity.
    crit = [f for f in findings if f.severity is Severity.CRITICAL]
    assert crit


def test_load_prowler_sample(samples_dir):
    findings = load_findings_file(samples_dir / "prowler_sample.json")
    assert findings
    assert all(f.source == "prowler" for f in findings)
    # Compliance map should resolve to canonical practice ids.
    mfa = next(f for f in findings if "3.5.3" in "".join(f.control_ids))
    assert "IA.L2-3.5.3" in mfa.control_ids
    assert mfa.status is Status.PASS


def test_load_securityhub_sample(samples_dir):
    findings = load_findings_file(samples_dir / "securityhub_sample.json")
    assert findings
    assert all(f.source == "securityhub" for f in findings)
    failed = [f for f in findings if f.status is Status.FAIL]
    assert failed
    # WARNING maps to PARTIAL.
    assert any(f.status is Status.PARTIAL for f in findings)


@pytest.mark.parametrize(
    "filename,expected",
    [
        ("manual_sample.json", "manual"),
        ("prowler_sample.json", "prowler"),
        ("securityhub_sample.json", "securityhub"),
    ],
)
def test_detect_source(samples_dir, filename, expected):
    data = json.loads((samples_dir / filename).read_text(encoding="utf-8"))
    assert detect_source(data) == expected


def test_unmapped_findings_are_dropped():
    data = {"findings": [{"id": "x", "title": "no controls", "status": "fail"}]}
    assert load_findings(data) == []


def test_forced_source_overrides_detection(samples_dir):
    data = json.loads((samples_dir / "manual_sample.json").read_text(encoding="utf-8"))
    findings = load_findings(data, source="manual")
    assert findings


def test_missing_file_raises():
    with pytest.raises(LoaderError):
        load_findings_file("does-not-exist-xyz.json")


def test_invalid_json_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(LoaderError):
        load_findings_file(bad)


def test_status_and_severity_normalization():
    data = {
        "findings": [
            {"id": "1", "title": "t", "status": "PASSED", "severity": "moderate", "control_ids": ["3.1.1"]},
            {"id": "2", "title": "t", "status": "alarm", "severity": "severe", "control_ids": ["3.1.2"]},
        ]
    }
    findings = load_findings(data)
    by_id = {f.id: f for f in findings}
    assert by_id["1"].status is Status.PASS
    assert by_id["1"].severity is Severity.MEDIUM
    assert by_id["2"].status is Status.FAIL
    assert by_id["2"].severity is Severity.HIGH
