"""Loaders that normalize findings from various sources into ``Finding`` objects.

Three input shapes are supported and auto-detected:

* **Prowler** native JSON (a list of check results with a ``Compliance`` map).
* **AWS Security Hub** ASFF findings (``{"Findings": [...]}`` with
  ``Compliance.RelatedRequirements``).
* **Manual** — the tool's own normalized schema (``{"findings": [...]}``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cmmc_scorecard.domains import normalize_control_id
from cmmc_scorecard.models import Finding, Severity, Status

# Map varied status strings onto the normalized PASS/FAIL set.
_STATUS_MAP: dict[str, Status] = {
    "pass": Status.PASS,
    "passed": Status.PASS,
    "ok": Status.PASS,
    "fail": Status.FAIL,
    "failed": Status.FAIL,
    "alarm": Status.FAIL,
    "warning": Status.PARTIAL,
    "partial": Status.PARTIAL,
    "manual": Status.NOT_ASSESSED,
    "info": Status.NOT_ASSESSED,
    "informational": Status.NOT_ASSESSED,
    "not_available": Status.NOT_ASSESSED,
}


class LoaderError(ValueError):
    """Raised when an input document cannot be parsed or recognized."""


def _norm_status(value: Any) -> Status:
    if isinstance(value, Status):
        return value
    return _STATUS_MAP.get(str(value).strip().lower(), Status.NOT_ASSESSED)


def _norm_severity(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value
    key = str(value).strip().lower()
    try:
        return Severity(key)
    except ValueError:
        return {
            "info": Severity.INFORMATIONAL,
            "moderate": Severity.MEDIUM,
            "severe": Severity.HIGH,
        }.get(key, Severity.MEDIUM)


def _collect_control_ids(*raw_refs: Any) -> list[str]:
    """Normalize and de-duplicate any number of raw control references."""
    out: list[str] = []
    seen: set[str] = set()
    for ref in raw_refs:
        candidates: list[str] = []
        if ref is None:
            continue
        if isinstance(ref, str):
            candidates = [ref]
        elif isinstance(ref, (list, tuple)):
            candidates = [str(item) for item in ref]
        elif isinstance(ref, dict):
            for value in ref.values():
                if isinstance(value, (list, tuple)):
                    candidates.extend(str(v) for v in value)
                else:
                    candidates.append(str(value))
        for candidate in candidates:
            normalized = normalize_control_id(candidate)
            if normalized and normalized not in seen:
                seen.add(normalized)
                out.append(normalized)
    return out


def _compliance_refs(compliance: dict[str, Any]) -> list[str]:
    """Pull control refs from a Prowler-style ``Compliance`` block, favoring
    NIST 800-171 / CMMC frameworks but falling back to anything mappable."""
    refs: list[str] = []
    for framework, values in compliance.items():
        fname = framework.upper()
        if any(tag in fname for tag in ("800-171", "800_171", "NIST", "CMMC")):
            refs.append(values)
    if not refs:  # fall back to every framework listed
        refs = list(compliance.values())
    return _collect_control_ids(*refs)


def _load_prowler(records: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for rec in records:
        compliance = rec.get("Compliance") or {}
        control_ids = _compliance_refs(compliance) if compliance else []
        # Some exports stash the mapping under a flat custom field.
        if not control_ids:
            control_ids = _collect_control_ids(
                rec.get("nist_800_171"), rec.get("ControlId")
            )
        if not control_ids:
            continue
        findings.append(
            Finding(
                id=str(rec.get("FindingUniqueId") or rec.get("CheckID") or "prowler"),
                title=str(rec.get("CheckTitle") or rec.get("CheckID") or "Prowler check"),
                status=_norm_status(rec.get("Status")),
                severity=_norm_severity(rec.get("Severity")),
                control_ids=control_ids,
                resource=str(rec.get("ResourceId") or rec.get("ResourceArn") or ""),
                description=str(rec.get("StatusExtended") or rec.get("Description") or ""),
                source="prowler",
                remediation=str(
                    (rec.get("Remediation") or {}).get("Recommendation", {}).get("Text", "")
                    if isinstance(rec.get("Remediation"), dict)
                    else rec.get("Remediation") or ""
                ),
            )
        )
    return findings


def _load_securityhub(records: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for rec in records:
        compliance = rec.get("Compliance") or {}
        control_ids = _collect_control_ids(
            compliance.get("RelatedRequirements"),
            compliance.get("SecurityControlId"),
        )
        if not control_ids:
            continue
        severity = (rec.get("Severity") or {}).get("Label", "MEDIUM")
        resources = rec.get("Resources") or []
        resource = resources[0].get("Id", "") if resources else ""
        findings.append(
            Finding(
                id=str(rec.get("Id") or "securityhub"),
                title=str(rec.get("Title") or "Security Hub finding"),
                status=_norm_status(compliance.get("Status", "WARNING")),
                severity=_norm_severity(severity),
                control_ids=control_ids,
                resource=str(resource),
                description=str(rec.get("Description") or ""),
                source="securityhub",
                remediation=str(
                    (rec.get("Remediation") or {}).get("Recommendation", {}).get("Text", "")
                ),
            )
        )
    return findings


def _load_manual(records: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for rec in records:
        control_ids = _collect_control_ids(
            rec.get("control_ids"), rec.get("controls"), rec.get("control_id")
        )
        if not control_ids:
            continue
        findings.append(
            Finding(
                id=str(rec.get("id") or "manual"),
                title=str(rec.get("title") or "Manual finding"),
                status=_norm_status(rec.get("status")),
                severity=_norm_severity(rec.get("severity", "medium")),
                control_ids=control_ids,
                resource=str(rec.get("resource") or ""),
                description=str(rec.get("description") or ""),
                source="manual",
                remediation=str(rec.get("remediation") or ""),
            )
        )
    return findings


def detect_source(data: Any) -> str:
    """Best-effort detection of the input document's source format."""
    if isinstance(data, dict):
        if "Findings" in data:
            return "securityhub"
        if "findings" in data:
            return "manual"
        records = data.get("results") or data.get("data")
        if isinstance(records, list):
            data = records
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            if "CheckID" in first or "Compliance" in first and "Status" in first:
                return "prowler"
            if "control_ids" in first or "controls" in first or "control_id" in first:
                return "manual"
            if "Compliance" in first and "Resources" in first:
                return "securityhub"
    return "manual"


def load_findings(data: Any, source: str | None = None) -> list[Finding]:
    """Normalize an already-parsed JSON document into ``Finding`` objects."""
    source = source or detect_source(data)

    if source == "securityhub":
        records = data["Findings"] if isinstance(data, dict) else data
    elif source == "manual":
        if isinstance(data, dict):
            records = data.get("findings", [])
        else:
            records = data
    else:  # prowler
        if isinstance(data, dict):
            records = data.get("results") or data.get("data") or []
        else:
            records = data

    if not isinstance(records, list):
        raise LoaderError(f"Expected a list of records for source '{source}'.")

    loader = {
        "prowler": _load_prowler,
        "securityhub": _load_securityhub,
        "manual": _load_manual,
    }[source]
    return loader(records)


def load_findings_file(path: str | Path, source: str | None = None) -> list[Finding]:
    """Read a JSON file and normalize it into ``Finding`` objects."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LoaderError(f"Findings file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise LoaderError(f"Invalid JSON in {path}: {exc}") from exc
    return load_findings(data, source)
