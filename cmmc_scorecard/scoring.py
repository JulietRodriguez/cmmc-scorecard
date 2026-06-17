"""The scoring engine: turns normalized findings into a ``Scorecard``."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from cmmc_scorecard.domains import (
    CATALOG,
    DOMAIN_NAMES,
    DOMAIN_ORDER,
)
from cmmc_scorecard.models import (
    ControlResult,
    DomainScore,
    Finding,
    Gap,
    RemediationItem,
    Scorecard,
    Severity,
    Status,
)


def _aggregate_control_status(findings: list[Finding]) -> Status:
    """Derive a control's status from the findings mapped to it."""
    relevant = [f for f in findings if f.status is not Status.NOT_ASSESSED]
    if not relevant:
        return Status.NOT_ASSESSED
    has_fail = any(f.status is Status.FAIL for f in relevant)
    has_pass = any(f.status is Status.PASS for f in relevant)
    has_partial = any(f.status is Status.PARTIAL for f in relevant)
    if has_fail and has_pass:
        return Status.PARTIAL
    if has_partial:
        return Status.PARTIAL
    if has_fail:
        return Status.FAIL
    return Status.PASS


def _build_control_results(findings: list[Finding]) -> dict[str, ControlResult]:
    """Build one ControlResult per catalog practice, attaching findings."""
    by_control: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for practice_id in finding.control_ids:
            if practice_id in CATALOG:
                by_control[practice_id].append(finding)

    results: dict[str, ControlResult] = {}
    for practice_id, practice in CATALOG.items():
        control_findings = by_control.get(practice_id, [])
        results[practice_id] = ControlResult(
            practice_id=practice_id,
            domain=practice.domain,
            description=practice.description,
            status=_aggregate_control_status(control_findings),
            findings=control_findings,
        )
    return results


def _worst_severity(findings: list[Finding]) -> Severity:
    """Highest severity among failing/partial findings (default MEDIUM)."""
    relevant = [f for f in findings if f.status in (Status.FAIL, Status.PARTIAL)]
    if not relevant:
        return Severity.MEDIUM
    return min(relevant, key=lambda f: f.severity.weight * -1).severity


def _build_gaps(results: dict[str, ControlResult]) -> list[Gap]:
    gaps: list[Gap] = []
    for result in results.values():
        if result.status in (Status.PASS,):
            continue
        if result.status is Status.NOT_ASSESSED:
            severity = Severity.MEDIUM
            detail = "No findings mapped to this practice; coverage gap."
        else:
            severity = _worst_severity(result.findings)
            detail = (
                f"{result.failed} failing / {len(result.findings)} mapped finding(s)."
            )
        gaps.append(
            Gap(
                practice_id=result.practice_id,
                domain=result.domain,
                description=result.description,
                status=result.status,
                severity=severity,
                finding_count=len(result.findings),
                detail=detail,
            )
        )
    return gaps


# Status weighting used in remediation prioritization.
_STATUS_URGENCY: dict[Status, float] = {
    Status.FAIL: 1.0,
    Status.PARTIAL: 0.6,
    Status.NOT_ASSESSED: 0.4,
}


def _build_remediation(gaps: list[Gap]) -> list[RemediationItem]:
    """Rank gaps by a priority score: severity x status urgency x finding volume."""
    items: list[RemediationItem] = []
    for gap in gaps:
        urgency = _STATUS_URGENCY.get(gap.status, 0.5)
        volume_factor = 1.0 + min(gap.finding_count, 10) * 0.1
        score = gap.severity.weight * urgency * volume_factor
        rationale = (
            f"{gap.severity.value} severity, {gap.status.value.lower()} "
            f"({gap.finding_count} finding(s))"
        )
        items.append(
            RemediationItem(
                practice_id=gap.practice_id,
                domain=gap.domain,
                description=gap.description,
                priority_score=round(score, 2),
                severity=gap.severity,
                rationale=rationale,
            )
        )
    items.sort(key=lambda i: i.priority_score, reverse=True)
    for rank, item in enumerate(items, start=1):
        item.rank = rank
    return items


def score_findings(findings: list[Finding]) -> Scorecard:
    """Produce a full :class:`Scorecard` from normalized findings."""
    results = _build_control_results(findings)

    domain_scores: list[DomainScore] = []
    for domain in DOMAIN_ORDER:
        controls = [
            r for pid, r in results.items() if CATALOG[pid].domain == domain
        ]
        controls.sort(key=lambda c: _nist_sort_key(CATALOG[c.practice_id].nist_id))
        domain_scores.append(
            DomainScore(domain=domain, name=DOMAIN_NAMES[domain], controls=controls)
        )

    gaps = _build_gaps(results)
    gaps.sort(key=lambda g: (g.severity.weight * -1, g.practice_id))
    remediation = _build_remediation(gaps)

    return Scorecard(
        domain_scores=domain_scores,
        gaps=gaps,
        remediation=remediation,
        findings=findings,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def _nist_sort_key(nist_id: str) -> tuple[int, ...]:
    return tuple(int(part) for part in nist_id.split("."))
