"""Core data models for cmmc-scorecard."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    """Normalized finding / control status values."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_ASSESSED = "NOT_ASSESSED"


class Severity(str, Enum):
    """Normalized severity, ordered so members can be compared by weight."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHTS[self]


_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
}


@dataclass
class Finding:
    """A single normalized security finding mapped to CMMC practices."""

    id: str
    title: str
    status: Status
    severity: Severity
    control_ids: list[str]  # canonical CMMC practice ids
    resource: str = ""
    description: str = ""
    source: str = "manual"
    remediation: str = ""


@dataclass
class ControlResult:
    """Aggregated assessment outcome for a single CMMC practice."""

    practice_id: str
    domain: str
    description: str
    status: Status
    findings: list[Finding] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for f in self.findings if f.status is Status.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for f in self.findings if f.status is Status.FAIL)

    @property
    def score(self) -> float:
        """Fractional credit for this control: 1.0 pass, 0.5 partial, else 0.0."""
        if self.status is Status.PASS:
            return 1.0
        if self.status is Status.PARTIAL:
            return 0.5
        return 0.0


@dataclass
class DomainScore:
    """Roll-up of all control results within a CMMC domain."""

    domain: str
    name: str
    controls: list[ControlResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.controls)

    @property
    def assessed(self) -> int:
        return sum(1 for c in self.controls if c.status is not Status.NOT_ASSESSED)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.controls if c.status is Status.PASS)

    @property
    def partial(self) -> int:
        return sum(1 for c in self.controls if c.status is Status.PARTIAL)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.controls if c.status is Status.FAIL)

    @property
    def not_assessed(self) -> int:
        return sum(1 for c in self.controls if c.status is Status.NOT_ASSESSED)

    @property
    def score(self) -> float:
        """Domain coverage score on a 0-100 scale across all practices."""
        if not self.controls:
            return 0.0
        return 100.0 * sum(c.score for c in self.controls) / len(self.controls)

    @property
    def rating(self) -> Status:
        """PASS >= 80, FAIL < 50, otherwise PARTIAL."""
        score = self.score
        if score >= 80.0:
            return Status.PASS
        if score < 50.0:
            return Status.FAIL
        return Status.PARTIAL


@dataclass
class Gap:
    """A control that is failing or not assessed — a compliance gap."""

    practice_id: str
    domain: str
    description: str
    status: Status
    severity: Severity
    finding_count: int
    detail: str = ""


@dataclass
class RemediationItem:
    """A prioritized remediation action derived from a gap."""

    practice_id: str
    domain: str
    description: str
    priority_score: float
    severity: Severity
    rank: int = 0
    rationale: str = ""


@dataclass
class Scorecard:
    """Top-level result object produced by the scoring engine."""

    domain_scores: list[DomainScore]
    gaps: list[Gap]
    remediation: list[RemediationItem]
    findings: list[Finding]
    generated_at: str

    @property
    def overall_score(self) -> float:
        """Mean of domain scores (each domain weighted equally)."""
        if not self.domain_scores:
            return 0.0
        return sum(d.score for d in self.domain_scores) / len(self.domain_scores)

    @property
    def overall_rating(self) -> Status:
        score = self.overall_score
        if score >= 80.0:
            return Status.PASS
        if score < 50.0:
            return Status.FAIL
        return Status.PARTIAL

    @property
    def total_controls(self) -> int:
        return sum(d.total for d in self.domain_scores)

    @property
    def passed_controls(self) -> int:
        return sum(d.passed for d in self.domain_scores)
