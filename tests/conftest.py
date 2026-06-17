"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from cmmc_scorecard.models import Finding, Severity, Status
from cmmc_scorecard.scoring import score_findings

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES


@pytest.fixture
def simple_findings() -> list[Finding]:
    return [
        Finding("f1", "Authorized access", Status.PASS, Severity.HIGH, ["AC.L2-3.1.1"]),
        Finding("f2", "Least priv", Status.FAIL, Severity.HIGH, ["AC.L2-3.1.5"]),
        Finding("f3", "Mixed", Status.PASS, Severity.LOW, ["AC.L2-3.1.8"]),
        Finding("f4", "Mixed", Status.FAIL, Severity.LOW, ["AC.L2-3.1.8"]),
        Finding("f5", "Crit patch", Status.FAIL, Severity.CRITICAL, ["RA.L2-3.11.3"]),
    ]


@pytest.fixture
def scorecard(simple_findings):
    return score_findings(simple_findings)
