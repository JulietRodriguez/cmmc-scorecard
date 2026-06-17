"""cmmc-scorecard: CMMC 2.0 Level 2 compliance scorecard generator.

Takes security findings (Prowler, AWS Security Hub, or manual JSON) and produces
a domain-by-domain CMMC 2.0 Level 2 scorecard with pass/fail/partial ratings,
gap analysis, remediation priorities, and OSCAL Assessment Results output.
"""

__version__ = "1.0.0"

from cmmc_scorecard.models import (
    ControlResult,
    DomainScore,
    Finding,
    Gap,
    RemediationItem,
    Scorecard,
)

__all__ = [
    "__version__",
    "Finding",
    "ControlResult",
    "DomainScore",
    "Gap",
    "RemediationItem",
    "Scorecard",
]
