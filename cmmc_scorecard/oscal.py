"""Export a :class:`Scorecard` as an OSCAL 1.1.2 Assessment Results document.

The output conforms to the OSCAL Assessment Results model
(https://pages.nist.gov/OSCAL/). Each CMMC practice that was assessed becomes a
``reviewed-control`` and each non-passing control becomes an OSCAL ``finding``
with an associated ``observation`` and a target status of
``satisfied`` / ``not-satisfied``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from cmmc_scorecard import __version__
from cmmc_scorecard.models import Scorecard, Status

OSCAL_VERSION = "1.1.2"

# Map our internal status onto OSCAL objective status states.
_OSCAL_STATE: dict[Status, str] = {
    Status.PASS: "satisfied",
    Status.FAIL: "not-satisfied",
    Status.PARTIAL: "not-satisfied",
    Status.NOT_ASSESSED: "not-satisfied",
}


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def to_oscal(scorecard: Scorecard, title: str | None = None) -> dict[str, Any]:
    """Build an OSCAL Assessment Results dictionary from a scorecard."""
    title = title or "CMMC 2.0 Level 2 Assessment Results"
    now = _now()

    controls = [c for ds in scorecard.domain_scores for c in ds.controls]
    assessed = [c for c in controls if c.status is not Status.NOT_ASSESSED]

    include_controls = [
        {"control-id": c.practice_id} for c in assessed
    ] or [{"control-id": "none"}]

    observations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for control in controls:
        if control.status is Status.PASS:
            continue

        observation_uuid = _uuid()
        observations.append(
            {
                "uuid": observation_uuid,
                "title": f"Observation for {control.practice_id}",
                "description": (
                    f"{control.description} Aggregated status: "
                    f"{control.status.value}."
                ),
                "methods": ["EXAMINE"],
                "collected": now,
                **(
                    {
                        "relevant-evidence": [
                            {
                                "description": (
                                    f"[{f.source}] {f.title} "
                                    f"({f.status.value}) on {f.resource or 'n/a'}"
                                )
                            }
                            for f in control.findings
                        ]
                    }
                    if control.findings
                    else {}
                ),
            }
        )

        findings.append(
            {
                "uuid": _uuid(),
                "title": f"{control.practice_id} — {control.status.value}",
                "description": control.description,
                "target": {
                    "type": "objective-id",
                    "target-id": control.practice_id,
                    "status": {"state": _OSCAL_STATE[control.status]},
                },
                "related-observations": [{"observation-uuid": observation_uuid}],
            }
        )

    result = {
        "uuid": _uuid(),
        "title": "CMMC Level 2 Scorecard Result",
        "description": (
            f"Overall coverage score {scorecard.overall_score:.1f}/100 "
            f"({scorecard.overall_rating.value}). "
            f"{scorecard.passed_controls}/{scorecard.total_controls} practices satisfied."
        ),
        "start": scorecard.generated_at,
        "end": now,
        "reviewed-controls": {
            "control-selections": [{"include-controls": include_controls}]
        },
        "observations": observations,
        "findings": findings,
    }

    return {
        "assessment-results": {
            "uuid": _uuid(),
            "metadata": {
                "title": title,
                "last-modified": now,
                "version": __version__,
                "oscal-version": OSCAL_VERSION,
                "props": [
                    {
                        "name": "framework",
                        "value": "CMMC 2.0 Level 2",
                        "ns": "https://cmmc-scorecard.local/ns",
                    }
                ],
                "roles": [
                    {"id": "assessor", "title": "Assessor"},
                ],
                "parties": [
                    {
                        "uuid": _uuid(),
                        "type": "organization",
                        "name": "cmmc-scorecard",
                    }
                ],
            },
            "import-ap": {"href": "#cmmc-l2-assessment-plan"},
            "results": [result],
        }
    }
