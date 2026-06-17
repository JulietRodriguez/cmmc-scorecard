"""Tests for the scoring engine."""

from __future__ import annotations

from cmmc_scorecard.models import Finding, Severity, Status
from cmmc_scorecard.scoring import _aggregate_control_status, score_findings


def _control(scorecard, practice_id):
    for ds in scorecard.domain_scores:
        for c in ds.controls:
            if c.practice_id == practice_id:
                return c
    raise AssertionError(f"{practice_id} not found")


def test_all_14_domains_present(scorecard):
    assert len(scorecard.domain_scores) == 14


def test_total_controls_is_110(scorecard):
    assert scorecard.total_controls == 110


def test_pass_fail_partial_aggregation(scorecard):
    assert _control(scorecard, "AC.L2-3.1.1").status is Status.PASS
    assert _control(scorecard, "AC.L2-3.1.5").status is Status.FAIL
    # 3.1.8 had one pass + one fail -> partial
    assert _control(scorecard, "AC.L2-3.1.8").status is Status.PARTIAL


def test_unmapped_control_is_not_assessed(scorecard):
    assert _control(scorecard, "MA.L2-3.7.1").status is Status.NOT_ASSESSED


def test_aggregate_status_rules():
    def f(s):
        return Finding("x", "t", s, Severity.LOW, ["AC.L2-3.1.1"])

    assert _aggregate_control_status([]) is Status.NOT_ASSESSED
    assert _aggregate_control_status([f(Status.PASS)]) is Status.PASS
    assert _aggregate_control_status([f(Status.FAIL)]) is Status.FAIL
    assert _aggregate_control_status([f(Status.PASS), f(Status.FAIL)]) is Status.PARTIAL
    assert _aggregate_control_status([f(Status.PARTIAL)]) is Status.PARTIAL
    # NOT_ASSESSED findings are ignored in aggregation
    assert _aggregate_control_status([f(Status.NOT_ASSESSED)]) is Status.NOT_ASSESSED


def test_domain_score_and_rating():
    findings = [
        Finding(f"p{i}", "t", Status.PASS, Severity.LOW, [f"AC.L2-3.1.{i}"])
        for i in range(1, 23)  # all 22 AC practices pass
    ]
    sc = score_findings(findings)
    ac = next(d for d in sc.domain_scores if d.domain == "AC")
    assert ac.score == 100.0
    assert ac.rating is Status.PASS
    assert ac.passed == 22


def test_partial_control_scores_half(scorecard):
    ac = next(d for d in scorecard.domain_scores if d.domain == "AC")
    # AC has 22 practices: 1 pass + 1 partial(0.5) out of 22.
    expected = 100.0 * (1.0 + 0.5) / 22
    assert abs(ac.score - expected) < 1e-6


def test_gaps_include_failures_and_unassessed(scorecard):
    gap_ids = {g.practice_id for g in scorecard.gaps}
    assert "AC.L2-3.1.5" in gap_ids  # failing
    assert "MA.L2-3.7.1" in gap_ids  # not assessed
    assert "AC.L2-3.1.1" not in gap_ids  # passing -> not a gap


def test_gap_count_excludes_passing(scorecard):
    # 110 total, only AC.L2-3.1.1 passes -> 109 gaps
    assert len(scorecard.gaps) == 109


def test_remediation_ranked_and_critical_first(scorecard):
    assert scorecard.remediation[0].rank == 1
    # The critical RA finding should outrank routine not-assessed items.
    top = scorecard.remediation[0]
    assert top.severity is Severity.CRITICAL
    assert top.practice_id == "RA.L2-3.11.3"
    scores = [r.priority_score for r in scorecard.remediation]
    assert scores == sorted(scores, reverse=True)


def test_overall_score_is_mean_of_domains(scorecard):
    expected = sum(d.score for d in scorecard.domain_scores) / 14
    assert abs(scorecard.overall_score - expected) < 1e-6


def test_empty_findings_produce_zero_score():
    sc = score_findings([])
    assert sc.overall_score == 0.0
    assert sc.overall_rating is Status.FAIL
    assert len(sc.gaps) == 110
