"""Tests for OSCAL Assessment Results export."""

from __future__ import annotations

import json
import uuid

from cmmc_scorecard.oscal import OSCAL_VERSION, to_oscal


def test_oscal_top_level_structure(scorecard):
    doc = to_oscal(scorecard)
    assert "assessment-results" in doc
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"] == OSCAL_VERSION
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    assert "import-ap" in ar
    assert len(ar["results"]) == 1


def test_oscal_uuids_are_valid(scorecard):
    doc = to_oscal(scorecard)
    ar = doc["assessment-results"]
    uuid.UUID(ar["uuid"])
    result = ar["results"][0]
    uuid.UUID(result["uuid"])
    for finding in result["findings"]:
        uuid.UUID(finding["uuid"])
    for obs in result["observations"]:
        uuid.UUID(obs["uuid"])


def test_oscal_findings_only_for_non_passing(scorecard):
    doc = to_oscal(scorecard)
    result = doc["assessment-results"]["results"][0]
    target_ids = {f["target"]["target-id"] for f in result["findings"]}
    # Passing control should not appear as a finding.
    assert "AC.L2-3.1.1" not in target_ids
    # Failing control should.
    assert "AC.L2-3.1.5" in target_ids


def test_oscal_target_status_states(scorecard):
    doc = to_oscal(scorecard)
    result = doc["assessment-results"]["results"][0]
    for finding in result["findings"]:
        assert finding["target"]["status"]["state"] in {"satisfied", "not-satisfied"}
        # all findings are non-passing controls, so not-satisfied
        assert finding["target"]["status"]["state"] == "not-satisfied"


def test_oscal_findings_link_observations(scorecard):
    doc = to_oscal(scorecard)
    result = doc["assessment-results"]["results"][0]
    obs_uuids = {o["uuid"] for o in result["observations"]}
    for finding in result["findings"]:
        for rel in finding["related-observations"]:
            assert rel["observation-uuid"] in obs_uuids


def test_oscal_is_json_serializable(scorecard):
    doc = to_oscal(scorecard)
    text = json.dumps(doc)
    assert json.loads(text) == doc


def test_reviewed_controls_lists_assessed(scorecard):
    doc = to_oscal(scorecard)
    result = doc["assessment-results"]["results"][0]
    includes = result["reviewed-controls"]["control-selections"][0]["include-controls"]
    listed = {c["control-id"] for c in includes}
    assert "AC.L2-3.1.1" in listed  # assessed (pass)
    assert "MA.L2-3.7.1" not in listed  # not assessed
