"""Tests for the Rich CLI."""

from __future__ import annotations

import json

import pytest

from cmmc_scorecard.cli import main


def test_score_command_renders(capsys, samples_dir):
    rc = main(["score", str(samples_dir / "manual_sample.json")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CMMC 2.0 Level 2 Scorecard" in out
    assert "Domain Coverage" in out
    assert "Remediation" in out


def test_score_json_output(capsys, samples_dir):
    rc = main(["score", str(samples_dir / "prowler_sample.json"), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["total_controls"] == 110
    assert len(payload["domains"]) == 14
    assert "overall_rating" in payload


def test_gaps_command(capsys, samples_dir):
    rc = main(["gaps", str(samples_dir / "securityhub_sample.json")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Gap Analysis" in out


def test_oscal_command_writes_file(tmp_path, samples_dir, capsys):
    out_path = tmp_path / "results.json"
    rc = main(["oscal", str(samples_dir / "manual_sample.json"), "-o", str(out_path)])
    assert rc == 0
    assert out_path.exists()
    doc = json.loads(out_path.read_text(encoding="utf-8"))
    assert doc["assessment-results"]["metadata"]["oscal-version"] == "1.1.2"


def test_score_with_oscal_flag(tmp_path, samples_dir):
    out_path = tmp_path / "embedded.json"
    rc = main(
        ["score", str(samples_dir / "manual_sample.json"), "--oscal", str(out_path), "--no-gaps"]
    )
    assert rc == 0
    assert out_path.exists()


def test_forced_source_flag(capsys, samples_dir):
    rc = main(
        ["score", str(samples_dir / "prowler_sample.json"), "--source", "prowler", "--json"]
    )
    assert rc == 0


def test_missing_file_exits_nonzero(samples_dir):
    with pytest.raises(SystemExit) as exc:
        main(["score", "nonexistent-file.json"])
    assert exc.value.code == 2
