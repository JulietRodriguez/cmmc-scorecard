"""Tests for the CMMC catalog and control-id normalization."""

from __future__ import annotations

import pytest

from cmmc_scorecard.domains import (
    CATALOG,
    DOMAIN_NAMES,
    DOMAIN_ORDER,
    domain_of,
    normalize_control_id,
    practices_for_domain,
    total_practice_count,
)

# Expected practice counts per CMMC 2.0 L2 domain (NIST 800-171 r2).
EXPECTED_COUNTS = {
    "AC": 22, "AT": 3, "AU": 9, "CM": 9, "IA": 11, "IR": 3, "MA": 6,
    "MP": 9, "PS": 2, "PE": 6, "RA": 3, "CA": 4, "SC": 16, "SI": 7,
}


def test_catalog_has_110_practices():
    assert total_practice_count() == 110


def test_domain_order_covers_all_14_domains():
    assert set(DOMAIN_ORDER) == set(DOMAIN_NAMES)
    assert len(DOMAIN_ORDER) == 14


@pytest.mark.parametrize("domain,count", EXPECTED_COUNTS.items())
def test_per_domain_practice_counts(domain, count):
    assert len(practices_for_domain(domain)) == count


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("3.1.1", "AC.L2-3.1.1"),
        ("AC.L2-3.1.1", "AC.L2-3.1.1"),
        ("NIST.800-171.r2 3.5.3", "IA.L2-3.5.3"),
        ("NIST-800-171-Revision-2 3.13.16", "SC.L2-3.13.16"),
        ("  3.14.1  ", "SI.L2-3.14.1"),
        ("AC-3.1.8", "AC.L2-3.1.8"),
    ],
)
def test_normalize_control_id(raw, expected):
    assert normalize_control_id(raw) == expected


@pytest.mark.parametrize("raw", ["", "not-a-control", "CIS 1.5", "9.9.9-ish text", None])
def test_normalize_returns_none_for_unmappable(raw):
    if raw is None:
        # the function guards against falsy input
        assert normalize_control_id("") is None
    else:
        assert normalize_control_id(raw) is None


def test_domain_of():
    assert domain_of("SC.L2-3.13.1") == "SC"
    assert domain_of("does-not-exist") is None


def test_every_practice_id_well_formed():
    for pid, practice in CATALOG.items():
        assert pid.startswith(f"{practice.domain}.L2-")
        assert practice.nist_id in pid
        assert practice.domain_name == DOMAIN_NAMES[practice.domain]
