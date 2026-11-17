"""Streamlit dashboard for cmmc-scorecard.

Run with::

    streamlit run cmmc_scorecard/dashboard.py

Dark, professional security-tool theme with domain scores, a radar chart of
CMMC domain coverage, gap-analysis cards, and remediation priority ranking.
"""

from __future__ import annotations

import json
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

from cmmc_scorecard.loaders import LoaderError, load_findings
from cmmc_scorecard.models import Scorecard, Status
from cmmc_scorecard.scoring import score_findings

# ---- Theme constants -------------------------------------------------------
BG = "#0b0f17"
PANEL = "#121826"
ACCENT = "#22d3ee"
GREEN = "#22c55e"
YELLOW = "#eab308"
RED = "#ef4444"
DIM = "#64748b"

STATUS_COLOR = {
    Status.PASS: GREEN,
    Status.FAIL: RED,
    Status.PARTIAL: YELLOW,
    Status.NOT_ASSESSED: DIM,
}

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def _inject_css() -> None:
    st.markdown(
        f"""
        <style>
        .stApp {{ background-color: {BG}; color: #e2e8f0; }}
        section[data-testid="stSidebar"] {{ background-color: {PANEL}; }}
        h1, h2, h3 {{ color: #f1f5f9; font-family: 'Segoe UI', sans-serif; }}
        .metric-card {{
            background: {PANEL}; border: 1px solid #1e293b; border-radius: 12px;
            padding: 18px; margin-bottom: 12px;
        }}
        .gap-card {{
            background: {PANEL}; border-left: 4px solid {RED};
            border-radius: 8px; padding: 12px 16px; margin-bottom: 10px;
        }}
        .gap-card.partial {{ border-left-color: {YELLOW}; }}
        .gap-card.na {{ border-left-color: {DIM}; }}
        .pill {{
            display:inline-block; padding:2px 10px; border-radius:999px;
            font-size:0.72rem; font-weight:700; letter-spacing:0.04em;
        }}
        .mono {{ font-family: 'JetBrains Mono','Consolas',monospace; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _color_for_score(score: float) -> str:
    if score >= 80:
        return GREEN
    if score < 50:
        return RED
    return YELLOW


def radar_chart(scorecard: Scorecard) -> go.Figure:
    domains = [ds.domain for ds in scorecard.domain_scores]
    scores = [ds.score for ds in scorecard.domain_scores]
    # Close the loop for a continuous polygon.
    domains_loop = domains + [domains[0]]
    scores_loop = scores + [scores[0]]

    fig = go.Figure()
    fig.add_trace(
        go.Scatterpolar(
            r=[80] * len(domains_loop),
            theta=domains_loop,
            mode="lines",
            line={"color": GREEN, "width": 1, "dash": "dot"},
            name="Target (80)",
            hoverinfo="skip",
        )
    )
    fig.add_trace(
        go.Scatterpolar(
            r=scores_loop,
            theta=domains_loop,
            fill="toself",
            fillcolor="rgba(34,211,238,0.25)",
            line={"color": ACCENT, "width": 2},
            name="Coverage",
            hovertemplate="%{theta}: %{r:.0f}/100<extra></extra>",
        )
    )
    fig.update_layout(
        polar={
            "bgcolor": PANEL,
            "radialaxis": {"visible": True, "range": [0, 100], "gridcolor": "#1e293b", "tickfont": {"color": DIM}},
            "angularaxis": {"gridcolor": "#1e293b", "tickfont": {"color": "#cbd5e1", "size": 12}},
        },
        paper_bgcolor="rgba(0,0,0,0)",
        font={"color": "#e2e8f0"},
        showlegend=True,
        legend={"orientation": "h", "y": -0.08},
        margin={"l": 40, "r": 40, "t": 30, "b": 40},
        height=460,
    )
    return fig


def domain_bar(scorecard: Scorecard) -> go.Figure:
    domains = [f"{ds.domain}" for ds in scorecard.domain_scores]
    scores = [ds.score for ds in scorecard.domain_scores]
    colors = [_color_for_score(s) for s in scores]
    fig = go.Figure(
        go.Bar(
            x=scores,
            y=domains,
            orientation="h",
            marker={"color": colors},
            hovertemplate="%{y}: %{x:.0f}/100<extra></extra>",
        )
    )
    fig.add_vline(x=80, line={"color": GREEN, "width": 1, "dash": "dot"})
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor=PANEL,
        font={"color": "#e2e8f0"},
        xaxis={"range": [0, 100], "gridcolor": "#1e293b"},
        yaxis={"autorange": "reversed"},
        margin={"l": 10, "r": 10, "t": 10, "b": 10},
        height=460,
    )
    return fig


def _pill(status: Status) -> str:
    color = STATUS_COLOR[status]
    return f'<span class="pill" style="background:{color}22;color:{color};">{status.value}</span>'


def render(scorecard: Scorecard) -> None:
    rating = scorecard.overall_rating
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f'<div class="metric-card"><div style="color:{DIM}">Overall Score</div>'
            f'<div style="font-size:2.2rem;font-weight:800;color:{_color_for_score(scorecard.overall_score)}">'
            f"{scorecard.overall_score:.0f}<span style='font-size:1rem;color:{DIM}'>/100</span></div>"
            f"{_pill(rating)}</div>",
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f'<div class="metric-card"><div style="color:{DIM}">Practices Satisfied</div>'
            f'<div style="font-size:2.2rem;font-weight:800;color:{ACCENT}">'
            f"{scorecard.passed_controls}<span style='font-size:1rem;color:{DIM}'>/{scorecard.total_controls}</span></div>"
            f'<span style="color:{DIM};font-size:0.8rem">110-practice CMMC L2 baseline</span></div>',
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f'<div class="metric-card"><div style="color:{DIM}">Open Gaps</div>'
            f'<div style="font-size:2.2rem;font-weight:800;color:{RED}">{len(scorecard.gaps)}</div>'
            f'<span style="color:{DIM};font-size:0.8rem">failing or not assessed</span></div>',
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f'<div class="metric-card"><div style="color:{DIM}">Findings Ingested</div>'
            f'<div style="font-size:2.2rem;font-weight:800;color:#f1f5f9">{len(scorecard.findings)}</div>'
            f'<span style="color:{DIM};font-size:0.8rem">mapped to practices</span></div>',
            unsafe_allow_html=True,
        )

    st.subheader("Domain Coverage")
    left, right = st.columns([1, 1])
    with left:
        st.plotly_chart(radar_chart(scorecard), use_container_width=True)
    with right:
        st.plotly_chart(domain_bar(scorecard), use_container_width=True)

    st.subheader("Domain Detail")
    st.dataframe(
        {
            "Domain": [f"{ds.domain} · {ds.name}" for ds in scorecard.domain_scores],
            "Score": [round(ds.score, 1) for ds in scorecard.domain_scores],
            "Rating": [ds.rating.value for ds in scorecard.domain_scores],
            "Pass": [ds.passed for ds in scorecard.domain_scores],
            "Partial": [ds.partial for ds in scorecard.domain_scores],
            "Fail": [ds.failed for ds in scorecard.domain_scores],
            "N/A": [ds.not_assessed for ds in scorecard.domain_scores],
        },
        use_container_width=True,
        hide_index=True,
    )

    g_col, r_col = st.columns([1, 1])
    with g_col:
        st.subheader(f"Gap Analysis ({len(scorecard.gaps)})")
        for gap in scorecard.gaps[:25]:
            cls = "partial" if gap.status is Status.PARTIAL else (
                "na" if gap.status is Status.NOT_ASSESSED else ""
            )
            st.markdown(
                f'<div class="gap-card {cls}">'
                f'<span class="mono" style="color:{ACCENT}">{gap.practice_id}</span> '
                f"{_pill(gap.status)} "
                f'<span class="pill" style="background:#33415555;color:#cbd5e1">{gap.severity.value}</span>'
                f'<div style="margin-top:6px;color:#cbd5e1">{gap.description}</div>'
                f'<div style="color:{DIM};font-size:0.8rem;margin-top:4px">{gap.detail}</div>'
                f"</div>",
                unsafe_allow_html=True,
            )
    with r_col:
        st.subheader("Remediation Priorities")
        for item in scorecard.remediation[:25]:
            st.markdown(
                f'<div class="gap-card">'
                f'<span style="font-weight:800;color:{ACCENT}">#{item.rank}</span> '
                f'<span class="mono">{item.practice_id}</span> '
                f'<span class="pill" style="background:{ACCENT}22;color:{ACCENT}">priority {item.priority_score:.1f}</span>'
                f'<div style="margin-top:6px;color:#cbd5e1">{item.description}</div>'
                f'<div style="color:{DIM};font-size:0.8rem;margin-top:4px">{item.rationale}</div>'
                f"</div>",
                unsafe_allow_html=True,
            )


def _list_samples() -> dict[str, Path]:
    if not SAMPLES_DIR.exists():
        return {}
    return {p.name: p for p in sorted(SAMPLES_DIR.glob("*.json"))}


def main() -> None:
    st.set_page_config(
        page_title="CMMC Scorecard", page_icon="🛡️", layout="wide",
        initial_sidebar_state="expanded",
    )
    _inject_css()
    st.markdown(
        f'<h1>🛡️ CMMC 2.0 Level 2 Scorecard</h1>'
        f'<p style="color:{DIM};margin-top:-12px">Domain-by-domain compliance posture from your security findings.</p>',
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.header("Data Source")
        source = st.selectbox(
            "Input format", ["auto", "prowler", "securityhub", "manual"], index=0
        )
        uploaded = st.file_uploader("Upload findings JSON", type="json")
        samples = _list_samples()
        sample_choice = st.selectbox(
            "…or pick a sample", ["(none)"] + list(samples), index=1 if samples else 0
        )

    data = None
    if uploaded is not None:
        data = json.load(uploaded)
    elif sample_choice != "(none)" and sample_choice in samples:
        data = json.loads(samples[sample_choice].read_text(encoding="utf-8"))

    if data is None:
        st.info("Upload a findings file or choose a sample to generate the scorecard.")
        return

    try:
        findings = load_findings(data, None if source == "auto" else source)
    except LoaderError as exc:
        st.error(f"Could not parse findings: {exc}")
        return

    if not findings:
        st.warning("No findings mapped to CMMC practices in this file.")
    render(score_findings(findings))


if __name__ == "__main__":
    main()
