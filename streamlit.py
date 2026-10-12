from pathlib import Path
import sys
import streamlit as st

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from investigation.investigation_planner import InvestigationPlanner
from investigation.investigation_executor import InvestigationExecutor
from investigation.evidence_filter import EvidenceFilter
from investigation.root_cause_analyzer import RootCauseAnalyzer

st.set_page_config(
    page_title="SMYD RCA Copilot",
    page_icon="🧭",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Light, high-contrast theme. Text input rules are deliberately explicit because
# browser/Streamlit themes can otherwise leave pale text on a pale textarea.
st.markdown(
    """
    <style>
    :root {
      --navy: #14233f;
      --blue: #315efb;
      --ink: #172033;
      --muted: #59677d;
      --border: #d9e1ed;
      --surface: #ffffff;
      --canvas: #f4f7fb;
    }
    .stApp { background: var(--canvas); color: var(--ink); }
    [data-testid="stHeader"] { background: rgba(244,247,251,.96); }
    [data-testid="stSidebar"] {
      background: #ffffff;
      border-right: 1px solid var(--border);
    }
    [data-testid="stSidebar"] * { color: #243149; }
    .hero {
      padding: 1.8rem 2rem; border-radius: 18px;
      background: linear-gradient(120deg, #14233f 0%, #213b68 100%);
      color: white; margin: .3rem 0 1.5rem 0;
      box-shadow: 0 8px 24px rgba(20,35,63,.12);
    }
    .hero .eyebrow { color: #a9c5ff; text-transform: uppercase;
      letter-spacing: .16em; font-size: .75rem; font-weight: 800; }
    .hero h1 { color: #ffffff !important; margin: .45rem 0 .55rem 0;
      font-size: 2.15rem; line-height: 1.2; }
    .hero p { color: #e2eaff !important; margin: 0; font-size: 1.02rem; }
    h1, h2, h3, p, label, .stMarkdown { color: var(--ink); }
    .stCaption, [data-testid="stCaptionContainer"] { color: var(--muted) !important; }
    div[data-testid="stTextArea"] textarea,
    div[data-testid="stTextInput"] input {
      background: #ffffff !important;
      color: #172033 !important;
      -webkit-text-fill-color: #172033 !important;
      caret-color: #172033 !important;
      border: 1px solid #b9c6d8 !important;
      border-radius: 10px !important;
      opacity: 1 !important;
    }
    div[data-testid="stTextArea"] textarea::placeholder,
    div[data-testid="stTextInput"] input::placeholder {
      color: #78869b !important;
      -webkit-text-fill-color: #78869b !important;
      opacity: 1 !important;
    }
    div[data-testid="stTextArea"] textarea:focus,
    div[data-testid="stTextInput"] input:focus {
      border-color: #315efb !important;
      box-shadow: 0 0 0 2px rgba(49,94,251,.15) !important;
    }
    div[data-testid="stForm"] {
      background: #ffffff; padding: 1rem;
      border: 1px solid var(--border); border-radius: 14px;
    }
    div[data-testid="stMetric"] {
      background: #ffffff; border: 1px solid var(--border);
      padding: .9rem; border-radius: 12px;
    }
    div[data-testid="stMetricLabel"] { color: #59677d !important; }
    div[data-testid="stMetricValue"] { color: #172033 !important; }
    div.stButton > button[kind="primary"],
    div[data-testid="stFormSubmitButton"] button {
      background: #315efb !important; color: #ffffff !important;
      border: 1px solid #315efb !important; border-radius: 10px !important;
      font-weight: 700 !important; min-height: 2.8rem;
    }
    div.stButton > button[kind="primary"]:hover,
    div[data-testid="stFormSubmitButton"] button:hover {
      background: #244bd6 !important; border-color: #244bd6 !important;
    }
    .info-card {
      background: #ffffff; border: 1px solid var(--border);
      border-radius: 14px; padding: 1rem 1.2rem; margin-bottom: .7rem;
    }
    .muted { color: #59677d !important; font-size: .9rem; }
    [data-testid="stExpander"] { background: #ffffff; border-radius: 10px; }
    code { color: #244bd6 !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("## 🧭 SMYD RCA Copilot")
    st.caption("ServiceNow • Evidence-based diagnostics")
    st.divider()
    st.markdown("### Investigation workflow")
    st.markdown("① Understand the issue")
    st.markdown("② Retrieve ServiceNow evidence")
    st.markdown("③ Classify evidence")
    st.markdown("④ Generate RCA report")
    st.divider()
    st.markdown("### Read-only safety")
    st.caption("The investigation retrieves configuration evidence only. It does not update ServiceNow records.")
    st.caption("Credentials are loaded from your existing Application/.env file.")

st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">People · Process · Technology</div>
      <h1>Root Cause Analysis Copilot</h1>
      <p>Investigate ServiceNow issues using configuration evidence, retrieval coverage, and explainable findings.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

input_col, examples_col = st.columns([1.55, 1], gap="large")
with input_col:
    st.subheader("Describe the problem")
    with st.form("investigation_form", clear_on_submit=False):
        question = st.text_area(
            "Technical issue",
            placeholder=(
                "Example: Additional comments becomes mandatory when "
                "the incident is on hold with reason Awaiting Caller."
            ),
            height=160,
            label_visibility="collapsed",
        )
        submitted = st.form_submit_button(
            "▶  Investigate issue",
            type="primary",
            use_container_width=True,
        )
    st.markdown(
        '<p class="muted">Include the table, field, trigger, expected behavior, and actual behavior when known.</p>',
        unsafe_allow_html=True,
    )

with examples_col:
    st.subheader("Example investigations")
    examples = [
        "Incident assignment group changes unexpectedly.",
        "On Hold Reason becomes mandatory on On Hold.",
        "Notifications trigger when incident worknotes are updated.",
        "A Client Script does not make a field mandatory.",
    ]
    for item in examples:
        st.markdown(
            f'<div class="info-card">↗ &nbsp; {item}</div>',
            unsafe_allow_html=True,
        )

if submitted:
    if not question.strip():
        st.warning("Enter a ServiceNow problem before starting the investigation.")
    else:
        executor = None
        try:
            progress = st.progress(0, text="Preparing investigation…")
            with st.status("Investigation running", expanded=True) as status:
                st.write("**Step 1/4 — Generating investigation plan**")
                planner = InvestigationPlanner()
                plan = planner.create_plan(question.strip())
                plan_data = plan.model_dump() if hasattr(plan, "model_dump") else plan
                progress.progress(25, text="Investigation plan generated")

                st.write("**Step 2/4 — Retrieving ServiceNow evidence**")
                executor = InvestigationExecutor(max_records_per_step=10)
                execution_result = executor.execute_plan(plan)
                progress.progress(50, text="ServiceNow evidence retrieved")

                st.write("**Step 3/4 — Classifying evidence**")
                filtered = EvidenceFilter().filter_evidence(
                    question=question.strip(),
                    execution_result=execution_result,
                )
                progress.progress(75, text="Evidence classified")

                st.write("**Step 4/4 — Generating root-cause assessment**")
                if execution_result.get("summary", {}).get("total_records", 0) == 0:
                    report = (
                        "## ROOT CAUSE ASSESSMENT: UNDETERMINED\n\n"
                        "No records were retrieved. Review the investigation plan, "
                        "target tables, permissions, and retrieval errors."
                    )
                else:
                    report = RootCauseAnalyzer().analyze(
                        question=question.strip(),
                        execution_result=execution_result,
                        filtered_evidence=filtered,
                    )
                progress.progress(100, text="Investigation complete")
                status.update(label="Investigation complete", state="complete", expanded=False)

            st.session_state["rca_last_run"] = {
                "question": question.strip(),
                "plan": plan_data,
                "execution": execution_result,
                "filtered": filtered,
                "report": report,
            }
        except Exception as exc:
            st.error(f"Investigation failed: {type(exc).__name__}: {exc}")
            st.info("Check your existing .env configuration and ServiceNow read permissions.")
        finally:
            if executor is not None:
                executor.close()

if "rca_last_run" in st.session_state:
    result = st.session_state["rca_last_run"]
    st.divider()
    st.subheader("Investigation results")
    summary = result["execution"].get("summary", {})
    counts = result["filtered"].get("counts", {})
    metric_cols = st.columns(5)
    metric_cols[0].metric("Steps attempted", summary.get("steps_attempted", 0))
    metric_cols[1].metric("Records selected", summary.get("total_records", 0))
    metric_cols[2].metric("Candidates scanned", summary.get("total_candidates_scanned", 0))
    metric_cols[3].metric("Ranked out", summary.get("records_ranked_out", 0))
    metric_cols[4].metric("Relevant evidence", counts.get("relevant", 0))

    report_tab, evidence_tab, plan_tab, retrieval_tab = st.tabs(
        ["📌 RCA report", "🔎 Evidence", "🧩 Investigation plan", "⚙️ Retrieval details"]
    )
    with report_tab:
        st.markdown(result["report"])
        st.download_button(
            "Download RCA report",
            data=result["report"],
            file_name="smyd_rca_report.md",
            mime="text/markdown",
        )
    with evidence_tab:
        for label, key in [
            ("Relevant", "relevant_evidence"),
            ("Potentially relevant", "potentially_relevant_evidence"),
            ("Low relevance", "low_relevance_evidence"),
        ]:
            items = result["filtered"].get(key, [])
            with st.expander(f"{label} ({len(items)})", expanded=(label == "Relevant")):
                if items:
                    rows = [{
                        "Source": item.get("source"),
                        "Name": item.get("name") or "(name unavailable)",
                        "sys_id": item.get("sys_id"),
                        "Relevance": item.get("relevance"),
                        "Score": item.get("relevance_score"),
                        "Reasons": "; ".join(item.get("reasons", []))
                        if isinstance(item.get("reasons"), list)
                        else item.get("reasons"),
                    } for item in items]
                    st.dataframe(rows, use_container_width=True, hide_index=True)
                else:
                    st.caption("No records in this category.")
    with plan_tab:
        st.markdown(f"**Problem:** {result['question']}")
        st.json(result["plan"])
    with retrieval_tab:
        st.json(summary)
        rows = [{
            "Step": step_id,
            "Source": item.get("source"),
            "Status": item.get("status"),
            "Candidates": item.get("candidate_count", 0),
            "Selected": item.get("count", 0),
            "Ranked out": item.get("ranking", {}).get("records_ranked_out", 0),
            "Error": item.get("error"),
        } for step_id, item in result["execution"].get("results", {}).items()]
        st.dataframe(rows, use_container_width=True, hide_index=True)
        if result["filtered"].get("retrieval_issues"):
            st.warning("Retrieval issues were reported.")
            st.json(result["filtered"]["retrieval_issues"])

st.divider()
st.caption("SMYD Global • ServiceNow Root Cause Analysis • Read-only investigation")
