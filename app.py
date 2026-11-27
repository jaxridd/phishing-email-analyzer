"""Streamlit interface for the AI Phishing Email Analyzer."""

from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

from analyzer.parser import MAX_INPUT_BYTES, EmailParseError
from analyzer.pipeline import analyze_email

load_dotenv()  # reads GEMINI_API_KEY from .env when running locally

SAMPLES_DIR = Path(__file__).parent / "samples"
SAMPLE_FILES = {
    "Phishing example": "phishing_contoso_login.eml",
    "Legitimate example": "legitimate_contoso_newsletter.eml",
}
SEVERITY_ICONS = {"high": "🔴", "medium": "🟠", "low": "🟡"}
CATEGORY_LABELS = {"header": "Headers", "link": "Links", "content": "Content", "attachment": "Attachments"}

st.set_page_config(page_title="Phishing Email Analyzer", page_icon="🛡️", layout="wide")


def load_sample(filename: str) -> None:
    """Fill the text area with a sample email (used by the sample buttons)."""
    st.session_state.raw_email = (SAMPLES_DIR / filename).read_text(encoding="utf-8")


def read_upload(uploaded_file) -> str:
    """Return the text of an uploaded .eml file, enforcing the size limit."""
    data = uploaded_file.getvalue()
    if len(data) > MAX_INPUT_BYTES:
        raise EmailParseError("The uploaded file is larger than the 1 MB limit.")
    return data.decode("utf-8", errors="replace")


def defang(text: str) -> str:
    """Make URLs unclickable (http -> hxxp), a common practice when sharing suspicious links."""
    return (text.replace("http://", "hxxp://")
                .replace("https://", "hxxps://")
                .replace("www.", "www[.]"))


def show_verdict(result) -> None:
    """Show the verdict banner, score, and ATT&CK techniques."""
    message = f"**{result.verdict} risk** — score {result.score}"
    if result.verdict == "High":
        st.error(message, icon="🚨")
    elif result.verdict == "Medium":
        st.warning(message, icon="⚠️")
    else:
        st.success(message, icon="✅")

    if result.attack_techniques:
        links = [
            f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)"
            for t in result.attack_techniques
        ]
        st.markdown("**MITRE ATT&CK:** " + " · ".join(links))


def show_findings(findings) -> None:
    """List findings grouped by category."""
    st.subheader(f"Findings ({len(findings)})")
    if not findings:
        st.write("No phishing indicators were found.")
        return
    for category, label in CATEGORY_LABELS.items():
        group = [f for f in findings if f.category == category]
        if not group:
            continue
        st.markdown(f"**{label}**")
        for f in group:
            st.markdown(f"{SEVERITY_ICONS.get(f.severity, '')} **{f.severity.title()}:** {f.description}")
            if f.evidence:
                # Inline code formatting keeps suspicious URLs and addresses from becoming clickable links.
                st.caption(f"`{f.evidence.replace('`', '')}`")


def show_email_details(email) -> None:
    """Show the parsed fields so the user can see what the checks looked at."""
    with st.expander("Parsed email details"):
        st.markdown(f"**From:** {email.display_name} `{email.from_address}`")
        st.markdown(f"**Reply-To:** `{email.reply_to or 'none'}`")
        st.markdown(f"**Return-Path:** `{email.return_path or 'none'}`")
        st.markdown(f"**Subject:** {email.subject}")
        st.markdown(f"**Authentication results:** `{email.auth_results or 'none'}`")
        if email.links:
            st.markdown("**Links:**")
            for link in email.links:
                st.markdown(f"- Shows `{link.display_text or '(no text)'}` → goes to `{link.url}`")
        if email.attachments:
            st.markdown("**Attachments:** " + ", ".join(f"`{a.filename}`" for a in email.attachments))


# ---------- Page layout ----------

st.title("🛡️ AI Phishing Email Analyzer")
st.caption(
    "Paste the raw source of an email or upload an .eml file. The scanner checks headers, links, "
    "content, and attachments, then uses AI to explain the results."
)

st.write("Try a sample:")
sample_cols = st.columns(len(SAMPLE_FILES))
for col, (label, filename) in zip(sample_cols, SAMPLE_FILES.items()):
    col.button(label, on_click=load_sample, args=(filename,), use_container_width=True)

st.text_area("Raw email source", key="raw_email", height=250,
             placeholder="In Gmail use 'Show original'; in Outlook use 'View message source'.")
uploaded = st.file_uploader("Or upload an .eml file", type=["eml"])
use_ai = st.toggle("Include AI explanation", value=True)

if st.button("Analyze", type="primary"):
    try:
        raw = read_upload(uploaded) if uploaded else st.session_state.raw_email
        with st.spinner("Analyzing..."):
            email, result = analyze_email(raw, use_ai=use_ai)
    except EmailParseError as exc:
        st.error(str(exc))
        st.stop()

    show_verdict(result)

    left, right = st.columns([3, 2])
    with left:
        show_findings(result.findings)
    with right:
        if use_ai:
            st.subheader("AI explanation" if result.ai_available else "Summary")
            st.markdown(defang(result.ai_explanation))

    show_email_details(email)

st.divider()
st.caption("Rules decide the verdict. AI only explains it. Do not paste emails containing sensitive personal data.")
