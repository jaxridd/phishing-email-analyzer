"""Streamlit interface for the AI Phishing Email Analyzer."""

import streamlit as st

st.set_page_config(page_title="Phishing Email Analyzer", page_icon="🛡️", layout="wide")

st.title("AI Phishing Email Analyzer")
st.caption("Paste the raw source of an email or upload an .eml file to check it for phishing indicators.")

raw_email = st.text_area("Raw email source", height=250)
uploaded = st.file_uploader("Or upload an .eml file", type=["eml"])

if st.button("Analyze"):
    st.info("Analysis is under construction.")
