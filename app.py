import streamlit as st
from core.email_parser import extract_email_content, extract_urls, extract_attachments
from core.verify_sender import verify_sender_spf
from core.url_checker import get_domain_info
from core.url_reputation import check_url_virustotal
from core.verdict import generate_verdict
import tempfile

st.set_page_config(page_title="Phishing Email Detector", page_icon="📧")
st.title("📧 Phishing Email Detector")
st.markdown("""
Upload a `.eml` file and this tool will analyze:
- Sender authenticity (SPF)
- Links and domain reputation (VirusTotal, WHOIS)
- Suspicious attachments
- A final verdict based on multiple factors
""")

uploaded_file = st.file_uploader("Choose a .eml file to scan", type=["eml"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(uploaded_file.read())
        email_path = tmp.name

    st.success("✅ File uploaded and ready for analysis")

    # Step 1: Parse email
    subject, sender, body, msg = extract_email_content(email_path)
    attachments = extract_attachments(msg)
    urls = extract_urls(body)

    st.header("📄 Email Summary")
    st.write(f"**Subject:** {subject}")
    st.write(f"**From:** {sender}")
    st.text_area("📃 Body Content:", body, height=200)

    # Step 2: SPF Check
    st.header("🛡️ Sender Verification")
    spf_record = "Not available"
    if sender and sender[0][1]:
        domain = sender[0][1].split('@')[-1]
        spf_record = verify_sender_spf(domain)
        st.write(f"**SPF Record for `{domain}`:** `{spf_record}`")
    else:
        st.warning("Could not extract sender domain.")

    # Step 3: URL Analysis
    st.header("🔗 URLs in Email")
    url_results = {}
    whois_results = {}

    if urls:
        for url in urls:
            st.markdown(f"**{url}**")
        
            # WHOIS + Domain Info
            domain_info = get_domain_info(url)
            whois_results[url] = domain_info.get("error", "")  # Only the WHOIS error (if any)

            # VirusTotal Reputation
            vt_status, vt_stats = check_url_virustotal(url)
            url_results[url] = vt_stats if isinstance(vt_stats, dict) else {}

            st.write("🌐 VirusTotal Status:", vt_status)
            st.write("🔍 Domain Info:", domain_info)


    # Step 4: Attachment Info
    st.header("📁 Attachments")
    if attachments:
        for att in attachments:
            st.write(f"- {att['filename']} ({att['content_type']}, {att['size']} bytes)")
    else:
        st.write("No attachments found.")

    # Step 5: Verdict
    st.header("🧠 Final Verdict")
    verdict = generate_verdict(spf_record, url_results, attachments, whois_info=whois_results)

    st.markdown(f"### {verdict}")

