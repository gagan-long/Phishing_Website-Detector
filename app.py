import streamlit as st
from urllib.parse import urlparse, urljoin
import re
import whois
import ssl
import requests
import socket
from bs4 import BeautifulSoup
import json
from concurrent.futures import ThreadPoolExecutor
import os
from dotenv import load_dotenv

# --- Load VirusTotal API Key Securely ---
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY", "")

# --- VirusTotal Threat Intelligence Function ---
def check_virustotal_url(url, api_key):
    if not api_key:
        return {"error": "No VirusTotal API key provided."}
    vt_url = "https://www.virustotal.com/api/v3/urls"
    try:
        resp = requests.post(vt_url, headers={"x-apikey": api_key}, data={"url": url})
        if resp.status_code not in (200, 201):
            return {"error": f"VirusTotal API error: {resp.status_code}"}
        scan_id = resp.json()["data"]["id"]
        report_url = f"{vt_url}/{scan_id}"
        report = requests.get(report_url, headers={"x-apikey": api_key})
        if report.status_code != 200:
            return {"error": f"VirusTotal API error: {report.status_code}"}
        data = report.json()["data"]["attributes"]
        stats = data["last_analysis_stats"]
        verdict = "malicious" if stats.get("malicious", 0) > 0 else "suspicious" if stats.get("suspicious", 0) > 0 else "clean"
        return {
            "verdict": verdict,
            "stats": stats,
            "scan_date": data.get("last_analysis_date"),
            "permalink": f"https://www.virustotal.com/gui/url/{scan_id}"
        }
    except Exception as e:
        return {"error": str(e)}

# ... (rest of your code, unchanged, until main) ...

def main():
    st.markdown("<h1 style='color:#ff4b4b;'>🛡️ Phishing Website Detector, Port & Text Scanner</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:#31333f;font-size:1.1rem;'>Analyze a website, suspicious text, or message for phishing risk!</p>", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔗 Website/Domain Analysis", "✉️ Text/Message Analysis"])

    # --- Website/Domain Tab ---
    with tab1:
        url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
        port_scan_enabled = st.checkbox("Perform Port Scan (for open ports)", value=False)
        port_range = (1, 1024)
        if port_scan_enabled:
            colp1, colp2 = st.columns(2)
            with colp1:
                port_start = st.number_input("Port range start", min_value=1, max_value=65535, value=1)
            with colp2:
                port_end = st.number_input("Port range end", min_value=1, max_value=65535, value=1024)
            port_range = (int(port_start), int(port_end))
        if st.button("Analyze", key="analyze_url"):
            if url:
                with st.spinner("Analyzing website..."):
                    details = extract_details(url)
                    risk_score = calculate_risk_score(details)
                    if risk_score > 50:
                        prediction = "🔴 Highly Likely Phishing"
                        pred_color = "#dc3545"
                    elif risk_score > 30:
                        prediction = "🟡 Likely Phishing"
                        pred_color = "#ffc107"
                    else:
                        prediction = "🟢 Potentially Safe"
                        pred_color = "#28a745"
                    st.subheader("Analysis Results")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"<div class='metric-container'><h3>Risk Score</h3><p style='font-size: 2rem; font-weight: bold;'>{risk_score}/100</p></div>", unsafe_allow_html=True)
                    with col2:
                        st.markdown(f"<div class='metric-container'><h3>Prediction</h3><p style='font-size: 2rem; font-weight: bold; color: {pred_color};'>{prediction}</p></div>", unsafe_allow_html=True)

                    # --- VirusTotal Threat Intelligence ---
                    st.subheader("VirusTotal Threat Intelligence")
                    if VT_API_KEY:
                        vt_result = check_virustotal_url(url, VT_API_KEY)
                        if vt_result.get("error"):
                            st.info(f"VirusTotal: {vt_result['error']}")
                        else:
                            verdict = vt_result["verdict"]
                            stats = vt_result["stats"]
                            vt_color = "#dc3545" if verdict == "malicious" else "#ffc107" if verdict == "suspicious" else "#28a745"
                            st.markdown(
                                f"<div class='metric-container'><h3>VirusTotal Verdict</h3>"
                                f"<p style='font-size: 1.5rem; font-weight: bold; color: {vt_color};'>{verdict.title()}</p></div>",
                                unsafe_allow_html=True)
                            st.write(f"**Malicious:** {stats.get('malicious',0)} | **Suspicious:** {stats.get('suspicious',0)} | "
                                     f"**Harmless:** {stats.get('harmless',0)} | **Undetected:** {stats.get('undetected',0)}")
                            st.markdown(f"[View full report on VirusTotal]({vt_result['permalink']})")
                    else:
                        st.info("VirusTotal threat intelligence available if you set your API key in the .env file.")

                    st.subheader("Technical Details")
                    st.markdown("<div class='details-list'><ul>", unsafe_allow_html=True)
                    for key, value in details.items():
                        if key not in ['found_paths', 'lookalike_brands']:
                            st.markdown(f"<li><strong>{key}:</strong> {value}</li>", unsafe_allow_html=True)
                    st.markdown("</ul></div>", unsafe_allow_html=True)

                    st.subheader("Typosquatting & Lookalike Domain Check")
                    if details.get('lookalike_brands'):
                        st.warning(f"This domain is a lookalike or typo of: {', '.join(details['lookalike_brands'])}")
                    else:
                        st.success("No lookalike or typosquatting detected for popular brands.")

                    st.subheader("Discovered Paths")
                    if details.get('found_paths'):
                        st.markdown("<div class='paths-list'><ul>", unsafe_allow_html=True)
                        for path in details['found_paths']:
                            st.markdown(f"<li><code>{url.rstrip('/')}{path}</code></li>", unsafe_allow_html=True)
                        st.markdown("</ul></div>", unsafe_allow_html=True)
                    else:
                        st.warning("No common paths discovered")
                    # --- Port Scan Section ---
                    if port_scan_enabled:
                        st.subheader(f"Port Scan Results ({port_range[0]}–{port_range[1]})")
                        parsed_url = urlparse(url)
                        domain = parsed_url.netloc
                        with st.spinner("Scanning ports... (this may take a while)"):
                            open_ports, closed_ports, error = port_scan(domain, port_range)
                            if error:
                                st.error(error)
                            else:
                                st.markdown("<div class='ports-list'><ul>", unsafe_allow_html=True)
                                if open_ports:
                                    st.markdown("<li><strong>Open Ports:</strong></li>", unsafe_allow_html=True)
                                    for port in open_ports:
                                        st.markdown(f"<li style='margin-left:20px;'><strong>Port {port}:</strong> <span style='color:green;'>OPEN</span></li>", unsafe_allow_html=True)
                                if closed_ports:
                                    st.markdown("<li><strong>Closed Ports:</strong></li>", unsafe_allow_html=True)
                                    for port in closed_ports[:20]:
                                        st.markdown(f"<li style='margin-left:20px;'><strong>Port {port}:</strong> <span style='color:red;'>CLOSED</span></li>", unsafe_allow_html=True)
                                    if len(closed_ports) > 20:
                                        st.markdown(f"<li style='margin-left:20px;'><em>...and {len(closed_ports)-20} more closed ports</em></li>", unsafe_allow_html=True)
                                st.markdown("</ul></div>", unsafe_allow_html=True)
                    st.subheader("Feedback")
                    feedback = st.radio("Was this prediction accurate?", ("Yes", "No"), horizontal=True)
                    comments = st.text_area("Additional Comments")
                    if st.button("Submit Feedback", key="feedback_url"):
                        st.success("Thank you for your feedback! (Submitted: {})".format(feedback))
                        if feedback == "No":
                            parsed_url = urlparse(url)
                            domain = parsed_url.netloc
                            add_to_blacklist(domain)
            else:
                st.warning("Please enter a valid URL")

    # --- Text/Message Tab ---
    with tab2:
        st.write("Paste any suspicious email, SMS, or message below to check for phishing risk.")
        text = st.text_area("Paste your message or email here:", height=180)
        if st.button("Analyze Text", key="analyze_text"):
            if text.strip():
                result = analyze_text(text)
                st.subheader("Text Analysis Results")
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"<div class='metric-container'><h3>Risk Score</h3><p style='font-size: 2rem; font-weight: bold;'>{result['risk_score']}/100</p></div>", unsafe_allow_html=True)
                with col2:
                    color = "#dc3545" if "Highly" in result['risk_label'] else "#ffc107" if "Likely" in result['risk_label'] else "#28a745"
                    st.markdown(f"<div class='metric-container'><h3>Prediction</h3><p style='font-size: 2rem; font-weight: bold; color: {color};'>{result['risk_label']}</p></div>", unsafe_allow_html=True)
                st.subheader("Detected Issues")
                if result['keywords']:
                    st.warning(f"Phishing keywords detected: {', '.join(result['keywords'])}")
                else:
                    st.success("No phishing keywords detected.")
                if result['links']:
                    st.warning(f"Suspicious links found: {', '.join(result['links'])}")
                else:
                    st.success("No suspicious links found.")
                if result['brands']:
                    st.warning(f"Brand names detected: {', '.join(result['brands'])}")
                else:
                    st.info("No popular brand names detected.")
            else:
                st.info("Paste some text to analyze.")

if __name__ == "__main__":
    main()
