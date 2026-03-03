import requests
import os
from dotenv import load_dotenv
import base64
import streamlit as st

load_dotenv()

VT_URL = "https://www.virustotal.com/api/v3/urls"

API_KEY = os.getenv("VT_API_KEY") or st.secrets.get("VT_API_KEY")

if not API_KEY:
    raise ValueError("VirusTotal API key not configured.")


def check_url_virustotal(url):
    try:
        headers = {
            "x-apikey": API_KEY
        }

        # Encode the URL to base64 format as required by VT API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # Submit the URL for scanning (optional, helpful for new URLs)
        _ = requests.post(VT_URL, headers=headers, data={"url": url})

        # Retrieve analysis results
        analysis_url = f"{VT_URL}/{url_id}"
        result = requests.get(analysis_url, headers=headers)

        if result.status_code != 200:
            return f"❌ Error fetching analysis: {result.status_code}", None

        analysis = result.json()
        stats = analysis["data"]["attributes"]["last_analysis_stats"]
        malicious_count = stats.get("malicious", 0)

        if malicious_count >= 3:
            return "🚨 Detected as Malicious by multiple engines!", stats
        elif 1 <= malicious_count < 3:
            return "⚠️ Detected as Suspicious (1–2 engines flagged it)", stats
        else:
            return "✅ Clean (No detections)", stats

    except Exception as e:
        return f"❌ Exception occurred: {e}", None


