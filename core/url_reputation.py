# import requests
# import os
# from dotenv import load_dotenv

# load_dotenv()  # Load the VirusTotal API key from the .env file



# API_KEY = os.getenv("VT_API_KEY")
# # print(f"Loaded VirusTotal API Key: {API_KEY}")

# VT_URL = "https://www.virustotal.com/api/v3/urls"

# def check_url_virustotal(url):
#     try:
#         headers = {
#             "x-apikey": API_KEY
#         }

#         # Step 1: Submit URL for analysis
#         response = requests.post(VT_URL, headers=headers, data={"url": url})
#         if response.status_code != 200:
#             return f"❌ Error submitting URL: {response.status_code}", None

#         analysis_url = f"{VT_URL}/{response.json()['data']['id']}"

#         # Step 2: Get analysis results
#         result = requests.get(analysis_url, headers=headers)
#         if result.status_code != 200:
#             return f"❌ Error fetching analysis: {result.status_code}", None

#         analysis = result.json()
#         stats = analysis["data"]["attributes"]["last_analysis_stats"]

#         total_engines = sum(stats.values())
#         malicious_engines = stats.get("malicious", 0)

#         if malicious_engines > 0:
#             return "⚠️ Detected as Malicious by VirusTotal!", stats
#         else:
#             return "✅ No malicious activity detected by VirusTotal.", stats

#     except Exception as e:
#         return f"❌ Exception occurred: {e}", None





import requests
import os
from dotenv import load_dotenv
import base64

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls"

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

        # 3-Tier Verdict Logic
        if malicious_count >= 3:
            return "🚨 Detected as Malicious by multiple engines!", stats
        elif 1 <= malicious_count < 3:
            return "⚠️ Detected as Suspicious (1–2 engines flagged it)", stats
        else:
            return "✅ Clean (No detections)", stats

    except Exception as e:
        return f"❌ Exception occurred: {e}", None
