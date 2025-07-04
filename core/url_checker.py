import tldextract
import whois
import requests

def get_domain_info(url):
    try:
        domain = tldextract.extract(url).registered_domain
        w = whois.whois(domain)
        return {
            "domain": domain,
            "created_date": str(w.creation_date),
            "updated_date": str(w.updated_date),
            "registrar": w.registrar
        }
    except Exception as e:
        return {"error": str(e)}

def check_virustotal(url, api_key):
    try:
        headers = {"x-apikey": api_key}
        params = {"url": url}
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)

        if response.status_code == 200:
            analysis_url = response.json()["data"]["id"]
            result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_url}", headers=headers)
            return result.json()
        else:
            return {"error": "Failed to query VirusTotal"}
    except Exception as e:
        return {"error": str(e)}

from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv("VT_API_KEY")

def check_url_safety(url):
    domain_info = get_domain_info(url)
    vt_result = check_virustotal(url, api_key)
    return {
        "domain_info": domain_info,
        "virus_total": vt_result
    }
