#  Phishing Email Detector
A multi-vector phishing detection platform that analyzes emails using authentication validation, URL threat intelligence, behavioural NLP heuristics, and attachment risk scoring — producing an explainable composite threat verdict.

---

## Overview

This project simulates an enterprise-style email security triage workflow by analyzing emails across multiple attack vectors:

- Sender authentication validation (SPF)
- URL reputation scoring (VirusTotal + threat intelligence logic)
- Attachment risk heuristics
- Behavioural & social engineering NLP indicators
- Composite risk scoring (0–10 scale)
- Explainable attack vector breakdown
- Exportable forensic reports (Markdown + JSON)

Designed with a SOC-style dashboard UI for interactive threat analysis.

---

##  Detection Vectors

| Vector | Description |
|--------|------------|
| Sender Authentication | SPF record validation against DNS |
| URL Reputation | Flagging malicious/suspicious links via threat intelligence |
| Attachment Analysis | Risky file extension & payload heuristics |
| Behavioural NLP | Urgency, manipulation & credential-harvesting pattern detection |
| Composite Scoring | Weighted risk aggregation engine (0–10 scale) |

---

##  Key Features

- Manual email input (`.eml` files)
- Animated multi-stage scan workflow
- Real-time risk gauge visualization (Plotly)
- Attack vector score breakdown
- Session-based scan history
- Downloadable forensic reports (.md / .json)
- Structured verdict categories:
  - Highly Suspicious
  - Moderately Suspicious
  - Negligible Risk

---

##  Tech Stack

- Python
- Streamlit
- Plotly
- DNS (SPF lookup)
- VirusTotal API (URL scanning)
- WHOIS analysis
- Custom heuristic NLP scoring

---

## ⚙️ Installation

```bash
git clone https://github.com/your-username/phishing-email-detector.git
cd phishing-email-detector
pip install -r requirements.txt
streamlit run app.py
