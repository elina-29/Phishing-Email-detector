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

##  Installation

```bash
git clone https://github.com/your-username/phishing-email-detector.git
cd phishing-email-detector
pip install -r requirements.txt
streamlit run app.py

```
---

##  Risk Scoring Model

The engine calculates a composite risk score (0–10) using:

- URL malicious weight  
- Behavioural NLP weight  
- Attachment risk flags  
- SPF authentication status  
- Identity spoofing indicators  

Each detection vector contributes transparently to the final verdict, enabling explainable security analysis.

---

##  Generated Output

The engine produces a structured threat analysis including:

- Executive summary  
- Risk score & confidence level  
- Key detection reasons  
- URL reputation breakdown  
- Behavioural indicator weights  
- Attachment security status  
- Authentication validation results  

Reports can be exported as:

- Markdown (.md)  
- JSON (.json)  

---

##  Security Philosophy

- Multi-vector detection (not keyword-only)  
- Explainable scoring model  
- SOC-oriented UI design  
- Transparent risk attribution  
- Defensive cybersecurity research focus  

---

##  Future Improvements

- DKIM & DMARC validation  
- WHOIS domain age scoring  
- Domain similarity detection (typosquatting analysis)  
- Machine learning classification layer  
- Real-time threat feed automation  

---

## ⚠ Disclaimer

This project is intended for educational and defensive cybersecurity research purposes only. Always analyze suspicious files in controlled and secure environments.
