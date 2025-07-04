# Phishing-Email-detector


This is a Streamlit-based tool that scans `.eml` email files to detect phishing attempts using:

- ✅ Sender verification (SPF records)
- ✅ URL analysis (VirusTotal, WHOIS)
- ✅ Attachment scanning
- ✅ Intelligent final verdict scoring

---

##  Features

- Upload `.eml` email files via web interface
- Detect malicious or suspicious links using VirusTotal API
- Identify fake sender domains with SPF record checks
- Flag risky attachments like `.exe`, `.js`, etc.
- Display a detailed final verdict with risk scores

---


##  Installation

### 1. Clone the repository

git clone https://github.com/your-username/phishing-email-detector.git
cd phishing-email-detector

### 2. Create and Activate Virtual Environment (Optional but Recommended)

python -m venv venv
source venv/bin/activate     # On Linux/macOS
venv\Scripts\activate        # On Windows

### 3. Install Dependencies

pip install -r requirements.txt

### 4. Set Up Environment Variables

Create a .env file in the project root and add your VirusTotal API key:
VT_API_KEY=your_virustotal_api_key_here


### Run the App:

streamlit run app.py

Open the browser at: http://localhost:8501

# Sample Test Email
You can test using sample .eml files (create your own or sanitize real ones). Keep them in a folder like sample_emails/.

# Disclaimer
This project is for educational purposes only. Always handle real user data and suspicious files carefully and in secure environments.


