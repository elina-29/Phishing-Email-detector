from core.verify_sender import get_spf_structured
from core.url_reputation import analyze_url_structured
from core.verdict import generate_structured_verdict
from core.email_parser import extract_urls

def extract_domain_from_sender(sender):
    """
    Robust domain extraction for both parsed and pasted emails.
    """

    if not sender:
        return None

    # Case 1: Parsed email format [('Name', 'email@domain.com')]
    if isinstance(sender, list):
        if sender and len(sender[0]) == 2:
            email_addr = sender[0][1]
        else:
            return None

    # Case 2: Plain string input
    elif isinstance(sender, str):
        email_addr = sender.strip()

        # If format like: "John Doe <john@example.com>"
        if "<" in email_addr and ">" in email_addr:
            email_addr = email_addr.split("<")[-1].replace(">", "").strip()

    else:
        return None

    if "@" in email_addr:
        return email_addr.split("@")[-1].strip()

    return None 


import re

def analyze_content_risk(text):
    """
    Tier-2 behavioral phishing detection engine.
    Uses pattern detection + escalation logic.
    """

    if not text:
        return {
            "matched_indicators": [],
            "risk_points": 0
        }

    text = text.lower()

    total_points = 0
    matched = []

    # ----------------------------
    # 1️⃣ Urgency Patterns
    # ----------------------------
    urgency_patterns = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bact now\b",
        r"\blimited time\b",
        r"\bdeadline\b",
        r"\bexpires (today|soon)\b"
    ]

    urgency_detected = False

    for pattern in urgency_patterns:
        if re.search(pattern, text):
            urgency_detected = True
            total_points += 1
            matched.append({"phrase": "Urgency indicator", "weight": 1})
            break  # count once

    # ----------------------------
    # 2️⃣ Action Trigger Patterns
    # ----------------------------
    action_patterns = [
        r"click\s+(on\s+)?(this|the)?\s*(link)?",
        r"follow\s+(this|the)?\s*link",
        r"access\s+(the)?\s*link",
        r"tap\s+(here|link)",
        r"open\s+(the)?\s*link"
    ]

    action_detected = False

    for pattern in action_patterns:
        if re.search(pattern, text):
            action_detected = True
            total_points += 2
            matched.append({"phrase": "Action trigger (click/link)", "weight": 2})
            break

    # ----------------------------
    # 3️⃣ Credential Harvesting Patterns
    # ----------------------------
    credential_patterns = [
        r"verify\s+(your\s+)?account",
        r"confirm\s+(your\s+)?identity",
        r"reset\s+(your\s+)?password",
        r"login\s+now",
        r"validate\s+credentials",
        r"re-?authenticate"
    ]

    credential_detected = False

    for pattern in credential_patterns:
        if re.search(pattern, text):
            credential_detected = True
            total_points += 3
            matched.append({"phrase": "Credential harvesting intent", "weight": 3})
            break

    # ----------------------------
    # 4️⃣ Fear-Based Patterns
    # ----------------------------
    fear_patterns = [
        r"account\s+suspended",
        r"account\s+locked",
        r"unauthorized\s+access",
        r"security\s+breach",
        r"legal\s+action",
        r"compliance\s+violation"
    ]

    fear_detected = False

    for pattern in fear_patterns:
        if re.search(pattern, text):
            fear_detected = True
            total_points += 3
            matched.append({"phrase": "Fear-based manipulation", "weight": 3})
            break

    # ----------------------------
    # 5️⃣ Escalation Bonus Logic
    # ----------------------------

    # Urgency + Action = classic phishing
    if urgency_detected and action_detected:
        total_points += 2
        matched.append({"phrase": "Escalation: Urgency + Action", "weight": 2})

    # Action + Credential = strong phishing signal
    if action_detected and credential_detected:
        total_points += 2
        matched.append({"phrase": "Escalation: Action + Credential", "weight": 2})

    # Fear + Credential = high-risk psychological attack
    if fear_detected and credential_detected:
        total_points += 2
        matched.append({"phrase": "Escalation: Fear + Credential", "weight": 2})

    return {
        "matched_indicators": matched,
        "risk_points": total_points
    }


def analyze_email_input(subject, sender, body, attachments=None):
    """
    Unified analysis pipeline.
    Works for both upload mode and paste mode.
    """

    attachments = attachments or []

    # -------------------------
    # Extract Sender Domain
    # -------------------------
    domain = extract_domain_from_sender(sender)

    if domain:
        spf_analysis = get_spf_structured(domain)
    else:
        spf_analysis = {
            "domain": None,
            "status": "error",
            "raw_record": "Could not extract domain",
            "risk_points": 1
        }

    # -------------------------
    # Extract URLs
    # -------------------------
    urls = extract_urls(body)

    url_analysis_list = []

    for url in urls:
        url_data = analyze_url_structured(url)
        url_analysis_list.append(url_data)

    # -------------------------
    # Generate Final Verdict
    # -------------------------
    # -------------------------
    # Content Risk Analysis
    # -------------------------
    combined_text = f"{subject} {body}"
    content_analysis = analyze_content_risk(combined_text)  

    final_result = generate_structured_verdict(
    spf_analysis,
    url_analysis_list,
    attachments,
    content_analysis
)

    # Add metadata
    final_result["email_meta"] = {
        "subject": subject,
        "sender": sender,
        "url_count": len(urls)
    }

    return final_result