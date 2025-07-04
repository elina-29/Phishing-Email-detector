def generate_verdict(spf_record, url_results, attachments, whois_info=None):
    verdict_messages = []
    risk_score = 0
    whois_info = whois_info or {}

    #  SPF Check
    if not spf_record or "spf" not in spf_record.lower():
        verdict_messages.append("⚠️ SPF record missing or invalid.")
        risk_score += 1

    #  URL Check
    SAFE_DOMAINS = ["github.com", "google.com", "microsoft.com"]

    for url, result in url_results.items():
        try:
            domain = url.split("/")[2].lower() if "://" in url else url.lower()
        except IndexError:
            domain = url.lower()

        #  Whitelisted domains
        if any(safe in domain for safe in SAFE_DOMAINS):
            verdict_messages.append(f"✅ Whitelisted domain: {url}")
            continue

        #  Handle VirusTotal result
        if not isinstance(result, dict):
            verdict_messages.append(f"⚠️ No VirusTotal data available for {url}")
            risk_score += 1
        else:
            malicious = result.get("malicious", 0)
            suspicious = result.get("suspicious", 0)

            if malicious > 0:
                verdict_messages.append(f"🚨 Malicious URL detected ({malicious} engines): {url}")
                risk_score += 2
            elif suspicious > 0:
                verdict_messages.append(f"⚠️ Suspicious URL detected ({suspicious} engines): {url}")
                risk_score += 1
            else:
                verdict_messages.append(f"✅ Clean URL: {url}")

        #  WHOIS check (if passed in)
        whois_text = whois_info.get(url, "")
        if "no match" in whois_text.lower():
            verdict_messages.append(f"⚠️ WHOIS: Domain not registered - {domain}")
            risk_score += 1
        elif "error" in whois_text.lower():
            verdict_messages.append(f"⚠️ WHOIS: Error fetching domain info for {domain}")
            risk_score += 1

    #  Attachment Check
    risky_exts = ['.exe', '.js', '.scr', '.vbs', '.bat']
    for att in attachments:
        filename = att.get('filename', '')
        if filename and any(filename.lower().endswith(ext) for ext in risky_exts):
            verdict_messages.append(f"🚫 Suspicious attachment: {filename}")
            risk_score += 2

    #  Final Verdict Summary
    if risk_score >= 4:
        final_verdict = "🚨 Verdict: Highly Suspicious – Likely a phishing email."
    elif risk_score >= 2:
        final_verdict = "⚠️ Verdict: Moderately Suspicious – Caution advised."
    else:
        final_verdict = "✅ Verdict: Looks Safe – No major red flags detected."

    return "\n".join(verdict_messages + [final_verdict])
