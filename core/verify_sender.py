import dns.resolver

def verify_sender_spf(domain):
    """
    Reliable SPF lookup with:
    - Multi-string TXT support
    - Subdomain fallback
    - Clean error handling
    """

    def lookup(d):
        try:
            answers = dns.resolver.resolve(d, "TXT")
            for rdata in answers:
                # Join multi-part TXT records properly
                record = "".join(part.decode("utf-8") for part in rdata.strings)
                if record.lower().startswith("v=spf1"):
                    return record
            return None

        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.NXDOMAIN:
            return "Domain does not exist."
        except Exception as e:
            return f"Error checking SPF: {str(e)}"

   
    result = lookup(domain)

    
    if not result and domain.count(".") >= 2:
        parent_domain = ".".join(domain.split(".")[-2:])
        result = lookup(parent_domain)
        if result:
            return result

    return result if result else "No SPF record found."


def get_spf_structured(domain):
    """
    Structured SPF analysis for dashboard mode.
    Returns dictionary format.
    """
    result = verify_sender_spf(domain)

    analysis = {
        "domain": domain,
        "raw_record": result,
        "status": None,
        "risk_points": 0
    }

    if not result:
        analysis["status"] = "error"
        analysis["risk_points"] = 1

    elif result.lower().startswith("v=spf1"):
        analysis["status"] = "pass"
        analysis["risk_points"] = 0

    elif "no spf" in result.lower():
        analysis["status"] = "fail"
        analysis["risk_points"] = 1

    elif "error" in result.lower() or "does not exist" in result.lower():
        analysis["status"] = "error"
        analysis["risk_points"] = 1

    else:
        analysis["status"] = "unknown"
        analysis["risk_points"] = 1

    return analysis
