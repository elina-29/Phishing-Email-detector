import subprocess

def verify_sender_spf(domain):
    try:
        result = subprocess.run(
            ["nslookup", "-type=txt", domain],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout

        if "v=spf1" in output.lower():
            
            for line in output.splitlines():
                if "v=spf1" in line.lower():
                    return line.strip()
            return "SPF record found but couldn't parse."
        else:
            return "No SPF record found."

    except subprocess.TimeoutExpired:
        return "SPF lookup timed out."
    except Exception as e:
        return f"Error checking SPF using nslookup: {e}"

    


