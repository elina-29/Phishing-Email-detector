# import dns.resolver

# def check_spf(domain):
#     try:
#         answers = dns.resolver.resolve(domain, 'TXT')
#         for rdata in answers:
#             for txt_string in rdata.strings:
#                 decoded = txt_string.decode('utf-8')
#                 if decoded.startswith('v=spf1'):
#                     return decoded
#         return "No SPF record found."
#     except Exception as e:
#         return f"Error: {e}"

# if __name__ == "__main__":
#     domain = "paypal.com"  # You can change this to test other domains
#     spf_record = check_spf(domain)
#     print(f"SPF record for {domain}: {spf_record}")

# core/verify_sender.py

# import dns.resolver

# def check_spf(domain):
#     try:
#         resolver = dns.resolver.Resolver()
#         resolver.nameservers = ['8.8.8.8', '8.8.4.4']
#         resolver.lifetime = 10
#         resolver.timeout = 5

#         answers = resolver.resolve(domain, 'TXT')
#         for rdata in answers:
#             for txt_string in rdata.strings:
#                 decoded = txt_string.decode("utf-8")
#                 if decoded.startswith("v=spf1"):
#                     return decoded
#         return "No SPF record found."
#     except Exception as e:
#         return f"Error checking SPF: {e}"
import subprocess

def verify_sender_spf(domain):
    try:
        result = subprocess.run(
            ["nslookup", "-type=txt", domain],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout

        if "v=spf1" in output.lower():
            # Find and return the SPF record line
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

    


