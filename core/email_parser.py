import email
from email import policy
from email.parser import BytesParser
import re

def extract_email_content(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        subject = msg['subject']
        from_ = email.utils.getaddresses([msg['from']])
        
        # Extract plain text body
        text = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    text += part.get_payload(decode=True).decode(errors='ignore')
        else:
            text = msg.get_payload(decode=True).decode(errors='ignore')

        return subject, from_, text, msg

    except Exception as e:
        print(f"❌ Failed to parse email: {e}")
        return None, None, None, None

def extract_urls(text):
    if not text:
        return []
    url_regex = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_regex, text)

def extract_attachments(msg):
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            content_type = part.get_content_type()
            size = len(part.get_payload(decode=True))
            attachments.append({
                "filename": filename,
                "content_type": content_type,
                "size": size
            })
    return attachments
