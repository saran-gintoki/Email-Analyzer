# Version 2.4.1 - VirusTotal URL Fully Fixed

from flask import Flask, render_template, request
import email
import hashlib
import os
import re
import base64
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Screenshot API token
SCREENSHOT_API_TOKEN = '5JS7Y6H-2BYMEAZ-GAFH08V-NJYHADX'

# VirusTotal and URLScan API Keys
VT_API_KEY = '4b8869ce2044c2e55f213bfddcd2f5564817be5a410b37bf715a7db44688344d'
URLSCAN_API_KEY = '01967272-54c7-739d-a000-ac8a9de53089'

def unwrap_url(url):
    if 'urldefense.com' in url:
        match = re.search(r'__(https?://[^_]*)', url)
        if match:
            true_url = match.group(1)
            return unquote(true_url)
    return url

def vt_url_encode(url):
    url_bytes = url.encode('utf-8')
    b64_bytes = base64.urlsafe_b64encode(url_bytes)
    b64_str = b64_bytes.decode('utf-8')
    return b64_str.rstrip("=")  # Remove padding

@app.route('/')
def upload_page():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    uploaded_file = request.files['file']
    if uploaded_file.filename.endswith('.eml'):
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)

        with open(filepath, 'rb') as f:
            msg = email.message_from_binary_file(f)

        sender = msg.get('From')
        subject = msg.get('Subject')
        sender_ip = msg.get('X-Originating-IP') or "10.90.40.166"
        reverse_dns_lookup = f"https://whois.domaintools.com/{sender_ip}"
        reply_to = msg.get('Reply-To')
        date = msg.get('Date')
        recipient = msg.get('To')

        attachments = []
        urls = []

        body_text = ""
        body_html = ""

        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain' and not part.get_filename():
                body_text += part.get_payload(decode=True).decode(errors='ignore')
            if content_type == 'text/html' and not part.get_filename():
                body_html += part.get_payload(decode=True).decode(errors='ignore')
            if part.get_filename():
                filename = part.get_filename()
                data = part.get_payload(decode=True)
                sha256_hash = hashlib.sha256(data).hexdigest()
                attachments.append({'name': filename, 'sha256': sha256_hash})

        raw_urls = []
        if body_html:
            soup = BeautifulSoup(body_html, 'html.parser')
            for link in soup.find_all('a', href=True):
                raw_urls.append(link['href'])

        if body_text:
            found = re.findall(r'(https?://\S+)', body_text)
            raw_urls.extend(found)

        seen = set()
        for url in raw_urls:
            clean_url = unwrap_url(url)
            if clean_url not in seen:
                seen.add(clean_url)
                parsed = urlparse(clean_url)
                domain = parsed.netloc

                screenshot_url = (f"https://shot.screenshotapi.net/screenshot"
                                  f"?token={SCREENSHOT_API_TOKEN}&url={clean_url}"
                                  f"&output=image&file_type=png&wait_for_event=load")
                vt_encoded = vt_url_encode(clean_url)
                virustotal_link = f"https://www.virustotal.com/gui/url/{vt_encoded}/detection"
                urlscan_link = f"https://urlscan.io/domain/{domain}"

                urls.append({
                    'url': clean_url,
                    'domain': domain,
                    'screenshot': screenshot_url,
                    'virustotal': virustotal_link,
                    'urlscan': urlscan_link
                })

        parsed_data = {
            'sender': sender,
            'subject': subject,
            'sender_ip': sender_ip,
            'reverse_dns': reverse_dns_lookup,
            'reply_to': reply_to,
            'date': date,
            'recipient': recipient,
            'attachments': attachments,
            'urls': urls,
            'full_email': body_text or body_html
        }

        return render_template('result.html', **parsed_data)

if __name__ == '__main__':
    app.run(debug=True)
