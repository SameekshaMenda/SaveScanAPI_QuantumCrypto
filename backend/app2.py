# from flask import Flask, request, jsonify, send_file
# from flask_cors import CORS
# from urllib.parse import urlparse
# from datetime import datetime
# import os
# import requests
# import ssl
# import socket
# import pdfkit
# from jinja2 import Template
# from scanner.scanner import advanced_scan

# app = Flask(__name__)
# CORS(app)

# REPORT_PATH = "static/report.pdf"

# # Security Check Functions
# def check_https(url, findings):
#     if url.startswith('https://'):
#         findings.append("✔ API is using HTTPS. [OWASP API2:2023 - Broken User Authentication]")
#     else:
#         findings.append("❌ API is NOT using HTTPS! (Risk of data interception) [OWASP API2:2023]")

# def check_ssl_tls(hostname, findings):
#     context = ssl.create_default_context()
#     try:
#         with socket.create_connection((hostname, 443), timeout=10) as sock:
#             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                 ssl_version = ssock.version()
#                 cipher = ssock.cipher()
#                 cert = ssock.getpeercert()

#                 findings.append(f"✔ Secure SSL/TLS Version: {ssl_version}" if ssl_version in ['TLSv1.2', 'TLSv1.3']
#                                 else f"❌ Weak SSL/TLS Version Detected: {ssl_version} [OWASP API7:2023]")

#                 findings.append(f"✔ Cipher Used: {cipher[0]} ({cipher[1]} bits)")
#                 if cipher[1] < 128:
#                     findings.append("❌ Weak Cipher Strength (<128 bits)! [OWASP API7:2023]")

#                 expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
#                 findings.append(f"✔ SSL Certificate is valid until {expiry}" if expiry > datetime.utcnow()
#                                 else "❌ SSL Certificate has expired!")

#     except Exception as e:
#         findings.append(f"⚠ SSL/TLS Check Failed: {e}")

# def check_security_headers(url, findings):
#     try:
#         response = requests.get(url, timeout=10)
#         headers = response.headers
#         important_headers = {
#             "Strict-Transport-Security": "Protects against protocol downgrade attacks [OWASP API7]",
#             "Content-Security-Policy": "Prevents XSS attacks [OWASP API8]",
#             "X-Content-Type-Options": "Prevents MIME-sniffing [OWASP API8]",
#             "X-Frame-Options": "Protects against clickjacking [OWASP API8]",
#             "Referrer-Policy": "Controls referer info [OWASP API7]",
#             "Permissions-Policy": "Restricts powerful features [OWASP API8]",
#             "Cross-Origin-Embedder-Policy": "Prevents cross-origin issues [OWASP API8]",
#             "Cross-Origin-Opener-Policy": "Isolates browsing context [OWASP API8]",
#             "Cross-Origin-Resource-Policy": "Prevents cross-origin sharing [OWASP API8]",
#             "Expect-CT": "Certificate transparency enforcement [OWASP API7]"
#         }

#         for header, desc in important_headers.items():
#             if header in headers:
#                 findings.append(f"✔ {header} is present ({desc})")
#             else:
#                 findings.append(f"❌ {header} is missing! ({desc})")
#     except Exception as e:
#         findings.append(f"⚠ Failed to fetch headers: {e}")

# def check_crypto_weaknesses(findings):
#     weaknesses = [
#         {"item": "Usage of MD5", "risk": "Collision attacks [OWASP API3:2023]"},
#         {"item": "Usage of SHA-1", "risk": "Weak hash strength [OWASP API3:2023]"},
#         {"item": "RSA keys < 2048 bits", "risk": "Easily breakable [OWASP API3:2023]"},
#         {"item": "AES keys < 128 bits", "risk": "Weak symmetric encryption [OWASP API3:2023]"},
#     ]
#     for weakness in weaknesses:
#         findings.append(f"⚠ {weakness['item']} - {weakness['risk']}")

# def generate_html_report(url, findings):
#     owasp_sections = {f"API{i}": [] for i in range(1, 11)}
#     owasp_sections["Uncategorized"] = []

#     for item in findings:
#         matched = False
#         for key in owasp_sections:
#             if f"[OWASP {key}:" in item:
#                 owasp_sections[key].append(item)
#                 matched = True
#                 break
#         if not matched:
#             owasp_sections["Uncategorized"].append(item)

#     template = Template("""<!DOCTYPE html>
#     <html><head><style>
#     body { font-family: Arial; padding: 20px; }
#     h1 { color: #003366; }
#     .good { color: green; }
#     .bad { color: red; }
#     .warn { color: orange; }
#     </style></head><body>
#     <h1>API Vulnerability Report</h1>
#     <p><strong>Scanned URL:</strong> {{ url }}</p>
#     <p><strong>Date:</strong> {{ date }}</p>
#     {% for key, items in owasp_sections.items() if items %}
#         <h2>{{ key }}</h2>
#         {% for item in items %}
#             <div class="{{ 'good' if '✔' in item else 'bad' if '❌' in item else 'warn' }}">{{ item }}</div>
#         {% endfor %}
#     {% endfor %}
#     </body></html>
#     """)
#     return template.render(url=url, date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), owasp_sections=owasp_sections)

# def save_pdf(html, filename):
#     try:
#         config = pdfkit.configuration(wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe') if os.name == 'nt' else None
#         pdfkit.from_string(html, filename, configuration=config)
#     except Exception as e:
#         print(f"🚨 PDF Generation Error: {e}")
#         raise

# # POST-based view-report route (used by frontend)
# @app.route('/view-report', methods=['POST'])
# def view_report():
#     data = request.json
#     url = data.get("url")
#     if not url:
#         return jsonify({'error': 'URL missing'}), 400

#     parsed_url = urlparse(url)
#     hostname = parsed_url.netloc
#     findings = []

#     check_https(url, findings)
#     check_ssl_tls(hostname, findings)
#     check_security_headers(url, findings)
#     check_crypto_weaknesses(findings)

#     try:
#         findings.extend(advanced_scan(url).get("issues", []))
#     except Exception as e:
#         findings.append(f"⚠ Advanced scan failed: {e}")

#     html = generate_html_report(url, findings)
#     return jsonify({'html': html, 'findings': findings, 'url': url})

# # GET-based scan route (for direct API calls or testing)
# @app.route('/scan', methods=['GET'])
# def scan():
#     url = request.args.get("url")
#     if not url:
#         return jsonify({'error': 'URL is missing'}), 400

#     parsed_url = urlparse(url)
#     hostname = parsed_url.netloc
#     findings = []

#     check_https(url, findings)
#     check_ssl_tls(hostname, findings)
#     check_security_headers(url, findings)
#     check_crypto_weaknesses(findings)

#     try:
#         findings.extend(advanced_scan(url).get("issues", []))
#     except Exception as e:
#         findings.append(f"⚠ Advanced scan failed: {e}")

#     html = generate_html_report(url, findings)
#     return jsonify({'html': html, 'findings': findings, 'url': url})

# # PDF generation route
# @app.route('/generate-pdf', methods=['POST'])
# def generate_pdf():
#     data = request.json
#     findings = data.get("findings", [])
#     url = data.get("url", "N/A")
#     html = generate_html_report(url, findings)
#     if not os.path.exists('static'):
#         os.makedirs('static')
#     save_pdf(html, REPORT_PATH)
#     return jsonify({'message': 'PDF generated', 'download_url': '/download-report'})

# # PDF download route
# @app.route('/download-report', methods=['GET'])
# def download_report():
#     if os.path.exists(REPORT_PATH):
#         return send_file(REPORT_PATH, as_attachment=True)
#     return jsonify({'error': 'No report found'}), 404

# # Start server
# if __name__ == "__main__":
#     if not os.path.exists('static'):
#         os.makedirs('static')
#     app.run(debug=False)







from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from urllib.parse import urlparse
from datetime import datetime
import os
import requests
import ssl
import socket
import pdfkit
from jinja2 import Template
import logging
from scanner.scanner import advanced_scan

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
REPORT_PATH = "static/report.pdf"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Security Check Functions
def check_https(url, findings):
    if url.startswith('https://'):
        findings.append("✔ API is using HTTPS. [OWASP API2:2023 - Broken User Authentication]")
    else:
        findings.append("❌ API is NOT using HTTPS! (Risk of data interception) [OWASP API2:2023]")

def check_ssl_tls(hostname, findings):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()

                findings.append(f"✔ Secure SSL/TLS Version: {ssl_version}" if ssl_version in ['TLSv1.2', 'TLSv1.3']
                              else f"❌ Weak SSL/TLS Version Detected: {ssl_version} [OWASP API7:2023]")

                findings.append(f"✔ Cipher Used: {cipher[0]} ({cipher[1]} bits)")
                if cipher[1] < 128:
                    findings.append("❌ Weak Cipher Strength (<128 bits)! [OWASP API7:2023]")

                expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                findings.append(f"✔ SSL Certificate is valid until {expiry}" if expiry > datetime.utcnow()
                              else "❌ SSL Certificate has expired!")

    except Exception as e:
        findings.append(f"⚠ SSL/TLS Check Failed: {e}")

def check_security_headers(url, findings):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        important_headers = {
            "Strict-Transport-Security": "Protects against protocol downgrade attacks [OWASP API7]",
            "Content-Security-Policy": "Prevents XSS attacks [OWASP API8]",
            "X-Content-Type-Options": "Prevents MIME-sniffing [OWASP API8]",
            "X-Frame-Options": "Protects against clickjacking [OWASP API8]",
            "Referrer-Policy": "Controls referer info [OWASP API7]",
            "Permissions-Policy": "Restricts powerful features [OWASP API8]",
            "Cross-Origin-Embedder-Policy": "Prevents cross-origin issues [OWASP API8]",
            "Cross-Origin-Opener-Policy": "Isolates browsing context [OWASP API8]",
            "Cross-Origin-Resource-Policy": "Prevents cross-origin sharing [OWASP API8]",
            "Expect-CT": "Certificate transparency enforcement [OWASP API7]"
        }

        for header, desc in important_headers.items():
            if header in headers:
                findings.append(f"✔ {header} is present ({desc})")
            else:
                findings.append(f"❌ {header} is missing! ({desc})")
    except Exception as e:
        findings.append(f"⚠ Failed to fetch headers: {e}")

def check_crypto_weaknesses(findings):
    weaknesses = [
        {"item": "Usage of MD5", "risk": "Collision attacks [OWASP API3:2023]"},
        {"item": "Usage of SHA-1", "risk": "Weak hash strength [OWASP API3:2023]"},
        {"item": "RSA keys < 2048 bits", "risk": "Easily breakable [OWASP API3:2023]"},
        {"item": "AES keys < 128 bits", "risk": "Weak symmetric encryption [OWASP API3:2023]"},
    ]
    for weakness in weaknesses:
        findings.append(f"⚠ {weakness['item']} - {weakness['risk']}")

def generate_html_report(url, findings):
    owasp_sections = {f"API{i}": [] for i in range(1, 11)}
    owasp_sections["Uncategorized"] = []

    for item in findings:
        matched = False
        for key in owasp_sections:
            if f"[OWASP {key}:" in item:
                owasp_sections[key].append(item)
                matched = True
                break
        if not matched:
            owasp_sections["Uncategorized"].append(item)

    template = Template("""<!DOCTYPE html>
    <html><head>
    <meta charset="UTF-8">
    <style>
    body { font-family: Arial, sans-serif; padding: 20px; line-height: 1.6; }
    h1 { color: #003366; border-bottom: 2px solid #003366; padding-bottom: 10px; }
    h2 { color: #2c5282; margin-top: 25px; border-left: 4px solid #2c5282; padding-left: 10px; }
    .good { color: green; }
    .bad { color: red; }
    .warn { color: orange; }
    .finding { margin-bottom: 8px; padding: 5px; border-radius: 3px; }
    .finding.good { background-color: #f0fff4; }
    .finding.bad { background-color: #fff5f5; }
    .finding.warn { background-color: #fffaf0; }
    .header { display: flex; justify-content: space-between; margin-bottom: 20px; }
    .logo { max-height: 60px; }
    </style>
    <title>API Vulnerability Report</title>
    </head>
    <body>
    <div class="header">
        <div>
            <h1>API Vulnerability Report</h1>
            <p><strong>Scanned URL:</strong> {{ url }}</p>
            <p><strong>Date:</strong> {{ date }}</p>
        </div>
    </div>
    
    {% for key, items in owasp_sections.items() if items %}
        <h2>{{ key }} Vulnerabilities</h2>
        {% for item in items %}
            <div class="finding {{ 'good' if '✔' in item else 'bad' if '❌' in item else 'warn' }}">
                {{ item }}
            </div>
        {% endfor %}
    {% endfor %}
    
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; text-align: center;">
        <p>Generated by API Security Scanner</p>
    </footer>
    </body></html>
    """)
    return template.render(url=url, date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), owasp_sections=owasp_sections)

def save_pdf(html, filename):
    try:
        options = {
            'encoding': 'UTF-8',
            'enable-local-file-access': '',
            'quiet': '',
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'footer-center': '[page]/[topage]',
            'footer-font-size': '8',
        }
        
        config = pdfkit.configuration(
            wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe' 
            if os.name == 'nt' 
            else None
        )
        
        pdfkit.from_string(
            html, 
            filename, 
            options=options,
            configuration=config
        )
        return True
    except Exception as e:
        logger.error(f"PDF generation error: {str(e)}")
        raise RuntimeError(f"Failed to generate PDF: {str(e)}")

@app.route('/view-report', methods=['POST'])
def view_report():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        url = data.get("url")
        if not url:
            return jsonify({'error': 'URL missing'}), 400

        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        findings = []

        # Run security checks
        check_https(url, findings)
        check_ssl_tls(hostname, findings)
        check_security_headers(url, findings)
        check_crypto_weaknesses(findings)

        # Run advanced scan
        try:
            advanced_results = advanced_scan(url)
            findings.extend(advanced_results.get("issues", []))
        except Exception as e:
            findings.append(f"⚠ Advanced scan failed: {e}")
            logger.error(f"Advanced scan failed: {e}")

        html = generate_html_report(url, findings)
        return jsonify({
            'success': True,
            'html': html, 
            'findings': findings, 
            'url': url
        })
    except Exception as e:
        logger.error(f"Error in view-report: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/generate-pdf', methods=['POST'])
def generate_pdf():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        findings = data.get("findings", [])
        url = data.get("url", "N/A")
        
        if not findings:
            return jsonify({'error': 'No findings provided'}), 400
            
        html = generate_html_report(url, findings)
        
        if not os.path.exists('static'):
            os.makedirs('static')
            
        save_pdf(html, REPORT_PATH)
        return jsonify({
            'success': True,
            'message': 'PDF generated successfully',
            'download_url': '/download-report'
        })
    except Exception as e:
        logger.error(f"PDF generation failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'PDF generation failed: {str(e)}'
        }), 500

@app.route('/download-report', methods=['GET'])
def download_report():
    try:
        if not os.path.exists(REPORT_PATH):
            return jsonify({'error': 'Report not found. Please generate it first.'}), 404
            
        return send_file(
            REPORT_PATH,
            as_attachment=True,
            download_name=f"API_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        logger.error(f"Download failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/scan', methods=['GET'])
def scan():
    try:
        url = request.args.get("url")
        if not url:
            return jsonify({'error': 'URL is missing'}), 400

        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        findings = []

        check_https(url, findings)
        check_ssl_tls(hostname, findings)
        check_security_headers(url, findings)
        check_crypto_weaknesses(findings)

        try:
            advanced_results = advanced_scan(url)
            findings.extend(advanced_results.get("issues", []))
        except Exception as e:
            findings.append(f"⚠ Advanced scan failed: {e}")

        html = generate_html_report(url, findings)
        return jsonify({
            'success': True,
            'html': html, 
            'findings': findings, 
            'url': url
        })
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == "__main__":
    if not os.path.exists('static'):
        os.makedirs('static')
    app.run(host='0.0.0.0', port=5000, debug=False)