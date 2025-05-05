# scanner/scanner.py

import requests
from urllib.parse import urljoin
import jwt

def advanced_scan(url):
    issues = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        if not url.startswith("https://"):
            issues.append("❌ Insecure protocol (HTTPS missing) [OWASP API2:2023]")

        # Important security headers
        required_headers = {
            "Content-Security-Policy": ("Mitigates XSS", "OWASP API8:2023"),
            "X-Frame-Options": ("Clickjacking prevention", "OWASP API8:2023"),
            "Strict-Transport-Security": ("Enforce HTTPS", "OWASP API7:2023"),
            "X-Content-Type-Options": ("Prevent MIME sniffing", "OWASP API8:2023")
        }

        for header, (purpose, owasp_tag) in required_headers.items():
            if header not in headers:
                issues.append(f"❌ Missing {header} ({purpose}) [{owasp_tag}]")

        # Modern headers
        modern_headers = {
            "Permissions-Policy": ("Restricts features like camera, geolocation", "OWASP API8:2023"),
            "Cross-Origin-Embedder-Policy": ("Prevents cross-origin resources", "OWASP API8:2023"),
            "Cross-Origin-Opener-Policy": ("Isolates browsing context group", "OWASP API8:2023"),
            "Cross-Origin-Resource-Policy": ("CORS policy enforcement", "OWASP API8:2023"),
            "Expect-CT": ("Ensures Certificate Transparency", "OWASP API7:2023")
        }

        for header, (purpose, owasp_tag) in modern_headers.items():
            if header not in headers:
                issues.append(f"⚠️ Missing {header} ({purpose}) [{owasp_tag}]")

        # CORS check
        if "Access-Control-Allow-Origin" in headers and "*" in headers["Access-Control-Allow-Origin"]:
            issues.append("⚠️ CORS policy too open [OWASP API8:2023]")

        # JWT checks
        if "Authorization" not in headers:
            issues.append("⚠️ No Authorization token in headers [OWASP API2:2023]")
        else:
            token = headers.get("Authorization").replace("Bearer ", "")
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                header = jwt.get_unverified_header(token)

                if 'exp' not in decoded:
                    issues.append("⚠️ JWT token missing 'exp' (expiration) claim [OWASP API2:2023]")

                if header.get("alg", "").lower() == "none":
                    issues.append("❌ JWT algorithm set to 'none' - major vulnerability [OWASP API2:2023]")

            except Exception:
                issues.append("⚠️ Failed to parse JWT token (may be invalid or encrypted) [OWASP API2:2023]")

        # Rate limit headers
        for h in ["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"]:
            if h not in headers:
                issues.append(f"⚠️ Missing {h} - may indicate lack of rate limiting [OWASP API4:2023]")

        # Check for open API docs
        def check_openapi_exposure(base_url):
            doc_paths = ["/swagger.json", "/v2/api-docs", "/openapi.json"]
            for path in doc_paths:
                try:
                    full_url = urljoin(base_url, path)
                    r = requests.get(full_url, timeout=3)
                    if r.status_code == 200 and "swagger" in r.text.lower():
                        issues.append(f"❌ Exposed API documentation at: {full_url} [OWASP API9:2023]")
                except:
                    continue

        check_openapi_exposure(url)

        return {
            "url": url,
            "status_code": response.status_code,
            "issues": issues or ["✅ No major issues detected [OWASP API10:2023]"]
        }

    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "issues": ["❌ Connection failed or timed out [OWASP API10:2023]"]
        }
