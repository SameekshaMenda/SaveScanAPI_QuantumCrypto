import requests

def scan_api(url):
    """
    Scans a given API URL for common vulnerabilities.
    
    Parameters:
        url (str): The URL of the API to scan.
    
    Returns:
        dict: A dictionary with the URL and a list of found issues.
    """
    result = {
        "url": url,
        "issues": []
    }

    try:
        # Make a GET request to the API
        response = requests.get(url)

        # Check if HTTPS is used
        if not url.startswith("https"):
            result["issues"].append("No HTTPS detected")

        # Check for missing security headers
        headers = response.headers
        if "X-Frame-Options" not in headers:
            result["issues"].append("Missing X-Frame-Options header")
        if "Content-Security-Policy" not in headers:
            result["issues"].append("Missing Content-Security-Policy header")

        # Check for insecure CORS policy
        cors_origin = headers.get("Access-Control-Allow-Origin", "")
        if "*" in cors_origin:
            result["issues"].append("CORS policy allows all origins (*)")

    except Exception as e:
        result["issues"].append(f"Could not connect: {str(e)}")

    return result
