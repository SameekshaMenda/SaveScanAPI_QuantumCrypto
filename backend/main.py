from flask import Flask, request, jsonify
from scanner.scanner import scan_api
from crypto.pqc_encrypt import quantum_encrypt

app = Flask(__name__)

@app.route("/scan", methods=["POST"])
def scan():
    """
    Endpoint to scan the given API URL for basic security vulnerabilities.
    Expects JSON: { "url": "<API URL>" }
    Returns: Vulnerability report (JSON)
    """
    data = request.get_json()
    api_url = data.get("url")
    report = scan_api(api_url)
    return jsonify(report)

@app.route("/secure-comm", methods=["POST"])
def secure_comm():
    """
    Endpoint to simulate quantum-safe communication.
    Expects JSON: { "message": "<message>" }
    Returns: Encrypted and decrypted message (JSON)
    """
    data = request.get_json()
    message = data.get("message")
    encrypted, decrypted = quantum_encrypt(message)
    return jsonify({"encrypted": encrypted, "decrypted": decrypted})

if __name__ == "__main__":
    app.run(debug=True)
