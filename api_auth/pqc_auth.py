# pqc_auth_simulated.py
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

# Generate key pair (simulate PQC key gen)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')

    if username != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401

    # Simulate token signing
    message = b"authenticated"
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return jsonify({
        'message': 'Login successful',
        'signature': signature.hex()
    })

@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    signature = bytes.fromhex(data.get('signature'))

    try:
        public_key.verify(
            signature,
            b"authenticated",
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return jsonify({'status': 'Signature valid'})
    except Exception:
        return jsonify({'status': 'Invalid signature'}), 400

if __name__ == '__main__':
    app.run(debug=True)
