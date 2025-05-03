from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests

# Dummy transaction data
transactions = [
    {"username": "user1", "amount": 100.5},
    {"username": "user2", "amount": 250.0},
    {"username": "user3", "amount": 50.75},
    {"username": "user4", "amount": 300.0},
    {"username": "user5", "amount": 150.25},
]

@app.route('/transactions', methods=['GET'])
def get_transactions():
    username = request.args.get('username')
    if username:
        filtered = [t for t in transactions if t['username'] == username]
        return jsonify(filtered)
    return jsonify(transactions)

if __name__ == '__main__':
    app.run(debug=True)
