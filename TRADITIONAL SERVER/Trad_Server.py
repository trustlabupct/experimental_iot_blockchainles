"""
This script sets up a Flask web server that handles transactions for an IoT system. It verifies transaction signatures, stores validated transactions, and retrieves transactions upon request.
"""

from flask import Flask, request, jsonify
import hashlib
import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Transaction storage
transactions = {}

def verify_signature(transaction_data, signature, public_key_pem):
    """
    Verifies the ECDSA signature of the transaction data.
    """
    public_key = load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    data_encoded = json.dumps(transaction_data).encode('utf-8')
    try:
        public_key.verify(signature, data_encoded, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def load_transactions():
    """
    Loads transactions from a JSON file.
    """
    try:
        with open('transactions.json', 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return {}

# Load existing transactions
transactions = load_transactions()

@app.route('/submit', methods=['POST'])
def submit_transaction():
    """
    Endpoint to submit a transaction. Verifies the transaction signature, computes the hash, and stores the transaction.
    """
    payload = request.json
    data = payload['data']
    signature = payload['signature']
    public_key_pem = payload['public_key']
    node_id = payload['node_id']
    
    # Verify the signature
    if not verify_signature(data, bytes.fromhex(signature), public_key_pem):
        return jsonify({'error': 'Invalid signature'}), 400

    transaction_id = data['transaction_id']
    device_id = data['device_id']
    temperature = data['temperature']
    timestamp = data['timestamp']

    # Concatenate data for the hash
    hash_input = f"{transaction_id}{device_id}{temperature}{timestamp}".encode('utf-8')
    hash_output = hashlib.sha256(hash_input).hexdigest()

    # Update the transaction dictionary securely
    new_entry = {
        'device_id': device_id,
        'temperature': temperature,
        'timestamp': timestamp,
        'transaction_id': transaction_id,
        'node_id': node_id
    }
    transactions[hash_output] = new_entry

    # Make a safe copy of the transaction dictionary for serialization
    transactions_copy = dict(transactions)
    
    with open('transactions.json', 'w') as f:
        json.dump(transactions_copy, f, indent=4)

    # Respond with the hash
    return jsonify({'hash': hash_output})

@app.route('/get_transaction', methods=['GET'])
def get_transaction():
    """
    Endpoint to retrieve a transaction based on its hash.
    """
    hash_value = request.args.get('hash')
    transaction = transactions.get(hash_value)
    if transaction:
        return jsonify(transaction)
    else:
        return jsonify({"error": "Transaction not found"}), 404

if __name__ == '__main__':
    app.run(host='localhost', port=8000, debug=True)
