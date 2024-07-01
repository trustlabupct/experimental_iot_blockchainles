# This script makes a request to an IPFS server to retrieve stored data. 
# It connects to a local IPFS node and retrieves transaction data using a given hash.

import ipfshttpclient

# Connect to the local IPFS node
client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http')

def retrieve_transaction_data(hash):
    try:
        # Retrieve transaction data from IPFS using the hash
        res = client.get_json(hash)
        # Return the transaction data
        return res
    except Exception as e:
        # Print an error message if retrieval fails
        print("Error retrieving transaction data from IPFS:", str(e))
        return None

# Prompt the user to enter the transaction hash
hash_from_user = input("Please enter the transaction hash: ")

# Use the provided hash to retrieve the transaction data
transaction_data = retrieve_transaction_data(hash_from_user)

# Check if the transaction data was successfully retrieved and print the result
if transaction_data:
    print("Transaction data successfully retrieved:", transaction_data)
else:
    print("Failed to retrieve transaction data.")
