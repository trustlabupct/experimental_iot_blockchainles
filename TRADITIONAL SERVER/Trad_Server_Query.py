import requests
import json
def fetch_transaction(hash_value):
    response = requests.get(f"http://localhost:8000/get_transaction", params={'hash': hash_value})
    if response.status_code == 200:
        return response.json()
    else:
        return response.json()

def main():
    hash_value = input("Ingrese el hash SHA-256 de la transacción que desea recuperar: ")
    transaction_data = fetch_transaction(hash_value)
    if 'error' not in transaction_data:
        print("Datos de la transacción recuperados con éxito:")
        print(json.dumps(transaction_data, indent=4))
    else:
        print("Error:", transaction_data['error'])

if __name__ == "__main__":
    main()
