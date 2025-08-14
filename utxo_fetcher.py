import requests
import json
from typing import List, Dict

def fetch_utxos(address: str) -> List[Dict]:
    """Fetch UTXOs from mempool.space API for a given address"""
    url = f"https://mempool.space/api/address/{address}/utxo"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        utxos = response.json()
        
        # Save UTXOs to JSON file
        with open('utxos.json', 'w') as f:
            json.dump(utxos, f, indent=2)
        
        return utxos
    
    except Exception as e:
        print(f"Error fetching UTXOs: {e}")
        return []

def main():
    """Main function to fetch and save UTXOs for a given address"""
    print("=== Bitcoin UTXO Fetcher ===")
    print("Network: Mainnet")
    print()
    
    # Get Bitcoin address
    address = input("Enter Bitcoin address: ").strip()
    
    if not address:
        print("Error: Address cannot be empty")
        return
    
    # Fetch and save UTXOs
    print(f"\nFetching UTXOs for address: {address}")
    utxos = fetch_utxos(address)
    
    if not utxos:
        print("No UTXOs found for this address")
        return
    
    total_balance = sum(u['value'] for u in utxos)
    print(f"\nFound {len(utxos)} UTXOs")
    print(f"Total balance: {total_balance / 100_000_000:.8f} BTC")
    print(f"UTXOs saved to 'utxos.json'")

if __name__ == "__main__":
    main()
