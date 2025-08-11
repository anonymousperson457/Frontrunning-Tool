import hashlib
import requests
import time
import json
import os
from typing import Dict, List, Tuple, Optional
import struct

# Secp256k1 parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def modinv(a: int, m: int) -> int:
    """Modular inverse using extended Euclidean algorithm"""
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = egcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = egcd(a % m, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    return (x % m + m) % m

def point_add(p1: Tuple[int, int], p2: Tuple[int, int]) -> Tuple[int, int]:
    """Elliptic curve point addition"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    
    x1, y1 = p1
    x2, y2 = p2
    
    if x1 == x2:
        if y1 == y2:
            # Point doubling
            s = (3 * x1 * x1 * modinv(2 * y1, P)) % P
        else:
            return None
    else:
        s = ((y2 - y1) * modinv(x2 - x1, P)) % P
    
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    
    return (x3, y3)

def point_multiply(k: int, point: Tuple[int, int]) -> Tuple[int, int]:
    """Scalar multiplication on elliptic curve"""
    if k == 0:
        return None
    
    result = None
    addend = point
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    
    return result

def privkey_to_pubkey(privkey: bytes) -> bytes:
    """Convert private key to public key"""
    privkey_int = int.from_bytes(privkey, 'big')
    pubkey_point = point_multiply(privkey_int, G)
    
    # Compressed public key
    x = pubkey_point[0].to_bytes(32, 'big')
    if pubkey_point[1] % 2 == 0:
        return b'\x02' + x
    else:
        return b'\x03' + x

def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))"""
    sha = hashlib.sha256(data).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    return ripe

def base58_encode(data: bytes) -> str:
    """Base58 encoding"""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    
    num = int.from_bytes(data, 'big')
    result = []
    
    while num > 0:
        num, remainder = divmod(num, 58)
        result.append(alphabet[remainder])
    
    # Add leading 1s for leading zeros
    for byte in data:
        if byte == 0:
            result.append('1')
        else:
            break
    
    return ''.join(reversed(result))

def base58_decode(s: str) -> bytes:
    """Base58 decoding"""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    
    num = 0
    for char in s:
        num = num * 58 + alphabet.index(char)
    
    # Convert to bytes
    hex_str = hex(num)[2:]
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    
    result = bytes.fromhex(hex_str)
    
    # Add leading zeros
    for char in s:
        if char == '1':
            result = b'\x00' + result
        else:
            break
    
    return result

def pubkey_to_p2pkh_address(pubkey: bytes) -> str:
    """Convert public key to P2PKH address"""
    pubkey_hash = hash160(pubkey)
    
    # Add version byte (0x00 for mainnet)
    versioned = b'\x00' + pubkey_hash
    
    # Add checksum
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    
    return base58_encode(versioned + checksum)

def address_to_pubkey_hash(address: str) -> bytes:
    """Extract pubkey hash from P2PKH address"""
    decoded = base58_decode(address)
    return decoded[1:-4]  # Remove version byte and checksum

def btc_to_satoshi(btc: float) -> int:
    """Convert BTC to satoshis"""
    return int(btc * 100_000_000)

def satoshi_to_btc(satoshi: int) -> float:
    """Convert satoshis to BTC"""
    return satoshi / 100_000_000

def get_current_fee_rate() -> int:
    """Get current recommended fee rate from mempool.space"""
    try:
        url = "https://mempool.space/api/v1/fees/recommended"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        fees = response.json()
        return fees.get('fastestFee', 10)  # Default to 10 sat/vB if API fails
    except:
        return 10  # Default fallback

def btc_fee_to_sat_vb(btc_fee: float, estimated_size: int = 250) -> int:
    """Convert BTC fee to sat/vB rate"""
    satoshi_fee = btc_to_satoshi(btc_fee)
    return max(1, satoshi_fee // estimated_size)

def fetch_utxos(address: str) -> List[Dict]:
    """Fetch UTXOs from mempool.space API"""
    url = f"https://mempool.space/api/address/{address}/utxo"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching UTXOs: {e}")
        return []

def var_int(n: int) -> bytes:
    """Encode integer as variable length integer"""
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return struct.pack('<BH', 0xfd, n)
    elif n <= 0xffffffff:
        return struct.pack('<BI', 0xfe, n)
    else:
        return struct.pack('<BQ', 0xff, n)

def double_sha256(data: bytes) -> bytes:
    """Double SHA256 hash"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def sign_transaction(tx_hash: bytes, privkey: bytes) -> bytes:
    """Sign transaction hash with private key (DER format)"""
    privkey_int = int.from_bytes(privkey, 'big')
    
    # Simple deterministic k generation (for demo - use proper RFC6979 in production)
    k = int.from_bytes(hashlib.sha256(privkey + tx_hash).digest(), 'big') % N
    
    # Calculate signature
    r_point = point_multiply(k, G)
    r = r_point[0] % N
    
    k_inv = modinv(k, N)
    z = int.from_bytes(tx_hash, 'big')
    s = (k_inv * (z + r * privkey_int)) % N
    
    # Ensure low S value
    if s > N // 2:
        s = N - s
    
    # DER encoding
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, 'big')
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, 'big')
    
    # Add padding if high bit is set
    if r_bytes[0] & 0x80:
        r_bytes = b'\x00' + r_bytes
    if s_bytes[0] & 0x80:
        s_bytes = b'\x00' + s_bytes
    
    der = b'\x02' + bytes([len(r_bytes)]) + r_bytes
    der += b'\x02' + bytes([len(s_bytes)]) + s_bytes
    der = b'\x30' + bytes([len(der)]) + der
    
    return der

def create_raw_transaction(utxos: List[Dict], privkey: bytes, recipient: str, 
                          amount: int, fee_satoshi: int) -> Tuple[str, str]:
    """Create and sign raw transaction with RBF enabled using user-provided fee"""
    pubkey = privkey_to_pubkey(privkey)
    sender_address = pubkey_to_p2pkh_address(pubkey)
    
    # Select UTXOs
    selected_utxos = []
    total_input = 0
    
    for utxo in utxos:
        selected_utxos.append(utxo)
        total_input += utxo['value']
        if total_input >= amount + fee_satoshi:
            break
    
    if total_input < amount + fee_satoshi:
        raise ValueError("Insufficient funds")
    
    # Build transaction
    tx = b''
    
    # Version (4 bytes)
    tx += struct.pack('<I', 2)
    
    # Input count
    tx += var_int(len(selected_utxos))
    
    # Inputs
    for utxo in selected_utxos:
        # Previous output hash (32 bytes, reversed)
        tx += bytes.fromhex(utxo['txid'])[::-1]
        
        # Previous output index (4 bytes)
        tx += struct.pack('<I', utxo['vout'])
        
        # Script length (will be replaced during signing)
        tx += b'\x00'
        
        # Sequence (RBF enabled: 0xfffffffd)
        tx += struct.pack('<I', 0xfffffffd)
    
    # Output count
    tx += var_int(2)  # Recipient + change
    
    # Output 1: Recipient
    tx += struct.pack('<Q', amount)
    recipient_hash = address_to_pubkey_hash(recipient)
    script_pubkey = b'\x76\xa9\x14' + recipient_hash + b'\x88\xac'
    tx += var_int(len(script_pubkey)) + script_pubkey
    
    # Calculate change
    change = total_input - amount - fee_satoshi
    
    if change > 546:  # Dust limit
        # Output 2: Change
        tx += struct.pack('<Q', change)
        sender_hash = address_to_pubkey_hash(sender_address)
        change_script = b'\x76\xa9\x14' + sender_hash + b'\x88\xac'
        tx += var_int(len(change_script)) + change_script
    
    # Locktime
    tx += struct.pack('<I', 0)
    
    # Sign inputs
    signed_tx = b''
    signed_tx += struct.pack('<I', 2)  # Version
    signed_tx += var_int(len(selected_utxos))
    
    for i, utxo in enumerate(selected_utxos):
        # Build signature hash
        sighash_preimage = b''
        sighash_preimage += struct.pack('<I', 2)  # Version
        sighash_preimage += var_int(len(selected_utxos))
        
        for j, u in enumerate(selected_utxos):
            sighash_preimage += bytes.fromhex(u['txid'])[::-1]
            sighash_preimage += struct.pack('<I', u['vout'])
            
            if i == j:
                # Add scriptPubKey for the input being signed
                prev_script = b'\x76\xa9\x14' + address_to_pubkey_hash(sender_address) + b'\x88\xac'
                sighash_preimage += var_int(len(prev_script)) + prev_script
            else:
                sighash_preimage += b'\x00'
            
            sighash_preimage += struct.pack('<I', 0xfffffffd)
        
        # Add outputs
        sighash_preimage += var_int(2 if change > 546 else 1)
        sighash_preimage += struct.pack('<Q', amount)
        sighash_preimage += var_int(len(script_pubkey)) + script_pubkey
        
        if change > 546:
            sighash_preimage += struct.pack('<Q', change)
            sighash_preimage += var_int(len(change_script)) + change_script
        
        sighash_preimage += struct.pack('<I', 0)  # Locktime
        sighash_preimage += struct.pack('<I', 1)  # SIGHASH_ALL
        
        # Sign
        sighash = double_sha256(sighash_preimage)
        signature = sign_transaction(sighash, privkey) + b'\x01'  # SIGHASH_ALL
        
        # Create scriptSig
        script_sig = var_int(len(signature)) + signature
        script_sig += var_int(len(pubkey)) + pubkey
        
        # Add signed input
        signed_tx += bytes.fromhex(utxo['txid'])[::-1]
        signed_tx += struct.pack('<I', utxo['vout'])
        signed_tx += var_int(len(script_sig)) + script_sig
        signed_tx += struct.pack('<I', 0xfffffffd)
    
    # Add outputs and locktime
    signed_tx += var_int(2 if change > 546 else 1)
    signed_tx += struct.pack('<Q', amount)
    signed_tx += var_int(len(script_pubkey)) + script_pubkey
    
    if change > 546:
        signed_tx += struct.pack('<Q', change)
        signed_tx += var_int(len(change_script)) + change_script
    
    signed_tx += struct.pack('<I', 0)
    
    tx_hex = signed_tx.hex()
    txid = double_sha256(signed_tx)[::-1].hex()
    
    return tx_hex, txid

def broadcast_transaction(tx_hex: str) -> Optional[str]:
    """Broadcast transaction via mempool.space API"""
    url = "https://mempool.space/api/tx"
    
    try:
        response = requests.post(url, data=tx_hex, headers={'Content-Type': 'text/plain'}, timeout=10)
        if response.status_code == 200:
            return response.text.strip()
        else:
            print(f"Broadcast error: {response.text}")
            return None
    except Exception as e:
        print(f"Broadcast exception: {e}")
        return None

def check_transaction_status(txid: str) -> Dict:
    """Check transaction status in mempool"""
    url = f"https://mempool.space/api/tx/{txid}"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        return {}
    except:
        return {}

def main():
    print("=== Bitcoin P2PKH Address RBF Attacker ===")
    print("Network: Mainnet")
    print()
    
    # Get private key (256-bit lowercase hex without 0x)
    privkey_hex = input("Enter private key (256-bit lowercase hex, without 0x prefix): ").strip().lower()
    
    try:
        if len(privkey_hex) != 64:
            print("Error: Private key must be exactly 64 hex characters (256 bits)")
            return
        
        privkey = bytes.fromhex(privkey_hex)
        if len(privkey) != 32:
            print("Error: Private key must be 32 bytes (256 bits)")
            return
    except ValueError:
        print("Error: Invalid hexadecimal format - use only characters 0-9 and a-f")
        return
    
    # Derive address
    pubkey = privkey_to_pubkey(privkey)
    address = pubkey_to_p2pkh_address(pubkey)
    print(f"\nYour P2PKH address: {address}")
    
    # Prompt user for initial UTXO source
    print("\nChoose UTXO source:")
    print("1. Fetch from mempool.space API")
    print("2. Load from utxos.json file")
    choice = input("Enter 1 or 2: ").strip()
    
    utxos = []
    if choice == '1':
        print("\nFetching UTXOs from mempool.space API...")
        utxos = fetch_utxos(address)
        if utxos:
            # Save fetched UTXOs to file
            with open('utxos.json', 'w') as f:
                json.dump(utxos, f, indent=2)
    elif choice == '2':
        if os.path.exists('utxos.json'):
            print("\nLoading UTXOs from utxos.json...")
            try:
                with open('utxos.json', 'r') as f:
                    utxos = json.load(f)
            except Exception as e:
                print(f"Error loading UTXOs from file: {e}")
                return
        else:
            print("Error: utxos.json file not found")
            return
    else:
        print("Error: Invalid choice. Please enter 1 or 2")
        return
    
    if not utxos:
        print("No UTXOs found")
        return
    
    total_balance = sum(u['value'] for u in utxos)
    print(f"Found {len(utxos)} UTXOs")
    print(f"Total balance: {satoshi_to_btc(total_balance):.8f} BTC")
    
    # Get recipient
    recipient = input("\nEnter Recipient P2PKH Address: ").strip()
    
    # Get amount in BTC
    try:
        amount_btc = float(input("Enter amount to send (BTC): "))
        amount_satoshi = btc_to_satoshi(amount_btc)
    except ValueError:
        print("Error: Invalid BTC amount")
        return

    # Get fee in BTC
    try:
        fee_btc = float(input("Enter transaction fee (BTC): "))
        fee_satoshi = btc_to_satoshi(fee_btc)
    except ValueError:
        print("Error: Invalid fee amount")
        return

    # Subtract fee from amount
    net_amount_satoshi = amount_satoshi - fee_satoshi
    if net_amount_satoshi <= 546:  # Check against dust limit
        print(f"Error: Net amount after fee ({satoshi_to_btc(net_amount_satoshi):.8f} BTC) is too low (must be above dust limit of 0.00000546 BTC)")
        return

    # Check if sufficient funds are available
    if total_balance < net_amount_satoshi:
        print(f"Error: Insufficient funds")
        print(f"Available balance: {satoshi_to_btc(total_balance):.8f} BTC")
        print(f"Required: {satoshi_to_btc(net_amount_satoshi):.8f} BTC (Net Amount after {satoshi_to_btc(fee_satoshi):.8f} BTC fee)")
        return

    print(f"\nCreating transaction with RBF enabled...")
    print(f"Net amount to send (after fee): {satoshi_to_btc(net_amount_satoshi):.8f} BTC")
    print(f"Fee: {satoshi_to_btc(fee_satoshi):.8f} BTC")
    
    try:
        tx_hex, txid = create_raw_transaction(utxos, privkey, recipient, net_amount_satoshi, fee_satoshi)
        print(f"Transaction ID: {txid}")
        
        # Broadcast initial transaction
        print("\nBroadcasting transaction...")
        result = broadcast_transaction(tx_hex)
        
        if result:
            print(f"Transaction broadcast successfully!")
            current_txid = txid
            current_fee_satoshi = fee_satoshi
            
            # Monitor for confirmation or replacement
            print("\nMonitoring transaction status...")
            print("Checking every 5 seconds for replacements. Waiting for 1 confirmation only.")
            print("Press Ctrl+C to exit.")
            
            while True:
                try:
                    time.sleep(5)  # Check every 5 seconds
                    
                    # Check transaction status
                    status = check_transaction_status(current_txid)
                    
                    if status.get('status', {}).get('confirmed', False):
                        confirmations = status.get('status', {}).get('block_height', 0)
                        if confirmations > 0:  # At least 1 confirmation
                            print(f"\nTransaction Confirmed!")
                            print(f"Transaction ID: {current_txid}")
                            print(f"Block height: {status['status'].get('block_height')}")
                            print(f"Confirmations: 1+ (waiting for 1 confirmation only)")
                            break
                    
                    elif not status:
                        # Transaction might have been replaced or dropped
                        print(f"\n⚠️TRANSACTION REPLACED!")
                         
                        # Directly prompt for new fee
                        try:
                            new_fee_btc = float(input("Enter new higher transaction fee (BTC): "))
                            new_fee_satoshi = btc_to_satoshi(new_fee_btc)
                            if new_fee_satoshi <= current_fee_satoshi:
                                print("Error: New fee must be higher than previous fee")
                                continue
                            
                            # Calculate new net amount
                            new_net_amount_satoshi = amount_satoshi - new_fee_satoshi
                            if new_net_amount_satoshi <= 546:
                                print(f"Error: Net amount after new fee ({satoshi_to_btc(new_net_amount_satoshi):.8f} BTC) is too low (must be above dust limit of 0.00000546 BTC)")
                                continue
                            
                            # Load UTXOs from utxos.json for replacement transaction
                            if os.path.exists('utxos.json'):
                                print("\nLoading UTXOs from utxos.json...")
                                try:
                                    with open('utxos.json', 'r') as f:
                                        utxos = json.load(f)
                                except Exception as e:
                                    print(f"Error loading UTXOs from file: {e}")
                                    continue
                            else:
                                print("Error: utxos.json file not found")
                                continue
                            
                            if utxos:
                                total_balance = sum(u['value'] for u in utxos)
                                if total_balance < new_net_amount_satoshi:
                                    print(f"Error: Insufficient funds for replacement transaction")
                                    print(f"Available balance: {satoshi_to_btc(total_balance):.8f} BTC")
                                    print(f"Required: {satoshi_to_btc(new_net_amount_satoshi):.8f} BTC")
                                    continue
                                
                                print("Creating replacement transaction...")
                                tx_hex, txid = create_raw_transaction(utxos, privkey, recipient, new_net_amount_satoshi, new_fee_satoshi)
                                
                                print(f"New Transaction ID: {txid}")
                                
                                # Broadcast replacement
                                result = broadcast_transaction(tx_hex)
                                
                                if result:
                                    print("Replacement transaction broadcast successfully!")
                                    print(f"Net amount to send (after fee): {satoshi_to_btc(new_net_amount_satoshi):.8f} BTC")
                                    print(f"New fee: {satoshi_to_btc(new_fee_satoshi):.8f} BTC")
                                    print("Continuing to monitor for confirmation...")
                                    current_txid = txid
                                    current_fee_satoshi = new_fee_satoshi
                                else:
                                    print("Failed to broadcast replacement transaction")
                                    break
                            else:
                                print("No UTXOs available for replacement")
                                break
                        except ValueError:
                            print("Error: Invalid fee amount")
                            continue
                    
                    else:
                        # Transaction is still in mempool
                        print(".", end="", flush=True)
                
                except KeyboardInterrupt:
                    print(f"\n\nMonitoring stopped. Current transaction ID: {current_txid}")
                    break
                except Exception as e:
                    print(f"\nError checking transaction status: {e}")
                    time.sleep(5)  # Continue checking after error
        
        else:
            print("Failed to broadcast transaction")
    
    except Exception as e:
        print(f"Error creating transaction: {e}")

if __name__ == "__main__":
    main()
