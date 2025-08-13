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
    
    hex_str = hex(num)[2:]
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    
    result = bytes.fromhex(hex_str)
    
    for char in s:
        if char == '1':
            result = b'\x00' + result
        else:
            break
    
    return result

def pubkey_to_p2pkh_address(pubkey: bytes) -> str:
    """Convert public key to P2PKH address for Mainnet"""
    pubkey_hash = hash160(pubkey)
    
    versioned = b'\x00' + pubkey_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    
    return base58_encode(versioned + checksum)

def address_to_pubkey_hash(address: str) -> bytes:
    """Extract pubkey hash from P2PKH or P2WPKH address"""
    if address.startswith('bc1'):
        decoded = decode_bech32(address)
        if decoded and decoded['hrp'] == 'bc' and decoded['version'] == 0 and len(decoded['program']) == 20:
            return bytes(decoded['program'])
        raise ValueError(f"Invalid P2WPKH address: {address}")
    else:
        try:
            decoded = base58_decode(address)
            if len(decoded) != 25 or decoded[0] != 0x00:
                raise ValueError(f"Invalid P2PKH address: {address}")
            return decoded[1:-4]
        except Exception as e:
            raise ValueError(f"Failed to decode P2PKH address: {str(e)}")

def btc_to_satoshi(btc: float) -> int:
    """Convert BTC to satoshis"""
    return int(round(btc * 100_000_000))

def satoshi_to_btc(satoshi: int) -> float:
    """Convert satoshis to BTC"""
    return satoshi / 100_000_000

def decode_bech32(address: str) -> Optional[Dict]:
    """Decode Bech32 address and return hrp, version, and program"""
    def bech32_polymod(values: List[int]) -> int:
        generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                chk ^= generator[i] if ((b >> i) & 1) else 0
        return chk

    def bech32_hrp_expand(hrp: str) -> List[int]:
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    def convertbits(data: List[int], frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        for value in data:
            if value < 0 or value >= (1 << frombits):
                return None
            acc = ((acc << frombits) | value) & max_acc
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        return ret

    charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

    try:
        address = address.strip().lower()
        if not (14 <= len(address) <= 74):
            return None

        if not address.startswith('bc1'):
            return None

        sep_index = address.find('1')
        if sep_index == -1:
            return None

        hrp, data = address[:sep_index], address[sep_index+1:]
        if hrp != 'bc':
            return None

        try:
            data_values = [charset.index(c) for c in data]
        except ValueError:
            return None

        values = bech32_hrp_expand(hrp) + data_values
        if bech32_polymod(values) != 1:
            return None

        version = data_values[0]
        program_5bit = data_values[1:-6]
        program_8bit = convertbits(program_5bit, 5, 8, False)
        if program_8bit is None:
            return None

        return {'hrp': hrp, 'version': version, 'program': program_8bit}

    except Exception:
        return None

def is_valid_p2wpkh_address(address: str) -> bool:
    """Check if address is a valid Mainnet P2WPKH address"""
    try:
        decoded = decode_bech32(address)
        if decoded is None:
            return False
        valid = (decoded['hrp'] == 'bc' and
                 decoded['version'] == 0 and
                 len(decoded['program']) == 20)
        return valid
    except Exception:
        return False

def fetch_utxos(address: str) -> List[Dict]:
    """Fetch UTXOs from mempool.space Mainnet API"""
    url = f"https://mempool.space/api/address/{address}/utxo"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception:
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
    
    k = int.from_bytes(hashlib.sha256(privkey + tx_hash).digest(), 'big') % N
    
    r_point = point_multiply(k, G)
    r = r_point[0] % N
    
    k_inv = modinv(k, N)
    z = int.from_bytes(tx_hash, 'big')
    s = (k_inv * (z + r * privkey_int)) % N
    
    if s > N // 2:
        s = N - s
    
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, 'big')
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, 'big')
    
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
    """Create and sign raw transaction, return tx_hex and txid"""
    pubkey = privkey_to_pubkey(privkey)
    sender_address = pubkey_to_p2pkh_address(pubkey)
    
    selected_utxos = []
    total_input = 0
    
    for utxo in utxos:
        selected_utxos.append(utxo)
        total_input += utxo['value']
        if total_input >= amount + fee_satoshi:
            break
    
    if total_input < amount + fee_satoshi:
        print(f"Insufficient funds: total_input={total_input}, required={amount + fee_satoshi}")
        raise ValueError("Insufficient funds")
    
    change = total_input - amount - fee_satoshi
    if change < 0:
        print(f"Error: Negative change calculated: {change}")
        raise ValueError("Negative change calculated")
    
    tx = b''
    tx += struct.pack('<I', 2)
    tx += var_int(len(selected_utxos))
    
    for utxo in selected_utxos:
        tx += bytes.fromhex(utxo['txid'])[::-1]
        tx += struct.pack('<I', utxo['vout'])
        tx += b'\x00'
        tx += struct.pack('<I', 0xffffffff)
    
    output_count = 2 if change > 546 else 1
    tx += var_int(output_count)
    
    tx += struct.pack('<Q', amount)
    recipient_hash = address_to_pubkey_hash(recipient)
    script_pubkey = b'\x00\x14' + recipient_hash
    tx += var_int(len(script_pubkey)) + script_pubkey
    
    if change > 546:
        tx += struct.pack('<Q', change)
        sender_hash = address_to_pubkey_hash(sender_address)
        change_script = b'\x76\xa9\x14' + sender_hash + b'\x88\xac'
        tx += var_int(len(change_script)) + change_script
    
    tx += struct.pack('<I', 0)
    
    signed_tx = b''
    signed_tx += struct.pack('<I', 2)
    signed_tx += var_int(len(selected_utxos))
    
    for i, utxo in enumerate(selected_utxos):
        sighash_preimage = b''
        sighash_preimage += struct.pack('<I', 2)
        sighash_preimage += var_int(len(selected_utxos))
        
        for j, u in enumerate(selected_utxos):
            sighash_preimage += bytes.fromhex(u['txid'])[::-1]
            sighash_preimage += struct.pack('<I', u['vout'])
            
            if i == j:
                prev_script = b'\x76\xa9\x14' + address_to_pubkey_hash(sender_address) + b'\x88\xac'
                sighash_preimage += var_int(len(prev_script)) + prev_script
            else:
                sighash_preimage += b'\x00'
            
            sighash_preimage += struct.pack('<I', 0xffffffff)
        
        sighash_preimage += var_int(output_count)
        sighash_preimage += struct.pack('<Q', amount)
        sighash_preimage += var_int(len(script_pubkey)) + script_pubkey
        
        if change > 546:
            sighash_preimage += struct.pack('<Q', change)
            sighash_preimage += var_int(len(change_script)) + change_script
        
        sighash_preimage += struct.pack('<I', 0)
        sighash_preimage += struct.pack('<I', 1)
        
        sighash = double_sha256(sighash_preimage)
        signature = sign_transaction(sighash, privkey) + b'\x01'
        
        script_sig = var_int(len(signature)) + signature
        script_sig += var_int(len(pubkey)) + pubkey
        
        signed_tx += bytes.fromhex(utxo['txid'])[::-1]
        signed_tx += struct.pack('<I', utxo['vout'])
        signed_tx += var_int(len(script_sig)) + script_sig
        signed_tx += struct.pack('<I', 0xffffffff)
    
    signed_tx += var_int(output_count)
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
    """Broadcast transaction via mempool.space Mainnet API without retries"""
    url = "https://mempool.space/api/tx"
    
    try:
        response = requests.post(url, data=tx_hex, headers={'Content-Type': 'text/plain'}, timeout=10)
        if response.status_code == 200:
            return response.text.strip()
        else:
            try:
                error_message = response.text.strip()
                print(f"Mainnet Tx Broadcasting Error (Status {response.status_code}): {error_message}")
            except:
                print(f"Mainnet Tx Broadcasting Error (Status {response.status_code}): Unable to parse error message")
            return None
    except Exception as e:
        print(f"Request Exception: {str(e)}")
        return None

def check_transaction_status(txid: str) -> Tuple[Dict, Optional[int], int, bool]:
    """Check transaction status in mempool, return status dict, HTTP status code, confirmations, and dropped flag"""
    url = f"https://mempool.space/api/tx/{txid}"
    tip_url = "https://mempool.space/api/blocks/tip/height"
    recent_blocks_url = "https://mempool.space/api/blocks/recent"
    
    max_retries = 5
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=10)
            status_code = response.status_code
            
            if status_code == 200:
                status = response.json()
                
                if not status.get('status', {}).get('confirmed', False):
                    return status, status_code, 0, False
                
                tx_block_height = status.get('status', {}).get('block_height', 0)
                if tx_block_height == 0:
                    return status, status_code, 0, False
                
                tip_response = requests.get(tip_url, timeout=10)
                if tip_response.status_code != 200:
                    return status, status_code, 0, False
                
                current_height = int(tip_response.text.strip())
                confirmations = current_height - tx_block_height + 1 if current_height >= tx_block_height else 0
                return status, status_code, max(0, confirmations), False
            
            elif status_code == 404:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                
                try:
                    recent_blocks_response = requests.get(recent_blocks_url, timeout=10)
                    if recent_blocks_response.status_code == 200:
                        recent_blocks = recent_blocks_response.json()
                        for block in recent_blocks[:5]:
                            block_txs_url = f"https://mempool.space/api/block/{block['id']}/txids"
                            block_txs_response = requests.get(block_txs_url, timeout=10)
                            if block_txs_response.status_code == 200 and txid in block_txs_response.json():
                                status_response = requests.get(url, timeout=10)
                                if status_response.status_code == 200:
                                    status = status_response.json()
                                    tx_block_height = status.get('status', {}).get('block_height', 0)
                                    tip_response = requests.get(tip_url, timeout=10)
                                    if tip_response.status_code == 200:
                                        current_height = int(tip_response.text.strip())
                                        confirmations = current_height - tx_block_height + 1 if current_height >= tx_block_height else 0
                                        return status, status_response.status_code, max(0, confirmations), False
                                return {}, status_code, 0, True
                        return {}, status_code, 0, True
                    else:
                        return {}, status_code, 0, True
                except Exception:
                    return {}, status_code, 0, True
            
            else:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                return {}, status_code, 0, False
        
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            return {}, None, 0, False
    
    return {}, None, 0, False

def main():
    print("=== Bitcoin P2WPKH Recipient Transaction Attacker ===")
    print("Network: Mainnet")
    print()
    
    privkey_hex = input("Enter Private Key: ").strip().lower()
    
    try:
        if len(privkey_hex) != 64:
            print("Error: Private Key Must Be Exactly 64 Hex Characters (256 bits)")
            return
        privkey = bytes.fromhex(privkey_hex)
        if len(privkey) != 32:
            print("Error: Private Key Must Be 32 Bytes (256 bits)")
            return
    except ValueError:
        print("Error: Invalid Hexadecimal Format - Use Only Characters 0-9 And a-f")
        return
    
    pubkey = privkey_to_pubkey(privkey)
    address = pubkey_to_p2pkh_address(pubkey)
    print(f"\nYour P2PKH Address: {address}")
    
    print("\nChoose UTXO source:")
    print("1. Fetch from Mempool")
    print("2. Load from utxos.json file")
    choice = input("Enter 1 or 2: ").strip()
    
    utxos = []
    if choice == '1':
        print("\nFetching UTXOs From Mempool...")
        utxos = fetch_utxos(address)
        if utxos:
            try:
                with open('utxos.json', 'w') as f:
                    json.dump(utxos, f, indent=2)
                print("utxos.json Updated With Fetched UTXOs")
            except Exception as e:
                print(f"Error Updating utxos.json: {e}")
        else:
            print("No UTXOs Found Via API")
            return
    elif choice == '2':
        if os.path.exists('utxos.json'):
            print("\nLoading UTXOs From utxos.json...")
            try:
                with open('utxos.json', 'r') as f:
                    utxos = json.load(f)
            except Exception as e:
                print(f"Error Loading UTXOs From File: {e}")
                return
        else:
            print("Error: utxos.json File Not Found")
            return
    else:
        print("Error: Invalid Choice. Please Enter 1 or 2")
        return
    
    if not utxos:
        print("No UTXOs found")
        return
    
    total_balance = sum(u['value'] for u in utxos)
    print(f"Found {len(utxos)} UTXOs")
    print(f"Total balance: {satoshi_to_btc(total_balance):.8f} BTC")
    
    recipient = input("\nEnter Recipient P2WPKH Address: ").strip()
    if not is_valid_p2wpkh_address(recipient):
        print(f"Error: Recipient Address Must Be A Valid Mainnet P2WPKH Address Starting With 'bc1q', got: {recipient}")
        return
    
    try:
        amount_btc = float(input("Enter Amount To Send (BTC): "))
        amount_satoshi = btc_to_satoshi(amount_btc)
        fee_btc = float(input("Enter Transaction Fee (BTC): "))
        fee_satoshi = btc_to_satoshi(fee_btc)
    except ValueError:
        print("Error: Invalid Amount Or Fee")
        return
    
    
    # Handle dust limit and funds check with automatic adjustment
    if total_balance < fee_satoshi:
        print(f"Error: Insufficient Balance To Cover The Tx Fee")
        print(f"Available Balance: {satoshi_to_btc(total_balance):.8f} BTC")
        print(f"Required Fee: {satoshi_to_btc(fee_satoshi):.8f} BTC")
        return
    if amount_satoshi < 546 or total_balance < amount_satoshi + fee_satoshi:
        amount_satoshi = max(546, total_balance - fee_satoshi)
    
    if amount_satoshi <= 0:
        print(f"Error: Insufficient Funds")
        print(f"Available Balance: {satoshi_to_btc(total_balance):.8f} BTC")
        print(f"Fee: {satoshi_to_btc(fee_satoshi):.8f} BTC")
        return
    
    print(f"\nCreating Tx...")
    print(f"Amount To Send: {satoshi_to_btc(amount_satoshi):.8f} BTC")
    print(f"Fee: {satoshi_to_btc(fee_satoshi):.8f} BTC")
    
    try:
        tx_hex, txid = create_raw_transaction(utxos, privkey, recipient, amount_satoshi, fee_satoshi)
        print(f"TXID: {txid}")
        
        print("\nBroadcasting Tx...")
        result = broadcast_transaction(tx_hex)
        
        if result:
            print(f"Tx Broadcasted Successfully!")
            current_txid = txid
            current_fee_satoshi = fee_satoshi
            
            print("\nMonitoring Tx Status...")
             
            while True:
                try:
                    time.sleep(5)
                    status, status_code, confirmations, is_dropped = check_transaction_status(current_txid)
                    
                    if confirmations >= 1:
                        print(f"\nTx Confirmed!")
                        print(f"Block Height: {status.get('status', {}).get('block_height', 'Unknown')}")
                        print(f"Confirmations: {confirmations}")
                        print(f"TXID: {current_txid}")v 
                        break
                    
                    elif is_dropped:
                        print(f"\n⚠️TX REPLACED!")
                        while True:
                            try:
                                new_fee_btc = input("Enter New Higher Tx Fee (BTC): ").strip()
                                if not new_fee_btc:
                                    print("Error: A New Tx Higher Fee is Required To Replace The Transaction")
                                    continue
                                
                                new_fee_btc = float(new_fee_btc)
                                new_fee_satoshi = btc_to_satoshi(new_fee_btc)
                                if new_fee_satoshi <= current_fee_satoshi:
                                    print(f"Error: New Fee ({satoshi_to_btc(new_fee_satoshi):.8f} BTC) Must Be Higher Than Previous Fee ({satoshi_to_btc(current_fee_satoshi):.8f} BTC)")
                                    continue
                                
                                # Load UTXOs from utxos.json for replacement transaction
                                if os.path.exists('utxos.json'):
                                    print("\nLoading UTXOs From utxos.json...")
                                    try:
                                        with open('utxos.json', 'r') as f:
                                            utxos = json.load(f)
                                    except Exception as e:
                                        print(f"Error Loading UTXOs From File: {e}")
                                        continue
                                else:
                                    print("Error: utxos.json File Not Found")
                                    continue
                                
                                if utxos:
                                    total_balance = sum(u['value'] for u in utxos)
                                    if total_balance < amount_satoshi + new_fee_satoshi:
                                        print(f"Error: Insufficient Funds For Replacement Transaction")
                                        print(f"Available balance: {satoshi_to_btc(total_balance):.8f} BTC")
                                        print(f"Required: {satoshi_to_btc(amount_satoshi):.8f} BTC")
                                        continue
                                
                                print("Creating Replacement Tx...")
                                continue
                                
                                tx_hex, txid = create_raw_transaction(utxos, privkey, recipient, amount_satoshi, new_fee_satoshi)
                                
                                print(f"New TXID: {txid}")
                                
                                result = broadcast_transaction(tx_hex)
                                
                                if result:
                                    print("Replacement Transaction Broadcast Successfully!")
                                    print(f"Amount To Send: {satoshi_to_btc(amount_satoshi):.8f} BTC")
                                    print(f"New Fee: {satoshi_to_btc(new_fee_satoshi):.8f} BTC")
                                    print("Continuing To Monitor For Confirmation...")
                                    current_txid = txid
                                    current_fee_satoshi = new_fee_satoshi
                                    break
                                else:
                                    print("Failed TX Broadcast Replacement Tx")
                                    continue
                            except ValueError:
                                print("Error: Invalid Fee Amount")
                                continue
                        continue
                
                except KeyboardInterrupt:
                    print(f"\n\nMonitoring Stopped.")
                    break
                except Exception as e:
                    print(f"\nError Checking Tx Status: {e}")
                    time.sleep(5)
        
        else:
            print("Failed To Broadcast Tx")
    
    except Exception as e:
        print(f"Error Creating Tx: {e}")

if __name__ == "__main__":
    main()
