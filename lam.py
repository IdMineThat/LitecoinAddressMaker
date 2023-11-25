import hashlib
import base58
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import requests
import json

def password_to_private_key(password):
    # Use a hash function (e.g., SHA-256) to derive a key from the password
    key = hashlib.sha256(password.encode('utf-8')).digest()

    # Use the derived key as a seed for the ECDSA signing key
    private_key = SigningKey.from_string(key, curve=SECP256k1)

    return private_key

def private_key_to_public_key(private_key):
    # Get the corresponding public key
    public_key = private_key.verifying_key
    public_key_bytes = public_key.to_string('compressed')
    
    return public_key_bytes

def public_key_to_address(public_key):
    # Hash the public key using SHA-256 and then RIPEMD-160
    hashed_public_key = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()

    # Add the version byte for mainnet (0x00) or testnet (0x6f)
    version_byte = b'\x30'  # for mainnet
    hashed_public_key_with_version = version_byte + hashed_public_key

    # Perform double SHA-256 hash to get the checksum
    checksum = hashlib.sha256(hashlib.sha256(hashed_public_key_with_version).digest()).digest()[:4]

    # Concatenate the hashed public key with the checksum
    address_data = hashed_public_key_with_version + checksum

    # Convert the address to base58
    bitcoin_address = base58.b58encode(address_data).decode('utf-8')

    return bitcoin_address

def private_key_to_wifc(private_key):
    # Get the private key as bytes
    private_key_bytes = private_key.to_string()

    # Add the version byte (0x80 for mainnet)
    version_byte = b'\xb0'

    # Add the compression flag (0x01) for compressed public key
    compression_flag = b'\x01'

    # Concatenate the version byte, private key, and compression flag
    wifc_data = version_byte + private_key_bytes + compression_flag

    # Perform double SHA-256 hash to get the checksum
    checksum = hashlib.sha256(hashlib.sha256(wifc_data).digest()).digest()[:4]

    # Concatenate the WIFC data with the checksum
    wifc_key = base58.b58encode(wifc_data + checksum).decode('utf-8')

    return wifc_key

# Example usage
balance = 0
while balance == 0:
    password = input('enter password:')
    private_key = password_to_private_key(password)
    public_key = private_key_to_public_key(private_key)
    bitcoin_address = public_key_to_address(public_key)
    wifc_key = private_key_to_wifc(private_key)

    print("Litecoin Address:", bitcoin_address)
    print("Private Key (hex):", private_key.to_string().hex())
    print("WIFC Key:", wifc_key)

    f = open("/home/ltc_list.csv", "a")
    f.write(bitcoin_address + ',' + wifc_key + '\n')
    f.close()
