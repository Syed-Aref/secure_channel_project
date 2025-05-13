import hmac
import hashlib

def generate_mac(message: bytes, secret_key: bytes, hash_func=hashlib.sha256) -> bytes:
    return hmac.new(secret_key, message, hash_func).digest()

def verify_mac(message: bytes, mac: bytes, secret_key: bytes, hash_func=hashlib.sha256) -> bool:
    expected_mac = generate_mac(message, secret_key, hash_func)
    return hmac.compare_digest(mac, expected_mac)
