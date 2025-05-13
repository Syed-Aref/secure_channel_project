from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_keypair(n_bits):
    key = RSA.generate(n_bits)
    return key.export_key(), key.publickey().export_key()

def rsa_encrypt(message: str, pubkey: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(RSA.import_key(pubkey))
    return cipher.encrypt(message.encode())

def rsa_decrypt(ciphertext: bytes, privkey: bytes) -> str:
    cipher = PKCS1_OAEP.new(RSA.import_key(privkey))
    return cipher.decrypt(ciphertext).decode()