from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import itertools
import io

def generate_dsa_keypair(bits=2048):
    key = DSA.generate(bits)
    return key.export_key(), key.publickey().export_key()

def sign_message(message: str, private_key_pem: bytes) -> bytes:
    private_key = DSA.import_key(private_key_pem)
    hash_obj = SHA256.new(message.encode())
    signer = DSS.new(private_key, 'fips-186-3')
    return signer.sign(hash_obj)

def verify_signature(message: str, signature: bytes, public_key_pem: bytes) -> bool:
    public_key = DSA.import_key(public_key_pem)
    hash_obj = SHA256.new(message.encode())
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False

def verify_key(key: str) -> bool:
    try:
        DSA.import_key(io.StringIO(key).getvalue())
        return True
    except ValueError:
        return False

def bruteforce_dsa_key(key_with_error: str) -> str:
    for permutation in itertools.product('abcdefghijklmnopqrstuvwxyz0123456789', repeat=2):
        candidate = key_with_error[:54] + ''.join(permutation) + key_with_error[56:]
        if verify_key(candidate):
            return candidate
    return None
