import hashlib
import itertools

def verify_md5hash(plain1: bytes, candidate: bytes) -> bool:
    return hashlib.md5(plain1).digest() == hashlib.md5(candidate).digest() and plain1 != candidate

def md5hash_collision(plain2: bytes, plain1: bytes):
    byte_array = bytearray(plain2)
    for b19, b45, b59 in itertools.product(range(256), repeat=3):
        byte_array[19] = b19
        byte_array[45] = b45
        byte_array[59] = b59
        candidate = bytes(byte_array)
        if verify_md5hash(plain1, candidate):
            return candidate
    return None
