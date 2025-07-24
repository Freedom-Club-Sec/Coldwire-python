from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import hashlib
import secrets 

def sha3_512(b: bytes) -> bytes:
    h = hashlib.sha3_512()
    h.update(b)
    return h.digest()

def derive_key_argon2id(password: bytes, salt: bytes = None, salt_length: int = 32, output_length: int = 32) -> tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(salt_length)

    kdf = Argon2id(
        salt=salt,
        iterations=1,
        memory_cost=262144,
        length=output_length,
        lanes=4
    )
    return kdf.derive(password), salt

"""
def derive_key_scrypt(password: bytes, salt: bytes = None, salt_length: int = 32) -> tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(salt_length)

    key = hashlib.scrypt(
        password,
        salt=salt,
        n=2**15,  # CPU/memory cost
        r=8,      # block size
        p=1,      # parallelization
        dklen=32  # desired key length
    )
    return key, salt
"""

def encrypt_aes_gcm(key: bytes, plaintext: bytes):
    nonce = get_random_bytes(12)  # GCM standard nonce size
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)
