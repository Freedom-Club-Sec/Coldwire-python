from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from core.constants import *
import hashlib
import secrets 

def sha3_512(b: bytes) -> bytes:
    h = hashlib.sha3_512()
    h.update(b)
    return h.digest()

def derive_key_argon2id(password: bytes, salt: bytes = None, salt_length: int = ARGON2_SALT_LEN, output_length: int = ARGON2_OUTPUT_LEN) -> tuple[bytes, bytes]:
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



def encrypt_aes_gcm(key: bytes, plaintext: bytes):
    nonce = secrets.token_bytes(AES_GCM_NONCE_LEN)  
    aes_gcm = AESGCM(key)
    ciphertext = aes_gcm.encrypt(nonce, plaintext, None)

    return nonce, ciphertext

def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes):
    aes_gcm = AESGCM(key)
    return aes_gcm.decrypt(nonce, ciphertext, None)


