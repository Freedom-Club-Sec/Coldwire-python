"""
core/trad_crypto.py
-------
Provides wrappers for cryptographic primitives:
- SHA3-512 hashing
- Argon2id key derivation for AES-256 keys
- AES-256-GCM encryption and decryption
These functions rely on the cryptography library and are intended for use within Coldwire's higher-level protocol logic.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from core.constants import (
    OTP_PAD_SIZE,
    AES_GCM_NONCE_LEN,
    ARGON2_ITERS,
    ARGON2_MEMORY,
    ARGON2_LANES,
    ARGON2_OUTPUT_LEN,
    ARGON2_SALT_LEN
)
import hashlib
import secrets



def sha3_512(data: bytes) -> bytes:
    """
    Compute a SHA3-512 hash of the given data.

    Args:
        data: Input bytes to hash.

    Returns:
        A 64-byte SHA3-512 digest.
    """
    h = hashlib.sha3_512()
    h.update(data)
    return h.digest()


def derive_key_argon2id(password: bytes, salt: bytes = None, salt_length: int = ARGON2_SALT_LEN, output_length: int = ARGON2_OUTPUT_LEN) -> tuple[bytes, bytes]:
    """
    Derive a symmetric key from a password using Argon2id.

    If no salt is provided, a new random salt is generated.

    Args:
        password: User-provided password bytes.
        salt: Optional salt bytes; must be of length salt_length.
        salt_length: Length of salt to generate if none is provided.
        output_length: Desired length of derived key.

    Returns:
        A tuple (derived_key, salt) where:
        - derived_key: The Argon2id-derived key of output_length bytes.
        - salt: The salt used for derivation.
    """
    if salt is None:
        salt = secrets.token_bytes(salt_length)

    kdf = Argon2id(
        salt=salt,
        iterations=ARGON2_ITERS,
        memory_cost=ARGON2_MEMORY,
        length=output_length,
        lanes=ARGON2_LANES
    )
    derived_key = kdf.derive(password)
    return derived_key, salt


def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256 in GCM mode.

    A random nonce is generated for each encryption.

    Args:
        key: A 32-byte AES key.
        plaintext: Data to encrypt.

    Returns:
        A tuple (nonce, ciphertext) where:
        - nonce: The randomly generated AES-GCM nonce.
        - ciphertext: The encrypted data including the authentication tag.
    """
    nonce = secrets.token_bytes(AES_GCM_NONCE_LEN)
    aes_gcm = AESGCM(key)
    ciphertext = aes_gcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-256 in GCM mode.

    Raises an exception if authentication fails.

    Args:
        key: The 32-byte AES key used for encryption.
        nonce: The nonce used during encryption.
        ciphertext: The encrypted data including the authentication tag.

    Returns:
        The decrypted plaintext bytes.
    """
    aes_gcm = AESGCM(key)
    return aes_gcm.decrypt(nonce, ciphertext, None)


