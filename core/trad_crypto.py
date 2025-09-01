"""
core/trad_crypto.py
-------
Provides wrappers for cryptographic primitives:
- SHA3-512 hashing
- Argon2id key derivation for AES-256 keys
- AES-256-GCM encryption and decryption
These functions rely on the cryptography library and are intended for use within Coldwire's higher-level protocol logic.
"""

from nacl import pwhash, bindings
from core.constants import (
    OTP_PAD_SIZE,
    XCHACHA20POLY1305_NONCE_LEN,
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


def derive_key_argon2id(password: bytes, salt: bytes = None, output_length: int = ARGON2_OUTPUT_LEN) -> tuple[bytes, bytes]:
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
        salt = secrets.token_bytes(ARGON2_SALT_LEN)

    return pwhash.argon2id.kdf(
        output_length, 
        password,
        salt,
        opslimit = ARGON2_ITERS,
        memlimit = ARGON2_MEMORY
    ), salt


def encrypt_xchacha20poly1305(key: bytes, plaintext: bytes, counter: int = None, counter_safety: int = 2 ** 32) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using ChaCha20Poly1305.

    A random nonce is generated for each encryption.

    Args:
        key: A 32-byte ChaCha20Poly1305 key.
        plaintext: Data to encrypt.
        counter: an (optional) number to add to nonce

    Returns:
        A tuple (nonce, ciphertext) where:
        - nonce: The randomly generated AES-GCM nonce.
        - ciphertext: The encrypted data including the authentication tag.
    """
    nonce = secrets.token_bytes(XCHACHA20POLY1305_NONCE_LEN)
    if counter is not None:
        if counter > counter_safety:
            raise ValueError("ChaCha counter has overflowen")

        nonce = nonce[:XCHACHA20POLY1305_NONCE_LEN - 4] + counter.to_bytes(4, "big")

    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, nonce, key) 

    return nonce, ciphertext


def decrypt_xchacha20poly1305(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using ChaCha20Poly1305.

    Raises an exception if authentication fails.

    Args:
        key: The 32-byte ChaCha20Poly1305 key used for encryption.
        nonce: The nonce used during encryption.
        ciphertext: The encrypted data including the authentication tag.

    Returns:
        The decrypted plaintext bytes.
    """

    return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, None, nonce, key)


