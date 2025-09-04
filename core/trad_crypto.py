"""
core/trad_crypto.py
-------
Provides wrappers for cryptographic primitives:
- SHA3-512 hashing
- Argon2id key derivation for XChaCha20Poly1305 keys
- XChaCha20Poly1305 encryption and decryption
These functions rely on the cryptography library and are intended for use within Coldwire's higher-level protocol logic.
"""

from nacl import pwhash, bindings
from core.constants import (
    OTP_PAD_SIZE,
    XCHACHA20POLY1305_NONCE_LEN,
    XCHACHA20POLY1305_SIZE_LEN,
    XCHACHA20POLY1305_MAX_RANODM_PAD,
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


def encrypt_xchacha20poly1305(key: bytes, plaintext: bytes, nonce: bytes = None, counter: int = None, counter_safety: int = 255, max_padding: int = XCHACHA20POLY1305_MAX_RANODM_PAD) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using XChaCha20Poly1305.

    A random nonce is generated for each encryption unless you specify one.

    Args:
        key: A 32-byte XChaCha20Poly1305 key.
        plaintext: Data to encrypt.
        nonce: An (optional) nonce to be used.
        counter: an (optional) number to add to nonce
        counter_safety: an (optional) max counter number, to prevent counter overflow.
        max_padding: an (optional) maximum padding limit number to message. Cannot be larger than what `XCHACHA20POLY1305_MAX_RANODM_PAD` could store. Set to 0 for no padding.
    Returns:
        A tuple (nonce, ciphertext) where:
        - nonce: The randomly generated nonce or the same given nonce.
        - ciphertext: The encrypted data including the authentication tag.
    """
    if nonce is None:
        nonce = sha3_512(secrets.token_bytes(XCHACHA20POLY1305_NONCE_LEN))[:XCHACHA20POLY1305_NONCE_LEN]

    if counter is not None:
        if counter > counter_safety:
            raise ValueError("ChaCha counter has overflowen")

        nonce = nonce[:XCHACHA20POLY1305_NONCE_LEN - 1] + counter.to_bytes(1, "big")

    if max_padding < 0:
        raise ValueError(f"Max_padding is less than 0! ({max_padding})")

    if max_padding > 2 ** (XCHACHA20POLY1305_SIZE_LEN * 8) - 1:
        raise ValueError(f"Max_padding is more than ``XCHACHA20POLY1305_SIZE_LEN`! ({max_padding})")

    padding = secrets.token_bytes(secrets.randbelow(max_padding + 1))
    padding_length_bytes = len(padding).to_bytes(XCHACHA20POLY1305_SIZE_LEN, "big")

    padded_plaintext = padding_length_bytes + plaintext + padding


    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(padded_plaintext, None, nonce, key) 

    return nonce, ciphertext


def decrypt_xchacha20poly1305(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using XChaCha20Poly1305.

    Raises an exception if authentication fails.

    Args:
        key: The 32-byte XChaCha20Poly1305 key used for encryption.
        nonce: The nonce used during encryption.
        ciphertext: The encrypted data including the authentication tag.

    Returns:
        The decrypted plaintext bytes with no padding.
    """

    padded_plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, None, nonce, key)

    padding_length = int.from_bytes(padded_plaintext[:XCHACHA20POLY1305_SIZE_LEN], "big")

    if padding_length < 0:
        raise ValueError(f"Negative padding length ({padding_length}), ciphertext likely corrupted, or key is invalid!")

    return padded_plaintext[XCHACHA20POLY1305_SIZE_LEN : -padding_length]



