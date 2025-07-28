# tests/test_trad_crypto.py
"""
    Tests for AES-256 GCM encryption/decryption and Argon2id key derivation.
    Focus: Correctness of encryption/decryption flow and tamper detection.
"""

import pytest
from core.trad_crypto import (
        encrypt_aes_gcm,
        decrypt_aes_gcm,
        derive_key_argon2id
)


def test_aes_encrypt_decrypt():
    # Test input data
    data = b"Hello, World!"
    password = b"Password123"

    # Derive AES-256 key using Argon2id
    key, salt = derive_key_argon2id(password)
    assert key != salt, "Derived key should not equal derived salt"
    assert key != password, "Derived key should not match plaintext password"

    # Encrypt plaintext using AES-GCM
    nonce, ciphertext = encrypt_aes_gcm(key, data)
    assert nonce != ciphertext, "Nonce and ciphertext should not be equal"
    assert ciphertext != data, "Ciphertext should differ from plaintext"

    # Decrypt ciphertext and verify correctness
    plaintext = decrypt_aes_gcm(key, nonce, ciphertext)
    assert plaintext == data, "Decrypted plaintext does not match original"

    # Tampering test: Modify ciphertext and expect decryption failure
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[-1] ^= 0xFF  # Flip last byte to corrupt data

    with pytest.raises(Exception):
        decrypt_aes_gcm(key, nonce, bytes(tampered_ciphertext))

