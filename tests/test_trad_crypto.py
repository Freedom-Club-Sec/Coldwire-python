# tests/test_trad_crypto.py
"""
    Tests for XChaCha20Poly1305 encryption & decryption and Argon2id key derivation.
    Focus: Correctness of encryption & decryption flow and tamper detection.
"""

import pytest
from core.trad_crypto import (
        encrypt_xchacha20poly1305,
        decrypt_xchacha20poly1305,
        derive_key_argon2id
)
from core.constants import (
        ARGON2ID_OUTPUT_LEN,
        ARGON2_SALT_LEN,
)


def test_aes_encrypt_decrypt():
    # Test input data
    data = b"Hello, World!"
    password = b"Password123"

    # Derive AES-256 key using Argon2id
    key, salt = derive_key_argon2id(password)
    assert key != salt, "Derived key should not equal derived salt"
    assert key != password, "Derived key should not match plaintext password"
    assert data != key, "Derived key should not match data"
    assert data != salt, "Derived salt should not match data"
    assert len(key) == ARGON2ID_OUTPUT_LEN, "key length does not match constant length"
    assert len(salt) == ARGON2ID_SALT_LEN, "salt length does not match constant length"

    key = key[:32]

    # Encrypt plaintext using xChaCha20Poly1305
    nonce, ciphertext = encrypt_xchacha20poly1305(key, data)
    assert nonce != ciphertext, "Nonce and ciphertext should not be equal"
    assert ciphertext != data, "Ciphertext should differ from plaintext"

    # Decrypt ciphertext and verify correctness
    plaintext = decrypt_xchacha20poly1305(key, nonce, ciphertext)
    assert plaintext == data, "Decrypted plaintext does not match original"

    # Tampering test: Modify ciphertext and expect decryption failure
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[-1] ^= 0xFF  # Flip last byte to corrupt data

    with pytest.raises(Exception):
        decrypt_aes_gcm(key, nonce, bytes(tampered_ciphertext))

