# tests/test_crypto.py
"""
Tests for ML-KEM-1024 (Kyber) and ML-DSA-87 (Dilithium5).
Covers:
- Key generation conformance to NIST spec
- OTP encryption using Kyber key exchange
- Hash chain tamper detection
"""

import pytest
from core.crypto import (
    generate_kem_keys,
    generate_sign_keys,
    generate_kyber_shared_secrets,
    decrypt_kyber_shared_secrets,
    otp_encrypt_with_padding,
    otp_decrypt_with_padding
)
from core.constants import (
    OTP_PADDING_LIMIT,
    OTP_PADDING_LENGTH
)
from core.trad_crypto import sha3_512

# NIST-specified key sizes (bytes)
ML_KEM_1024_SK_LEN = 3168
ML_KEM_1024_PK_LEN = 1568
ML_DSA_87_SK_LEN   = 4864
ML_DSA_87_PK_LEN   = 2592
HASH_SIZE          = 64     # SHA3-512 output size in bytes


def test_mlkem_keygen_basic():
    """Validate ML-KEM-1024 key generation: uniqueness, type, and length."""
    seen_private_keys = set()
    seen_public_keys  = set()

    for _ in range(100):
        private_key, public_key = generate_kem_keys(algorithm="Kyber1024")

        assert private_key not in seen_private_keys, "Duplicate private key detected"
        assert public_key not in seen_public_keys,  "Duplicate public key detected"

        assert private_key != public_key, "Private and public keys must differ"
        assert isinstance(private_key, bytes) and isinstance(public_key, bytes), "Keys must be bytes"
        assert len(private_key) == ML_KEM_1024_SK_LEN, "Private key length mismatch with spec"
        assert len(public_key)  == ML_KEM_1024_PK_LEN, "Public key length mismatch with spec"

        seen_private_keys.add(private_key)
        seen_public_keys.add(public_key)


def test_mldsa_keygen_basic():
    """Validate ML-DSA-87 key generation: uniqueness, type, and length."""
    seen_private_keys = set()
    seen_public_keys  = set()

    for _ in range(100):
        private_key, public_key = generate_sign_keys(algorithm="Dilithium5")

        assert private_key not in seen_private_keys, "Duplicate private key detected"
        assert public_key not in seen_public_keys,  "Duplicate public key detected"

        assert private_key != public_key, "Private and public keys must differ"
        assert isinstance(private_key, bytes) and isinstance(public_key, bytes), "Keys must be bytes"
        assert len(private_key) == ML_DSA_87_SK_LEN, "Private key length mismatch with spec"
        assert len(public_key)  == ML_DSA_87_PK_LEN, "Public key length mismatch with spec"

        seen_private_keys.add(private_key)
        seen_public_keys.add(public_key)


def test_kem_otp_encryption():
    """Full Kyber OTP exchange and tamper detection test."""
    # Alice creates ephemeral ML-KEM-1024 keypair for PFS
    alice_private_key, alice_public_key = generate_kem_keys()

    # Bob creates his own ephemeral keypair
    bob_private_key, bob_public_key = generate_kem_keys()

    # Bob derives shared pads from Alice's public key
    ciphertext, bob_pads = generate_kyber_shared_secrets(alice_public_key)
    assert ciphertext != bob_pads, "Ciphertext equals pads (should differ)"

    # First 64 bytes are hash chain seed
    bob_hash_chain_seed = bob_pads[:HASH_SIZE]

    # Alice decrypts ciphertext to recover shared pads
    plaintext = decrypt_kyber_shared_secrets(ciphertext, alice_private_key)
    assert plaintext == bob_pads, "Pads mismatch after decryption"

    # Bob encrypts a message using OTP with hash chain
    message = "Hello, World!"
    message_encoded     = message.encode("utf-8")
    bob_next_hash_chain = sha3_512(bob_hash_chain_seed + message_encoded)
    message_encoded     = bob_next_hash_chain + message_encoded

    pad_len   = max(0, OTP_PADDING_LIMIT - OTP_PADDING_LENGTH - len(message_encoded))
    otp_pad   = bob_pads[:len(message_encoded) + OTP_PADDING_LENGTH + pad_len]
    encrypted = otp_encrypt_with_padding(message_encoded, otp_pad, padding_limit=pad_len)

    assert encrypted != message_encoded, "Ciphertext equals plaintext"
    assert len(encrypted) == len(otp_pad), "Ciphertext length mismatch"

    # Alice decrypts and validates hash chain
    decrypted      = otp_decrypt_with_padding(encrypted, plaintext[:len(encrypted)])
    recv_hash      = decrypted[:HASH_SIZE]
    recv_plaintext = decrypted[HASH_SIZE:]
    assert recv_plaintext.decode() == message, "Decrypted message mismatch"

    calc_next_hash = sha3_512(bob_hash_chain_seed + recv_plaintext)
    assert calc_next_hash == recv_hash, "Hash chain verification failed"

    # Tampering test: flip a byte
    tampered_message = bytearray(encrypted)
    tampered_message[65] ^= 0xFF

    tampered_decrypted = otp_decrypt_with_padding(bytes(tampered_message), plaintext[:len(encrypted)])
    tampered_hash      = tampered_decrypted[:HASH_SIZE]
    tampered_plaintext = tampered_decrypted[HASH_SIZE:]

    calc_tampered_hash = sha3_512(bob_hash_chain_seed + tampered_plaintext)
    assert calc_tampered_hash != tampered_hash, "Tampering not detected"
