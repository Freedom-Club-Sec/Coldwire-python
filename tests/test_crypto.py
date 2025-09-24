# tests/test_crypto.py
"""
Tests for ML-KEM-1024, ML-DSA-87, Classic-McEliece-8192128f.
Covers:
- Key generation conformance to NIST spec
- Signature generation and verification
- OTP encryption using Kyber key exchange
- Hash chain tamper detection
"""

from core.crypto import (
    generate_kem_keys,
    generate_sign_keys,
    create_signature,
    verify_signature,
    generate_shared_secrets,
    decrypt_shared_secrets,
    otp_encrypt_with_padding,
    otp_decrypt_with_padding,
    random_number_range
)
from core.constants import (
    OTP_SIZE_LENGTH,
    OTP_MAX_BUCKET,
    ML_KEM_1024_NAME,
    ML_KEM_1024_SK_LEN,
    ML_KEM_1024_PK_LEN,
    ML_DSA_87_NAME,  
    ML_DSA_87_SK_LEN,
    ML_DSA_87_PK_LEN,
    ML_DSA_87_SIGN_LEN,

    CLASSIC_MCELIECE_8_F_NAME,
    CLASSIC_MCELIECE_8_F_SK_LEN, 
    CLASSIC_MCELIECE_8_F_PK_LEN,
    CLASSIC_MCELIECE_8_F_CT_LEN 

)


def test_random_number_range():
    min_val, max_val = 10, 1000

    # Check multiple values fall in range
    for _ in range(10000):
        num = random_number_range(min_val, max_val)
        assert min_val <= num <= max_val, f"{num} out of range {min_val}-{max_val}"


def test_mlkem_keygen_basic():
    """Validate ML-KEM-1024 key generation: uniqueness, type, and length."""
    seen_private_keys = set()
    seen_public_keys  = set()

    for _ in range(10):
        private_key, public_key = generate_kem_keys(ML_KEM_1024_NAME)

        assert private_key not in seen_private_keys, "Duplicate private key detected"
        assert public_key not in seen_public_keys,  "Duplicate public key detected"

        assert private_key != public_key, "Private and public keys must differ"
        assert isinstance(private_key, bytes) and isinstance(public_key, bytes), "Keys must be bytes"
        assert len(private_key) == ML_KEM_1024_SK_LEN, "Private key length mismatch with spec"
        assert len(public_key)  == ML_KEM_1024_PK_LEN, "Public key length mismatch with spec"

        seen_private_keys.add(private_key)
        seen_public_keys.add(public_key)


def test_mceliece_keygen_basic():
    """Validate ML-KEM-1024 key generation: uniqueness, type, and length."""
    seen_private_keys = set()
    seen_public_keys  = set()

    for _ in range(10):
        private_key, public_key = generate_kem_keys(CLASSIC_MCELIECE_8_F_NAME)

        assert private_key not in seen_private_keys, "Duplicate private key detected"
        assert public_key not in seen_public_keys,  "Duplicate public key detected"

        assert private_key != public_key, "Private and public keys must differ"
        assert isinstance(private_key, bytes) and isinstance(public_key, bytes), "Keys must be bytes"
        assert len(private_key) == CLASSIC_MCELIECE_8_F_SK_LEN, "Private key length mismatch with spec"
        assert len(public_key)  == CLASSIC_MCELIECE_8_F_PK_LEN, "Public key length mismatch with spec"

        seen_private_keys.add(private_key)
        seen_public_keys.add(public_key)


def test_mldsa_keygen_basic():
    """Validate ML-DSA-87 key generation: uniqueness, type, and length."""
    seen_private_keys = set()
    seen_public_keys  = set()

    for _ in range(10):
        private_key, public_key = generate_sign_keys(algorithm=ML_DSA_87_NAME)

        assert private_key not in seen_private_keys, "Duplicate private key detected"
        assert public_key not in seen_public_keys,  "Duplicate public key detected"

        assert private_key != public_key, "Private and public keys are identical"
        assert isinstance(private_key, bytes) and isinstance(public_key, bytes), "Keys must be bytes"
        assert len(private_key) == ML_DSA_87_SK_LEN, "Private key length mismatch with spec"
        assert len(public_key)  == ML_DSA_87_PK_LEN, "Public key length mismatch with spec"

        seen_private_keys.add(private_key)
        seen_public_keys.add(public_key)


def test_signature_verifcation():
    """Validate ML-DSA-87 signature creation and verification"""
    private_key, public_key = generate_sign_keys(algorithm=ML_DSA_87_NAME)

    assert private_key != public_key, "Private and public keys are identical"

    message = "Hello, World!".encode("utf-8")
    signature = create_signature(ML_DSA_87_NAME, message, private_key)

    assert isinstance(signature, bytes), "Signature must be bytes"
    assert len(signature) == ML_DSA_87_SIGN_LEN, "Signature length mismatch with spec"
    
    verify = verify_signature(ML_DSA_87_NAME, message, signature, public_key)

    assert isinstance(verify, bool), "Verification result must be bool"
    assert verify == True, "Verification failed"

    message = "Hi, World!".encode()
    verify = verify_signature(ML_DSA_87_NAME, message, signature, public_key)

    assert isinstance(verify, bool), "Verification result must be bool"
    assert verify == False, "Verification shouldn't have succeeded"



def test_kem_otp_encryption():
    """ML-KEM-1024 OTP pad derivation and encryption test."""
    # Alice creates ephemeral ML-KEM-1024 keypair for PFS
    alice_private_key, alice_public_key = generate_kem_keys(ML_KEM_1024_NAME)

    # Bob creates his own ephemeral keypair
    bob_private_key, bob_public_key = generate_kem_keys(ML_KEM_1024_NAME)

    # Bob derives shared pads from Alice's public key
    ciphertext, bob_pads = generate_shared_secrets(alice_public_key, ML_KEM_1024_NAME)
    assert ciphertext != bob_pads, "Ciphertext equals pads (should differ)"

    # First 64 bytes are hash chain seed
    # bob_hash_chain_seed = bob_pads[:HASH_SIZE]

    # Alice decrypts ciphertext to recover shared pads
    plaintext = decrypt_shared_secrets(ciphertext, alice_private_key, ML_KEM_1024_NAME)
    assert plaintext == bob_pads, "Pads mismatch after decryption"
    assert plaintext != ciphertext, "Pads equals Bobs ciphertext"

    # Bob encrypts a message using OTP with hash chain
    message_encoded = "Hello, World!".encode("utf-8")

    encrypted_message, new_pads = otp_encrypt_with_padding(message_encoded, bob_pads)

    assert encrypted_message != message_encoded, "Ciphertext equals message"
    assert new_pads != bob_pads, "Pads did not get truncated after use!"
    assert len(encrypted_message) == len(message_encoded) + (OTP_MAX_BUCKET - len(message_encoded)), "Encrypted message length does not match expected length"


    # Alice decrypts and validates hash chain
    decrypted_message = otp_decrypt_with_padding(encrypted_message, plaintext[:len(encrypted_message)])
    assert decrypted_message == message_encoded, "Decrypted message mismatch"

    # calc_next_hash = sha3_512(bob_hash_chain_seed + recv_plaintext)
    # assert calc_next_hash == recv_hash, "Hash chain verification failed"

    # Temporarily disabled until I make new, improved tests.
    """
    # Tampering test: flip a byte
    tampered_message = bytearray(encrypted)
    tampered_message[HASH_SIZE + 1] ^= 0xFF

    tampered_decrypted = otp_decrypt_with_padding(bytes(tampered_message), plaintext[:len(encrypted)])
    tampered_hash      = tampered_decrypted[:HASH_SIZE]
    tampered_plaintext = tampered_decrypted[HASH_SIZE:]

    calc_tampered_hash = sha3_512(bob_hash_chain_seed + tampered_plaintext)
    assert calc_tampered_hash != tampered_hash, "Tampering not detected"
    """
