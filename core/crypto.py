"""
core/crypto
-----------
Post-quantum cryptographic operations for Coldwire.

Implements:
- Key generation (ML-KEM-1024 / Kyber, ML-DSA-87 / Dilithium5)
- Signature creation and verification
- One-Time Pad (OTP) encryption with padding
- Kyber-based OTP key exchange
- Secure random number generation

Notes:
- Kyber keys and ciphertext sizes follow NIST spec for ML-KEM-1024.
- Dilithium5 keys/signature sizes follow NIST spec for ML-DSA-87.
- OTP padding randomizes message lengths to resist ciphertext length analysis.
"""

import oqs
import secrets
from core.constants import (
    OTP_PAD_SIZE,
    OTP_PADDING_LENGTH,
    ML_KEM_1024_NAME,
    ML_KEM_1024_SK_LEN,
    ML_KEM_1024_PK_LEN,
    ML_DSA_87_NAME,
    ML_DSA_87_SK_LEN,
    ML_DSA_87_PK_LEN,
    ML_DSA_87_SIGN_LEN,
    ML_BUFFER_LIMITS
)


def create_signature(algorithm: str, message: bytes, private_key: bytes) -> bytes:
    """
    Creates a digital signature for a message using a post-quantum signature scheme.

    Args:
        algorithm: PQ signature algorithm (e.g. "Dilithium5").
        message: Data to sign.
        private_key: Private key bytes.

    Returns:
        Signature bytes of fixed size defined by the algorithm.
    """
    with oqs.Signature(algorithm, secret_key = private_key[:ML_BUFFER_LIMITS[algorithm]["SK_LEN"]]) as signer:
        return signer.sign(message)

def verify_signature(algorithm: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verifies a post-quantum signature.

    Args:
        algorithm: PQ signature algorithm (e.g. "Dilithium5").
        message: Original message data.
        signature: Signature to verify.
        public_key: Corresponding public key bytes.

    Returns:
        True if valid, False if invalid.
    """
    with oqs.Signature(algorithm) as verifier:
        return verifier.verify(message, signature, public_key[:ML_BUFFER_LIMITS[algorithm]["PK_LEN"]])

def generate_sign_keys(algorithm: str = ML_DSA_87_NAME):
    """
    Generates a new post-quantum signature keypair.

    Args:
        algorithm: PQ signature algorithm (default ML-DSA-87 / Dilithium5).

    Returns:
        (private_key, public_key) as bytes.
    """
    with oqs.Signature(algorithm) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
        return private_key, public_key

def otp_encrypt_with_padding(plaintext: bytes, key: bytes, padding_limit: int) -> bytes:
    """
    Encrypts plaintext using a one-time pad with random padding.

    Process:
    - Prefixes length of padding.
    - Adds random padding (0..padding_limit bytes).
    - XORs with one-time pad key.

    Args:
        plaintext: Data to encrypt.
        key: OTP key (≥ plaintext length + padding).
        padding_limit: Max padding length.

    Returns:
        Ciphertext bytes.
    """
    if padding_limit > ((2 ** (8 * OTP_PADDING_LENGTH)) - 1):
        raise ValueError("Padding too large")

    plaintext_padding = secrets.token_bytes(padding_limit)
    padding_length_bytes = len(plaintext_padding).to_bytes(OTP_PADDING_LENGTH, "big")
    padded_plaintext = padding_length_bytes + plaintext + plaintext_padding
    return one_time_pad(padded_plaintext, key)

def otp_decrypt_with_padding(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts one-time pad ciphertext that contains prefixed padding length.

    Args:
        ciphertext: Ciphertext bytes.
        key: OTP key (≥ ciphertext length).

    Returns:
        Original plaintext bytes without padding.
    """
    plaintext_with_padding = one_time_pad(ciphertext, key)
    padding_length = int.from_bytes(plaintext_with_padding[:OTP_PADDING_LENGTH], "big")
    if padding_length != 0:
        return plaintext_with_padding[OTP_PADDING_LENGTH : -padding_length]
    return plaintext_with_padding[OTP_PADDING_LENGTH:]

def one_time_pad(plaintext: bytes, key: bytes) -> bytes:
    """
    XOR-based One-Time Pad encryption/decryption.

    Args:
        plaintext: Input data.
        key: Random key (equal or longer length).

    Returns:
        XORed result (ciphertext or plaintext).
    """
    otpd_plaintext = b''
    for index, plain_byte in enumerate(plaintext):
        key_byte = key[index]
        otpd_plaintext += bytes([plain_byte ^ key_byte])
    return otpd_plaintext

def generate_kem_keys(algorithm: str = ML_KEM_1024_NAME):
    """
    Generates ML-KEM-1024 keypair (Kyber).

    Args:
        algorithm: PQ KEM algorithm (default Kyber1024).

    Returns:
        (private_key, public_key) as bytes.
    """
    with oqs.KeyEncapsulation(algorithm) as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        return private_key, public_key

def decrypt_kyber_shared_secrets(ciphertext_blob: bytes, private_key: bytes, otp_pad_size: int = OTP_PAD_SIZE):
    """
    Decrypts concatenated Kyber ciphertexts to derive shared one-time pad.

    Args:
        ciphertext_blob: Concatenated Kyber ciphertexts.
        private_key: ML-KEM-1024 private key.
        otp_pad_size: Desired OTP pad size in bytes.

    Returns:
        Shared secret OTP pad bytes.
    """
    cipher_size    = 1568  # Kyber1024 ciphertext size
    shared_secrets = b''
    cursor         = 0

    with oqs.KeyEncapsulation(ML_KEM_1024_NAME, secret_key=private_key[:ML_BUFFER_LIMITS[ML_KEM_1024_NAME]["SK_LEN"]]) as kem:
        while len(shared_secrets) < otp_pad_size:
            ciphertext = ciphertext_blob[cursor:cursor + cipher_size]
            if len(ciphertext) != cipher_size:
                raise ValueError("Ciphertext blob is malformed or incomplete")
            shared_secret = kem.decap_secret(ciphertext)
            shared_secrets += shared_secret
            cursor += cipher_size

    return shared_secrets[:otp_pad_size]

def generate_kyber_shared_secrets(public_key: bytes, otp_pad_size: int = OTP_PAD_SIZE):
    """
    Generates a one-time pad via Kyber encapsulation.

    Args:
        public_key: Recipient's ML-KEM-1024 public key.
        otp_pad_size: Desired OTP pad size in bytes.

    Returns:
        (ciphertexts_blob, shared_secrets) for transport & encryption.
    """
    shared_secrets   = b''
    ciphertexts_blob = b''

    with oqs.KeyEncapsulation(ML_KEM_1024_NAME) as kem:
        while len(shared_secrets) < otp_pad_size:
            ciphertext, shared_secret = kem.encap_secret(public_key[:ML_BUFFER_LIMITS[ML_KEM_1024_NAME]["PK_LEN"]])
            ciphertexts_blob += ciphertext
            shared_secrets   += shared_secret

    return ciphertexts_blob, shared_secrets[:otp_pad_size]

def random_number_range(a: int, b: int) -> int:
    """
    Generates a secure random integer in [a, b].

    Args:
        a: Minimum value.
        b: Maximum value.

    Returns:
        Secure random integer between a and b inclusive.
    """
    return secrets.randbelow(b - a + 1) + a
