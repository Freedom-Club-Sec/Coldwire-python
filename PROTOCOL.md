COLDWIRE PROTOCOL

Version: Draft 1.0 (Work in Progress)
Author: ChadSec (Freedom Club)

INTRODUCTION

ColdWire is a post-quantum secure communication protocol focused on:

Minimal metadata leakage

Server as a dumb relay (no trust in server)

Per-contact cryptographic verification

No persistent contact lists or user directories on the server

No concept of friend requests server-side

Server only relays encrypted messages between clients, deleting data after delivery.

CRYPTOGRAPHIC PRIMITIVES

Authentication:

Long-term Identity Key: ML-DSA-87 (Dilithium5) signature key pair

Per-contact Verification Keys: ML-DSA-87 key pair generated for each contact

Identity Verification: Socialist Millionaire Problem (SMP) variant

Key Derivation & Proofs:

Hash: SHA3-512

Password-based KDF: Argon2id

MAC: HMAC-SHA3-512

AUTHENTICATION FLOW

Identity Key Generation

Client generates ML-DSA-87 key pair locally.

Public key and user ID used for authentication; private key stored securely on disk.

Registration / Login

Client sends POST /authentication/init with public key (and user_id if re-authenticating).

Server responds with a base64-encoded random challenge.

Client decodes challenge, signs it with Dilithium private key.

Client sends signature to POST /authentication/verify.

Server verifies signature:

If valid & key exists: returns JSON Web Token (JWT) with existing user_id.

If valid & key new: generates new 16-byte random numeric user_id, returns JWT.

Client must include JWT in Authorization header for all subsequent requests.

TERMS

Alice: User initiating verification (User 1)

Bob: Contact being verified (User 2)

Client: The Coldwire client software (context-dependent, could refer to user or app)

User: The human end-user (not the software)

CONTACT VERIFICATION (SMP VARIANT)

ColdWire uses a human-language variant of Socialist Millionaire Problem (SMP) to verify per-contact keys.
Server does not store any contact relationships; all verification state is local to the clients.

Assumptions:

Alice wants to add Bob as a contact and verify authenticity of Bob's per-contact key.

5.1 SMP INITIATION (Alice → Bob)

Alice generates per-contact ML-DSA-87 key pair (PK_A, SK_A). Stores SK_A locally.

Alice composes human-language question & normalized answer.

Alice sends:

POST /smp/initiate
{
  "question"    : "What cafe did we meet at last time?",
  "nonce"       : base64(32 random bytes)  # rA
  "public_key"  : base64(PK_A)
  "recipient_id": Bob's user_id
}

5.2 SMP STEP 2 (Bob → Alice)

Bob generates per-contact ML-DSA-87 key pair (PK_B, SK_B).

Bob reads question, inputs answer.

Computes shared secret:

fpA = sha3_512(PK_A)
rA  = Alice's nonce (decoded from base64)
rB  = random_bytes(32)
secret = normalize(answer)
secret = argon2id(secret, sha3_512(rA + rB))
message = rA + rB + fpA
proof_1 = HMAC(secret, message, sha3_512)

Bob sends:

POST /smp/step_2
{
  "proof"       : hex(proof_1),
  "nonce"       : base64(rB),
  "public_key"  : base64(PK_B),
  "recipient_id": Alice's user_id
}

5.3 SMP STEP 3 (Alice → Bob)

Alice computes expected proof_1 from Bob and verifies.

If valid, computes proof for Bob's key:

fpB = sha3_512(PK_B)
message = rB + rA + fpB
proof_2 = HMAC(secret, message, sha3_512)

Alice sends:

POST /smp/step_3
{
  "proof"       : hex(proof_2),
  "recipient_id": Bob's user_id
}

5.4 SMP COMPLETION (Bob verifies Alice)

Bob computes expected proof_2 and verifies.

If valid: mutual key verification established.

Both clients mark contact as verified locally.

SECURITY NOTES

Per-contact keypairs ensure compartmentalization of trust.

Verification security depends on entropy of shared answer.

SMP interaction must occur within short timeframe to avoid brute-force feasibility.

Server remains unaware of trust relationships; verification is end-to-end.



