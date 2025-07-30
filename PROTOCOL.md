# COLDWIRE PROTOCOL

Version: Draft 1.0 (Work in Progress)

Author: ChadSec (Freedom Club)

## 1. INTRODUCTION
### 1.1. Prologue

Coldwire is a post-quantum secure communication protocol focused on:
- Minimal metadata leakage
- 0-trust in server (server is just a dumb relay)
- Messages & Keys plausible deniblity
- Post-quantum future proofing
- Design minimalism

There are a **best** and **worst** case scenario for Coldwire's security:
- **Best case security**: Provides unbreakable encryption, no matter how much compute power an adversary has, by utilizing One-time-Pads (OTP) encryption.

- **Worst case security**: Falls back to `ML-KEM-1024` (`Kyber1024`) security


There are no persistent contact lists or user directories on the server, no concept of friend requests server-side, no usernames, no avatars, no bio, IPs, no online status, no metadata.

Server only relays encrypted data between clients, deleting data after delivery. Data is only kept in an in-memory database (official implementation uses Redis).

### 1.2. Terminology & Wording

`Alice`: User initiating verification (User 1)

`Bob`: Contact being verified (User 2)

`Client`: The Coldwire client software (context-dependent, could refer to user or app)

`User`: The human end-user (not the software)
`SMP`: Socialist Millionaire Problem

All requests payloads and responses are sent & received in `JSON` format, unless expliclity stated otherwise.

## 2. Cryptographic Primitives

### 2.1. Authentication:

Long-term Identity Key: `ML-DSA-87` (`Dilithium5`) signature key pair

Per-contact Verification Keys: ML-DSA-87 key pair generated for each contact

Identity Verification: Socialist Millionaire Problem (SMP) variant

### 2.2. Key Derivation & Proofs:

Hash: `SHA3-512` (Note: we use `SHA3`, because `SHA3`'s Keccak sponge remains indifferentitable from a random oracle even under quantum attacks)

MAC: `HMAC-SHA3-512`

Password-based KDF: `Argon2id` with `Memory_cost` set to `256MB`, `iterations` set to 3 and `salt_length` set to `32`.


## 3. Authentication Flow

### 3.1. Identity Key Generation

`Client` generates a `ML-DSA-87` keypair locally (if he doesn't already have a keypair.)

`Public key` and `user ID` used for authentication; private key stored securely on disk.

### Registration / Login (Authentication)

Client sends 
```
POST /authentication/init
``` 
with payload that consists of public key (and user_id if re-authenticating).

Server responds with a base64-encoded random challenge.

`Client` decodes challenge, signs it with his Dilithium private key.

`Client` sends signature to ```POST /authentication/verify```.

Server verifies signature:

**If valid & key exists**: returns JSON Web Token (JWT) with existing `user_id`.

**If valid & key new**: generates new 16-byte random numeric `user_id`, and returns JWT.

`Client` must include JWT in Authorization header for all subsequent requests.


## 4. SMP verification 

ColdWire uses a human-language variant of Socialist Millionaire Problem (SMP) to verify per-contact keys.
Server does not store any contact relationships; all verification state is local to the clients.

### 4.1. Assumptions:

Alice wants to add Bob as a contact and verify authenticity of Bob's per-contact key.

### 4.2. SMP Initiation (Alice → Bob)

Alice generates per-contact ML-DSA-87 key pair (PK_A, SK_A). Stores SK_A locally.

Alice composes human-language question & normalized answer.

Alice sends:
```
POST /smp/initiate
```
```json
{
  "question"    : "What cafe did we meet at last time?",
  "nonce"       : "32 random bytes that are base64 encoded", # rA
  "public_key"  : "PK_A base64 encoded"
  "recipient_id": "Bob's user ID"
}
```

### 4.3. SMP STEP 2 (Bob to Alice)

Bob generates per-contact `ML-DSA-8`7 key pair (`PK_B`, `SK_B`).

Bob reads question, inputs answer.

Computes shared secret:
```python
fpA = sha3_512(PK_A)
rA  = b"Alice's nonce (decoded from base64)"
rB  = random_bytes(32)
secret = normalize(answer)
secret = argon2id(secret, sha3_512(rA + rB))
message = rA + rB + fpA
proof_1 = HMAC(secret, message, sha3_512)
```

Bob sends:
```
POST /smp/step_2
```
```json
{
  "proof"       : "proof_1 hex encoded",
  "nonce"       : "rB base64 encoded",
  "public_key"  : "PK_B base64 encoded",
  "recipient_id": "Alice's 16 digits user_id"
}
```

### 4.4. SMP STEP 3 (Alice → Bob)

`Alice` computes expected `proof_1` from Bob and verifies.

If valid, computes proof for Bob's key:
```python
fpB = sha3_512(PK_B)
message = rB + rA + fpB
proof_2 = HMAC(secret, message, sha3_512)
```
Alice sends:
```
POST /smp/step_3
```
```json
{
  "proof"       : hex(proof_2),
  "recipient_id": Bob's user_id
}
```

### 4.5 SMP Completion (Bob verifies Alice)

Bob computes expected proof_2 and verifies.

If valid: mutual key verification established.

Both clients mark contact as verified locally.

### SMP Security notes

Per-contact keypairs ensure compartmentalization of trust.

Verification security depends on entropy of shared answer.

SMP interaction must occur within short timeframe to avoid brute-force feasibility.

Server remains unaware of trust relationships; verification is end-to-end.



