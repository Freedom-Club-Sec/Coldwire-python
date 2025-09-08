# Strandlock Protocol Specification
Version: `1.0`
Date: `2025-09-08`
Author(s): `ChadSec1` (`Freedom Club Sec`)
Contact: github.com/Freedom-Club-Sec
Status: `Draft`
Intended Audience: Security engineers, cryptographers, protocol implementers
### 0. Overview

The *`Strandlock`* Protocol is a composite encryption protocol designed to intertwine multiple cryptographic primitives to achieve robust security. Its purpose is to ensure that the compromise of one, two, or even three different cryptographic primitives does not jeopardize the confidentiality or integrity of messages.

Even if `ML-KEM-1024` and `Classic McEliece-8192128` are broken, messages remain secure, provided that the initial `SMP` verification request is not intercepted. If the initial SMP request is intercepted, security is maintained as long as the SMP answer retains sufficient entropy.
If `xChaCha20poly1305` is broken, messages remain safe as long as (at least) one `KEM` is uncompromised.
If `OTP` implementation has mistakes, messages remain safe as long as `xChaCha20Poly1305` is remains unbroken.

If Both `KEMs`, and `xChaCha20Poly1305` are compromised in future, as long as `OTP batch` request was not intercepted nor logged, messages remain safe.

*`Strandlock`* is transport-agnostic. It can operate over any underlying protocol, including federated chat systems like *`Coldwire`* or raw `TCP` sockets.

### 1. Terminology

For clarity, the following terms are used consistently throughout this specification:

##### Request
A generic protocol message sent from one party to another. A Request is not bound to `HTTP` or any specific transport mechanism; it may be carried over `TCP`, `UDP`, `sockets`, `pipes`, or any `communication medium`.

##### Response
The reply to a Request, carrying the necessary protocol data to complete or continue a Strandlock operation.
We use term "Response" and "Request" interchangably. A response is a request.

##### Session
A logical state maintained between two parties that tracks shared secrets, nonces, and protocol progress. A session may span multiple Requests and Responses. Only one session is allowed per-contact. This protocol does not (and will not) support multi-devices, nor multi-session per same contact.

##### Strand Nonce
A cryptographically secure random value used for entropy injection, whitening, and rotation. Strand nonces are exclusively used for `xChaCha20Poly1305` wrapping encryption. Every request contains the next nonce that will be used for the next request. Such nonces we call "Strand Nonces". Alice and Bob both save each other strand nonces.

##### Strand Key
Any key material derived, rotated, or combined from multiple primitives within Strandlock. Strand Key is fed to `xChaCha20Poly1305` to "wrap encrypt" everything. Applies to PFS, MSGS requests and responses, but not SMP. SMP process uses a temporary key simply dubbed "Temporary xChaCha key" or "SMP key"


##### SMP (Socialist Millionaire Protocol)
An authentication mechanism used to confirm shared knowledge between two parties without revealing the secret itself.
It does not refer to vanilla SMP, but refers to Off-the-record messaging-style `SMP`.

##### OTP Batch
A collection of one-time pad material derived from multiple primitives and signed before being used for message encryption.

### 2. General Protocol Features

##### Request Types: 
Every request includes a message type identifier, which may be visible only in the very first `SMP` stage request. For all other requests that come afterwards, the type is encrypted within the payload.

##### Nonces:
Each request contains a `24-bytes nonce` immediately following the `type` field. These `nonces` are meant to be used for the next request to prevent metadata leakage, replay attacks, and on the small off-chance that a randomly generated nonce repeats twice, network adversaries wouldn't know a nonce reuse occured.
Additionally, while all public security proofs of `xChaCha20Poly1305` assume nonce is public, encrypting and or hiding the `nonce` might actually "future-proof" `xChaCha20Poly1305` against potentinal future attacks, leaving only open window through pure dumb brute-forcing of `32 bytes` key space.

##### Encryption: 
All payloads are encrypted with `XChaCha20Poly1305`, except for the `SMP` initiation stage.

##### Human Verification: 
SMP enforces a human-verifiable question-and-answer process before any chat communication. This prevents "trust on first use"-style attacks that plagues other encrypted protocols.

### 3. SMP (Socialist Millionaire Protocol)
##### 3.1 Initialization (Alice -> Bob)

`Alice` selects an `SMP` question and answer and stores them locally.

`Alice` generates an `ML-KEM-1024` key pair for Bob and saves the keys locally.

`Alice` sends the following to the server:
- Metadata: recipient (contact address) 
-  Blob: `Alice’s` `ML-KEM-1024` public key

The `payload` is prefixed with `SMP_TYPE = 0x00`.

##### 3.2 Response (Bob -> Alice)

`Bob` generates a shared secret using `Alice’s` `ML-KEM-1024` public key (this is called temporary xchacha key, only used for `SMP` encryption).

`Bob` generates two `Strand Nonces` (one for himself, one for `Alice`) and hashes each with `SHA3-512`, truncating output to `24 bytes`.

`Bob` also generates an `SMP nonce` for the verification process.

`Bob` generates an `ML-DSA-87` key pair for signing (this is called `per-contact signing public key` or just `signing key`).

`Bob` prepares the `SMP response`:
```
BOB_SIGNING_PUBLIC_KEY || BOB_NONCE || BOB_STRAND_NEXT_NONCE || ALICE_STRAND_NEXT_NONCE
```

`Bob` encrypts the `response` using the derived `temporary XChaCha20 key`.

`Bob` sends:
```
SMP_TYPE || ALICE_ML_KEM_CIPHERTEXT || SMP_RESPONSE_CIPHERTEXT
```

`Bob` saves `Alice` to his contact list locally, however `Bob` **must** flag `Alice` as `unverified` or `pending_verification`.
`Bob` also stores all `nonces` and the `temporary XChaCha key` for this `SMP` session.

##### 3.3 Proof 1 (`Alice's` proof of `Bob's` public-key)

`Alice` decapsulates the KEM ciphertext, derives shared secret to get the "temporary xChaCha key", then she decrypts the `XChaCha` ciphertext using the `temporary xChaCha key`.

`Alice` stores `Bob’s` signing key, `Bob's SMP nonce`, `Alice Strand Nonce`, and `Bob Strand Nonce` .

`Alice` generates her `SMP nonce`.

`Alice` normalizes her `SMP answer` (strip whitespace, lowercase only the first character) and `UTF-8` encodes it.

Alice generates an `Argon2Id salt` by concatenating `ALICE_SMP_NONCE` to `BOB_SMP_NONCE`, hashes it with `SHA3_512` and truncates back to `16 bytes` (16 bytes for interoperability with libsodium):
```
ARGON2ID_SALT = SHA3-512(BOB_SMP_NONCE || ALICE_SMP_NONCE)[:16]
```

`Alice` derives `answer_secret` using `Argon2id` with the `salt`, and the following paramaters:
- Memory: 3072 * 1024 bytes (3 Gigabytes)
- Iterations: 50000 (50k)
- Output: 64 bytes

`Alice` computes `Bob’s` public-key fingerprint: 
```
BOB_FINGERPRINT = SHA3-512(BOB_SIGNING_PUBLIC_KEY)
```

`Alice` prepares `proof` data: 
```
PROOF_DATA = BOB_SMP_NONCE || ALICE_SMP_NONCE || BOB_KEY_FINGERPRINT
```

`Alice` computes the proof by performing HMAC operation on `PROOF_DATA` with key being `ANSWER_SECRET` and algorithm being `SHA3_512`: 
```
PROOF = HMAC(SHA3_512, PROOF_DATA, ANSWER_SECRET)
```

`Alice` generates a `New Strand Nonce` (random `24 bytes`, hashed with `SHA3-512`, truncated to `24 bytes`).

Alice generates an `ML-DSA-87` key pair for herself.

`Alice` prepares `SMP` request (Question must be `UTF-8` encoded):
```
SMP_REQUEST_DATA = SMP_TYPE || NEW_ALICE_STRAND_NONCE || ALICE_SIGNING_PUBLIC_KEY || ALICE_SMP_NONCE || ALICE_PROOF_OF_BOB || QUESTION_UTF-8
```

`Alice` encrypts the payload with `XChaCha20` using `temporary xchacha key` as key, and uses `ALICE_NEXT_STRAND_NONCE` as nonce, and sends it to `Bob`

##### 3.4 Verification & Proof 2 (`Bob`):

`Bob` decrypts the payload with the `temporary key` and asks the user for an `SMP answer`.

`Bob` checks if `BOB_SMP_NONCE` is equal to `ALICE_SMP_NONCE`, aborting and sending a `SMP failure request` if they match.

`Bob` verifies `Alice’s` `proof` **using a time-constant comparison**.

If verification *fails*:
`Bob` prepares `SMP failure request` payload data:
```
SMP_REQUEST_DATA = SMP_TYPE || b"failure".
```
`Bob` encrypts the payload using `temporary chacha key`, but does not use his **Strand Nonce**, instead he generates a random nonce and bundles it at start of the **ciphertext**.

If verification *succeeds*:

`Bob` computes the `fingerprint` of `Alice’s` `KEM` and `signing` public-keys:
```
ALICE_FINGERPRINT = SHA3-512(ALICE_SIGNING_PUBLIC_KEY || ALICE_KEM_PUBLIC_KEY)
```

`Bob` prepares proof data:
```
PROOF_DATA = ALICE_SMP_NONCE || BOB_SMP_NONCE || ALICE_FINGERPRINT
```

`Bob` generates `ALICE_STRAND_KEY` and `BOB_STRAND_KEY`, which will be used for all other `non-SMP requests` going forward. (`32 bytes` each, random bytes, `SHA3-512` hashed, then truncated back to `32 bytes`)

`Bob` generates a new `BOB_NEW_STRAND_NONCE`

`Bob` prepares `SMP` payload data:
```
SMP_REQUEST_DATA = SMP_TYPE || BOB_NEW_STRAND_NONCE || BOB_PROOF_OF_ALICE || BOB_STRAND_KEY || ALICE_STRAND_KEY
```

`Bob` encrypts the `SMP request data` with `temporary xchacha key` as key, and previous `BOB_NEXT_STRAND_NONCE` as nonce, and sends to `Alice`.

`Bob` modifies both `ALICE_STRAND_KEY` and `BOB_STRAND_KEY` by `XOR-ing` each key with the `SHA3-512` hash of `ANSWER_SECRET`:
```

ALICE_STRAND_KEY = XOR(ALICE_STRAND_KEY, SHA3_512(ANSWER_SECRET))
BOB_STRAND_KEY   = XOR(BOB_STRAND_KEY, SHA3_512(ANSWER_SECRET))
```
`Bob` then saves the new keys, and marks `Alice` as `SMP` verified.

3.5 Final Verification (`Alice`):

`Alice` decrypts `Bob’s` `SMP` payload and verifies `Bob’s` proof.

If valid, she applies the same XOR transformation to the `Strand Keys`, and saves them.

`Alice` marks `Bob` as verified.

`Alice` sends her first PFS keys.

##### 3.6. Notes on SMP:

Step 1: No encryption

Step 2: Encryption is being set up

Step 3 and onwards: All requests are encrypted with the `temporary xchacha key` and `nonces` protected using the `strand nonces` by bundling next nonce to be used in every request.

Nonces are embedded in payloads, not sent in clear, except in step 2 and SMP failure requests

Do not confuse `Strand Nonces` with `SMP Nonces`, the latter is only used for SMP process (as salt for `Argon2id`, etc, not for encryption), while the former is used in Step 3 and onwards, even in other requests types (`PFS`, `MSGS`, etc.)

The security of the `SMP` process depends entirely on the entropy of the user-provided `answer`, we use extreme `Argon2id` parameters to protect against a *"god-like"* adversary with virtually *unlimited* computing power, and we salt the answer to prevent *Rainbow-style* attacks. **However**, if `answer` is *low-entropy*, even such measures cannot completely prevent the cracking of the answer. 
We highly recommend implementations to only allow user to set a `8+ character` answer, and to check the entropy of provided answer (is all lowercase, is all uppercase, is only digits, etc), and to warn (or prevent) the user from continuing.

Even though the `question` is encrypted, an active *Man-in-the-middle* adversary **can still retrieve it**. The verification would fail, but the adversary would have the `question` plaintext.
This is acceptable, as the purpose of encrypting `SMP` process is to hide *metadata* against **passive** adversaries, not an **active** adversary. 
The question **must not** contain any senstive data. And it must not contain any hints to the answer.
Implementations **must** check `answer` and `question` in initation stage, to ensure neither contain the other.


### 4. Perfect Forward Secrecy (PFS)
##### 4.1 Key Rotation

Alice checks if a saved ALICE_KEYS_HASH_CHAIN exists:

If not, she generates a new hash chain of size KEYS_HASH_CHAIN_LEN.

Otherwise, she advances the hash chain using SHA3-512.

Alice generates new ML-KEM-1024 key pairs.

Alice checks if McEliece keys need rotation (after 10 OTP batches or if never sent before).

Alice constructs publickeys_hashchain:

hash_chain || ml_kem_1024_public_key || optional_classic_mceliece_8192128f_public_key

Alice signs publickeys_hashchain with her signing key.

Alice generates ALICE_NEW_STRAND_NONCE.

Alice sends:

PFS_TYPE || ALICE_NEW_STRAND_NONCE || PUBLICKEYS_HASHCHAIN_SIGNATURE || PUBLICKEYS_HASHCHAIN


Encrypted using previous ALICE_NEXT_STRAND_NONCE.

4.2 Receiving PFS Keys (Bob)

Bob decrypts using ALICE_STRAND_KEY and ALICE_NEXT_STRAND_NONCE.

Bob updates ALICE_NEXT_STRAND_NONCE.

Bob verifies hash chain and signature.

Bob determines which keys were sent (ML-KEM-1024 only or ML-KEM + McEliece) and saves them.

If Bob has no new keys to send, he generates them similarly.

5. Messaging (MSGS)
5.1 OTP Batch Generation

Alice checks if message length + OTP_SIZE_LENGTH ≤ available pad space:

If not, she generates a new OTP batch.

Alice generates ML-KEM-1024 shared secrets in chunks until OTP_PAD_SIZE is reached.

Alice generates Classic McEliece shared secrets similarly.

Alice generates OTP_PAD_SIZE of random bytes for XChaCha shared secrets.

Alice generates a new hash chain seed MESSAGE_HASH_CHAIN_LEN (64 bytes).

Alice signs all ciphertexts using her signing key.

Alice generates ALICE_NEW_STRAND_NONCE and prepares the payload:

MSG_TYPE || 0x00 || ALICE_NEW_STRAND_NONCE || HASH_CHAIN_SEED || OTP_BATCH_SIGNATURE || ML_KEM_1024_CIPHERTEXT || CLASSIC_MCELIESE_819_CIPHERTEXT || XCHACHA_SHARED_SECRETS


Alice encrypts using ALICE_STRAND_KEY and sends.

Alice XORs ML-KEM, McEliece, and XChaCha secrets to produce OTP pads.

The first 32 bytes of pads become the new ALICE_STRAND_KEY.

5.2 Message Sending

Alice UTF-8 encodes the message.

Alice OTP encrypts the message with generated pads:

If length < OTP_MAX_BUCKET - OTP_SIZE_LENGTH, pad to OTP_MAX_BUCKET.

If length > OTP_MAX_BUCKET, pad randomly up to OTP_MAX_RANDOM_PAD.

Prefix message with padding length (OTP_SIZE_LENGTH, 2 bytes, big-endian).

Advance hash chain: SHA3-512(previous_hash_chain || encrypted_message)

Generate ALICE_NEW_STRAND_NONCE.

Prepare payload:

MSG_TYPE || 0x01 || ALICE_NEW_STRAND_NONCE || HASH_CHAIN || MESSAGE_ENCRYPTED


Encrypt with ALICE_STRAND_KEY using ALICE_NEXT_STRAND_NONCE and send.

5.3 Receiving Messages (Bob)

Decrypt payload using ALICE_STRAND_KEY and nonce.

Verify hash chain.

Decrypt message with OTP pads from OTP batch.

Display message.

6. Argon2id Parameters for SMP

Memory: 3GB (3072 * 1024 KB)

Iterations: 50,000

Output: 64 bytes

7. Design Notes

Nonce hiding: Prevents metadata leakage and hides rare nonce collisions.

OTP usage: Provides additional protection even if XChaCha is broken. Makes known-plaintext attacks ineffective.

Composite security: Messages remain secure if an attacker breaks a single primitive; at least 3 primitives need to be broken for full compromise (ML-KEM, McEliece, XChaCha or SMP).

xChaCha20-Poly1305 vs AES-GCM: Larger nonce, no hardware dependencies, reduces potential backdoors.

SHA3-512 whitening: Reduces CSPRNG bias and protects against metadata leakage.

Argon2id for SMP: Protects against brute force attacks and Trust-On-First-Use style attacks.
