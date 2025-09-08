# Strandlock Protocol Specification
Version: **`1.0`**

Date: **`2025-09-08`**

Author(s): **`ChadSec1`** (**`Freedom Club Sec`**)

Contact: github.com/Freedom-Club-Sec

Status: **`Draft`**

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

#### Request
A generic protocol message sent from one party to another. A Request is not bound to `HTTP` or any specific transport mechanism; it may be carried over `TCP`, `UDP`, `sockets`, `pipes`, or any `communication medium`.

#### Response
The reply to a Request, carrying the necessary protocol data to complete or continue a Strandlock operation.
We use term "Response" and "Request" interchangably. A response is a request.

#### Session
A logical state maintained between two parties that tracks shared secrets, nonces, and protocol progress. A session may span multiple Requests and Responses. Only one session is allowed per-contact. This protocol does not (and will not) support multi-devices, nor multi-session per same contact.

#### Strand Nonce
A cryptographically secure random value used for entropy injection, whitening, and rotation. Strand nonces are exclusively used for `xChaCha20Poly1305` wrapping encryption. Every request contains the next nonce that will be used for the next request. Such nonces we call "Strand Nonces". Alice and Bob both save each other strand nonces.

#### Strand Key
Any key material derived, rotated, or combined from multiple primitives within Strandlock. Strand Key is fed to `xChaCha20Poly1305` to "wrap encrypt" everything. Applies to PFS, MSGS requests and responses, but not SMP. SMP process uses a temporary key simply dubbed "Temporary xChaCha key" or "SMP key"


#### SMP (Socialist Millionaire Protocol)
An authentication mechanism used to confirm shared knowledge between two parties without revealing the secret itself.
It does not refer to vanilla SMP, but refers to Off-the-record messaging-style `SMP`.

#### OTP Batch
A collection of one-time pad material derived from multiple primitives and signed before being used for message encryption.

### 2. General Protocol Features

#### Request Types: 
Every request includes a message type identifier, which may be visible only in the very first `SMP` stage request. For all other requests that come afterwards, the type is encrypted within the payload.

#### Nonces:
Each request contains a `24-bytes nonce` immediately following the `type` field. These `nonces` are meant to be used for the next request to prevent metadata leakage, replay attacks, and on the small off-chance that a randomly generated nonce repeats twice, network adversaries wouldn't know a nonce reuse occured.

Additionally, while all public security proofs of `xChaCha20Poly1305` assume nonce is public, encrypting and or hiding the `nonce` might actually "future-proof" `xChaCha20Poly1305` against potentinal future attacks, leaving only open window through pure dumb brute-forcing of `32 bytes` key space.

#### Encryption: 
All payloads are encrypted with `XChaCha20Poly1305`, except for the `SMP` initiation stage.

#### Human Verification: 
`SMP` enforces a human-verifiable question-and-answer process before any chat communication. This prevents "trust on first use"-style attacks that plagues other encrypted protocols.

### 3. Socialist Millionaire Protocol (`SMP`)
#### 3.1 Initialization (`Alice` -> `Bob`)

`Alice` selects an `SMP` question and answer and stores them locally.

`Alice` generates an `ML-KEM-1024` key pair for Bob and saves the keys locally.

`Alice` sends the following to the server:
- Metadata: recipient (contact address) 
-  Blob: `Alice’s` `ML-KEM-1024` public key

The `payload` is prefixed with `SMP_TYPE = 0x00`.

#### 3.2 Initialization response (`Bob`)

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

#### 3.3 Proof 1 (`Alice's` proof of `Bob's` public-key)

`Alice` decapsulates the KEM ciphertext, derives shared secret to get the "temporary xChaCha key", then she decrypts the `XChaCha` ciphertext using the `temporary xChaCha key`.

`Alice` stores `Bob’s` signing key, `Bob's SMP nonce`, `Alice Strand Nonce`, and `Bob Strand Nonce` .

`Alice` generates her `SMP nonce`.

`Alice` normalizes her `SMP answer` (strip whitespace, lowercase only the first character) and `UTF-8` encodes it.

Alice generates an `Argon2Id salt` by concatenating `ALICE_SMP_NONCE` to `BOB_SMP_NONCE`, hashes it with `SHA3_512` and truncates back to `16 bytes` (16 bytes for interoperability with libsodium):
```
ARGON2ID_SALT = SHA3-512(BOB_SMP_NONCE || ALICE_SMP_NONCE)[:16]
```

`Alice` derives `answer_secret` using `Argon2id` with the `salt`, and the following paramaters:
- Memory: 3072 * 1024 * 1024 bytes (3 Gigabytes)
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

#### 3.4 Verification & Proof 2 (`Bob`):

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

#### 3.5 Final Verification (`Alice`):

`Alice` decrypts `Bob’s` `SMP` payload and verifies `Bob’s` proof.

If valid, she applies the same `XOR` transformation to the `Strand Keys`, and saves them.

`Alice` marks `Bob` as verified.

`Alice` sends her first PFS keys.

#### 3.6. Notes on SMP:

Step 1: No encryption

Step 2: Encryption is being set up

Step 3 and onwards: All requests are encrypted with the `temporary xchacha key` and `nonces` protected using the `strand nonces` by bundling next nonce to be used in every request.

Nonces are embedded in payloads, not sent in clear, except in step 2 and SMP failure requests

Do not confuse `Strand Nonces` with `SMP Nonces`, the latter is only used for SMP process (as salt for `Argon2id`, etc, not for encryption), while the former is used in Step 3 and onwards, even in other requests types (`PFS`, `MSGS`, etc.)


The security of the `SMP` process depends entirely on the entropy of the user-provided `answer`, we use extreme `Argon2id` parameters to protect against a *"god-like"* adversary with virtually *unlimited* computing power, and we salt the answer to prevent *Rainbow-style* attacks. **However**, if `answer` is *low-entropy*, even such measures cannot completely prevent the cracking of the answer. 

Answers don't have to be uncrackable forever, just uncrackable for a reasonable duration (minimum 1 week to months), our extreme `Argon2id` parameters achieve just that.

We highly recommend implementations to only allow user to set a `8+ character` answer, and to check the entropy of provided answer (is all lowercase, is all uppercase, is only digits, etc), and to warn (or prevent) the user from continuing.

Even though the `question` is encrypted, an active *Man-in-the-middle* adversary **can still retrieve it**. The verification would fail, but the adversary would have the `question` plaintext.

This is acceptable, as the purpose of encrypting `SMP` process is to hide *metadata* against **passive** adversaries, not an **active** adversary. 

The question **must not** contain any senstive data. And it must not contain any hints to the answer.

Implementations **must** check `answer` and `question` in initation stage, to ensure neither contain the other.


### 4. Perfect Forward Secrecy (`PFS`)
#### 4.1 Key Rotation (`Alice`)

`Alice` checks if a saved `ALICE_KEYS_HASH_CHAIN` exists:
- If not, she generates a new hash chain of size `KEYS_HASH_CHAIN_LEN` (default `64 bytes`).
- Otherwise, she advances the hash chain by hashing the previous hash chain with `SHA3-512`, then output truncating to `KEYS_HASH_CHAIN_LEN`.

`Alice` generates new `ML-KEM-1024` key pairs.

`Alice` checks if `Classic-McEliece` keys need rotation (by checking some `rotation_counter` and when it reaches a specific number, say `10`, it means its time to rotate, or, if `Alice` never sent any keys before).

`Alice` constructs `PUBLICKEYS_HASHCHAIN`:
```
hash_chain || ml_kem_1024_public_key || optional_classic_mceliece_8192128_public_key
```

`Alice` signs `PUBLICKEYS_HASHCHAIN` with her signing key.

`Alice` generates `ALICE_NEW_STRAND_NONCE`.

`Alice` constructs `PFS` request:
```
PFS_PAYLOAD = PFS_TYPE || ALICE_NEW_STRAND_NONCE || PUBLICKEYS_HASHCHAIN_SIGNATURE || PUBLICKEYS_HASHCHAIN
```

`Alice` then encrypts the `PFS_PAYLOAD`, with `xChaCha20Poly1305` using her `ALICE_STRAND_KEY` key, and using previous `ALICE_NEXT_STRAND_NONCE` as nonce. 

#### 4.2 Receiving PFS Keys (`Bob`)

`Bob` decrypts strand wrapper encryption with `xChaCha20Poly1305` using `ALICE_STRAND_KEY` as key, and `ALICE_NEXT_STRAND_NONCE` as nonce.

`Bob` updates `ALICE_NEXT_STRAND_NONCE` with `ALICE_NEW_STRAND_NONCE`.

`Bob` *verifies* hash chain and signature using `Alice` signing public-key.

`Bob` determines which keys were sent (`ML-KEM-1024` only or `ML-KEM-1024` + `Classic-McEliece-8192128`), and saves them.

`Bob` then checks if he already sent keys to `Alice`, if he never sent any keys before to `Alice`, he performs the `4.1. Key Rotation` as well.

#### 4.3. PFS Notes:
Even though the use of hash-chains and signatures may appear redundant here, as we already wrap everything in `xChaCha20Poly1305`, and we encrypt its nonce, which serves as a replay protection, and tamper protection, the use of hash-chains here ensures that even if `xChaCha20Poly1305` is broken, PFS keys cannot be replayed, nor tampered with.

The reason we opted for a hash-chain based design, instead of a simple counter, is to ensure metadata of how many key rotations occured never gets leaked, even when `xChaCha20Poly1305` is broken. 
Even if `Alice's` or `Bob's` endpoint get compromised, no metadata of how many key rotation occured could be recovered.

### 5. Messaging (`MSGS`)
#### 5.1 OTP Batch Generation (`Alice`)
`Alice` uses `Bob's` `ML-KEM-1024` public-key to generates many shared secrets *in chunks*, concatenating them until their total size reaches (or exceeds) `OTP_PAD_SIZE` size (default `11264 bytes`).

`Alice` does the same thing with `Classic-McEliece-8192128`.

`Alice` generates random bytes of `OTP_PAD_SIZE` size, these are called `xChaCha_shared_secrets`

`Alice` signs all `KEM's` ciphertexts using her signing private key.

`Alice` generates new `ALICE_NEW_STRAND_NONCE` as always, and bundles in `OTP BATCH` type of `0x00`, and constructs the `MSG OTP request`:
```
MSG_REQUEST = MSG_TYPE || 0x00 || ALICE_NEW_STRAND_NONCE || OTP_BATCH_SIGNATURE || ML_KEM_1024_CIPHERTEXT || CLASSIC_MCELIESE_819_CIPHERTEXT || XCHACHA_SHARED_SECRETS
```

`Alice` encrypts the payload using her `ALICE_STRAND_KEY`, and her `ALICE_NEXT_STRAND_NONCE`, and sends payload to Bob.

`Alice` then `XORs` `ML-KEM-1024's` shared secrets with `Classic-McEliece's` shared secrets, then she `XORs` the result with `XChaCha` secrets to produce the final result, the `ALICE_OTP_PADS`.

The first `32 bytes` of pads become the new `ALICE_STRAND_KEY`, and is truncated from `ALICE_OTP_PADS`.

She saves her new `ALICE_STRAND_KEY`, and `ALICE_OTP_PADS`.

These `ALICE_OTP_PADS` will be used to encrypt messages sent from `Alice` to `Bob`.

#### 5.2 New OTP Batch Processing (`Bob`)
`Bob` decrypts the `xChaCha20Poly1305` wrapping, using `ALICE_STRAND_KEY` as key, and `ALICE_NEXT_STRAND_NONCE` as nonce.
`Bob` checks if request type is `MSG_TYPE`, then `Bob` checks the next byte if it's `0x00` (`New OTP Batch`), or `0x01` (New `OTP Message`)

If its a `New OTP Batch`, `Bob`  verifies `OTP_BATCH_SIGNATURE` against `ML_KEM_1024_CIPHERTEXT` + `CLASSIC_MCELIESE_819_CIPHERTEXT`
If invalid, abort, by skipping the request. Implementations are recommended to log and display the error to the user, so that they may be notified that someone attempted to MiTM against their conversation.

If valid, `Bob` decapsulate `ML_KEM_1024_CIPHERTEXT` and `CLASSIC_MCELIESE_819_CIPHERTEXT` shared secrets.
`Bob` then follows same exact forumla `Alice` did with her keys, `XOR-ing` `ML-KEM-1024's` shared secrets with `Classic-McEliece's` shared secrets, then she `XORs` the result with `XChaCha` secrets to produce the final result, the `ALICE_OTP_PADS`.

The first `32 bytes` of pads become the new `ALICE_STRAND_KEY`, and are truncated from `ALICE_OTP_PADS`

`Bob` updates `ALICE_NEXT_STRAND_NONCE` to be `ALICE_NEW_STRAND_NONCE`, then saves.

These pads will be used to decrypt messages coming from `Alice`.

#### 5.3 Message Sending
`Alice` first `UTF-8` encodes her `message`, then she checks if (`message` size + `OTP_SIZE_LENGTH` size) ≤ available `ALICE_OTP_PADS`.

If theres not enough pads for the message, she generates and sends a new OTP batch (see section 5.1 & 5.2).

`Alice` performs `OTP` encryption on her message, using her pads as key.
`OTP` encryption uses 2 models of padding, depending on the message's size.
- If `message` length < `OTP_MAX_BUCKET` - `OTP_SIZE_LENGTH` (default `2 bytes`), pad to `OTP_MAX_BUCKET` (default `64 bytes`).

- If `message` length > `OTP_MAX_BUCKET`, pad randomly up to `OTP_MAX_RANDOM_PAD` (default `16 bytes`).

**All messages** are prefixed with a padding length field `OTP_SIZE_LENGTH` (`2 bytes` in `big-endian` format).

After padding, the new padded message plaintext, is `OTP` encrypted.

After encryption is complete, the `OTP pads` used for encryption **must** be truncated immeditely. Truncate pads *before* sending on wire, and even if request fail, never re-use nor undo truncation.

`Alice`, as always, generates a new `ALICE_NEW_STRAND_NONCE`, and prepares the request data:
```
MSG_DATA = MSG_TYPE || 0x01 || ALICE_NEW_STRAND_NONCE || MESSAGE_ENCRYPTED
```

`0x01` indicates this is a MSG of type `New OTP Message`.

`Alice` then encrypts `MSG_DATA` with `xChaCha20Poly1305` using `ALICE_STRAND_KEY`, and `ALICE_NEXT_STRAND_NONCE` as nonce, then sends it to `Bob`.

#### 5.3 Receiving Messages (Bob)

`Bob` decrypts the `xChaCha20Poly1305` wrapping, using `ALICE_STRAND_KEY` as key, and `ALICE_NEXT_STRAND_NONCE` as nonce.
`Bob` checks if request type is `MSG_TYPE`, then `Bob` checks the next byte if it's `0x00` (`New OTP Batch`), or `0x01` (New `OTP Message`)

if is `New OTP Message`, `Bob` decrypt the encrypted message with `ALICE_OTP_PADS`.
`Bob` then reads the padding prefix of message, and removes the padding, then he removes the padding prefix.

`Bob` then `UTF-8` decodes the message, and displays it.

#### 5.4. MSGs Notes
The reason we don't use a hash-chain like in `PFS`, is because the `xChaCha20Poly1305` wrapping `strand` scheme provides tampering and replay protection. And even if `xChaCha20Poly1305` is broken, messages that get tampered or replayed with, `Bob` would notice as the message content would be inparsable junk (at UTF-8 decoding step).

Encrypting with `OTP` ensures that even if `xChaCha20Poly1305` is broken, and even if one `KEM` is broken, messages remain uncompromised.

Even if `xChaCha20Poly1305` is broken, and 2 KEMs broken, messages remain uncompromised if the `OTP batch` request was not intercepted.

If `OTP batch` request was not intercepted, messages become true OTPs.

If `OTP batch` request is intercepted, `OTP` messages inherits the combined security of `xChaCha20Poly1305`, `ML-KEM-1024`, `Classic-McEliece-8192128`, and even the entropy of `SMP answer`.

Additionally, using `OTPs` here provides an odd protection to `xChaCha20Poly1305`, by making "`known plaintext oracles`" attacks impossible, significantly bolstering `xChaCha20Poly1305` security.

Additionally, using `OTPs` makes nonce reuses non-fatal, as we already encrypt nonces, the only possible way for an adversary on wire to know a nonce reuse occured, is if user types same message, with same key, with same nonce.

Even if a ranodmly generated nonce was repeated, and the user does such unlikely thing, the fact plaintext is OTP encrypted, means the adversary would still see different ciphertexts. Making it impossible for them to know if a nonce reuse occured.
Obviously, this does not mean a nonce reuse wouldn't occur, it just means an adversary wouldn't be able to exploit the fact because to him, is invisible random blobs.

However, implementations **MUST** still use cryptographically secure `CSPRNG` for nonce generation nonetheless. This protection property only protects against the off chance a `CSPRNG` generated nonce gets duplicated.



### 7. Design choices (Questions & Answers)
**Question**:

Why did you opt for `xChaCha20Poly1305` over `ChaCha20Poly1305` if you're encrypting the nonce ?

**Answer**: 

Even though we do encrypt the nonce, encrypting the nonce does not prevent nonce-reuse attacks, it only hides the fact they occured. 
`xChaCha20Poly1305` nonces are a lot larger than `ChaCha20Poly1305` nonces, which means the probablity of a collision is tiny.


**Question**:

Why did you opt for `xChaCha20Poly1305` over `AES-GCM-SIV` ?

**Answer**: 

We chose `xChaCha20Poly1305` over `AES-GCM-SIV` (or just `AES` as an algorithm in general) because the former is easier to implement in software, less vulnerable to side-channels, and does not depend on any black-box hardware "accelerators".


**Question**

Why did you opt for `OTP` encryption, if you're already using `xChaCha20Poly1305`, why not just use `xChaCha` alone ?

**Answer**

OTP encryption provides unique properties, and when combined with a classical symmetric algorithm, both algorithms benefit each other. On one hand, `xChaCha20Poly1305` encryption of `OTP`-encrypted messages, provides protection against `OTP` implementation errors, on the other hand, using `OTP`-encrypted messages as plaintext to `xChaCha20Poly1305` destroys one of cryptographors favorite oracles `known plaintext oracle`, which removes a whole class of attacks.

Additionally, if the `OTP Batch` exchange was not intercepted nor logged, OTPs become unbreakable.


**Question**

Why do you generate random bytes of X size, then hash them with `SHA3_512` and truncate them back to X size ?

**Answer**

Using raw entropy does not guarantee it is uniform. As `CSPRNG` entropy is usually collected from device's sensors, and whatnot, a poorly made `CSPRNG` can have small biases, or even leak metadata. Hashing them with SHA3_512 helps "whiten" any potentinal issue.

The reason we use SHA3_512 specifically, and truncate to size we need, is actually 3 separate reasons:
- Less code is called: Depending on one hashing algorithm, means we have to call less code with potentinally untrusted input. 
- `SHA3_512` internal state can store more entropy than for instance `SHA3_256`.
- `SHA3` in general, is proven to be better resistant to `Shor's` algorithm, which makes it better long-term than (for instance) `SHA2`.
- 

**Question**

Why do you use `Argon2id` instead of `Argon2i` or `Argon2d` ?

**Answer**

Because `Argon2id` combines both `Argon2i` and `Argon2d` providing more general protection, and is recommended variant as per `RFC 9106`.


**Question**

Why don't you use a NIST-approved algorithm instead of `Argon2id` ?

**Answer**

Because just because an algorithm is not NIST-approved, does not mean it's insecure. NIST tend to take their time standardizing and recommending algorithms, and `Argon2id` is relatively new. Even though `Argon2id` is on the newer side of things, it has won `Passowrd Hashing Competition` and has undergone many audits, and has been proven to be among the slowest, GPU-resistant hashing algorithms.


**Question**

Why reinvent the wheel ? Why not adopt something like Signal's protocol ?

**Answer**

Even though Signal's protocol is well audited, and deployed widely, it offers bare minimum protection, with no overlapping layers, and no metadata protection. It works, it encrypts, it is safe against most "reasonable" adversaries. 
But it does not fit our criteria nor objective with the `Strandlock` protocol. Our threat model is much more paranoid than Signal's in multiple ways, that adopting their protocol would make no sense.


**Question**

Why is the protocol name "Strandlock" ?

**Answer**

Because it combines cryptographic in a way that breaking one, two, or even three, does not break the entire protocol (or shall we say "strand"), sort of like a hair strand.
