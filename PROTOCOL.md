# COLDWIRE PROTOCOL

Version: Draft 1.0 (Work in Progress)

Author: ChadSec (Freedom Club)

## 1. INTRODUCTION
### 1.1. Prologue

Coldwire is a post-quantum secure communication protocol focused on:
- Minimal metadata
- *0-trust* in server (server is just a dumb relay, and is always assumed malicious)
- Messages & Keys plausible deniability 
- Post-quantum future proofing (NIST Post-quantum algorithms with tier-5 security)
- Design minimalism (few dependencies, simple UI)


There are a **best** and **worst** case scenario for Coldwire's security:
- **Best case security**: Provides *unbreakable encryption*, no matter how much compute power an adversary has, by utilizing One-time-Pads (OTP) encryption.

- **Worst case security**: Falls back to `ML-KEM-1024` (`Kyber1024`) security

We depend on The Open-Quantum Safe Project for the implementation of the Post-Quantum (PQ) algorithms.

We have chosen Python for our first `client` implementation for rapid development, and memory-safety. Additionally, this saves us from distributing binaries, which is a great thing security wise.

What you see in the source code tree, is exactly what you get. No surpises.

Additionally, we do extra effort to prevent 0-day exploits (memory-safety issues) in the underlying LibOQS and Tkinter libraries, by always truncating buffers to safe lengths before passing on to the libraries, we reduce the risk of buffer-overflows.

There are no persistent contact lists or user directories on the server, no concept of friend requests server-side, no usernames, no avatars, no bio, IPs, no online status, no metadata.

Server only relays encrypted data between clients, deleting data after delivery. Data is only kept in an in-memory database (official server implementation uses Redis).

### 1.2. Terminology & Wording

`Alice`: Our user, or a hypothetical `User 1`

`Bob`: Our Contact, or a hypothetical `User 2`

`Client`: The Coldwire client software (context-dependent, could refer to user or app)

`User`: The human end-user (not the software)

`SMP`: Socialist Millionaire Problem

`Dilithium`, `Dilithium5`: Interchangeably refers to `ML-DSA-87`

`Kyber`, `Kyber1024`: Interchangeably refers to `ML-KEM-1024`

`per-contact keys`: Refers to a keypair whose public key is **only sent once** to a contact in the `SMP` phase.

*All* requests payloads and responses are sent & received in `JSON` format, unless expliclity stated otherwise.

*ALL* code displayed in this documented is purely pseudocode.

## 2. Cryptographic Primitives

### 2.1. Authentication:

Long-term Identity Key: `ML-DSA-87` (`Dilithium5`) signature key pair

Per-contact Keys: `ML-DSA-87` key pair generated for each contact

Identity Verification: Custom `Socialist Millionaire Problem` (`SMP`) human-language variant.

### 2.2. Key Derivation & Proofs:

Hash: `SHA3-512` (Note: we use `SHA3`, because `SHA3`'s Keccak sponge remains indifferentitable from a random oracle even under quantum attacks)

MAC: `HMAC-SHA3-512`

Password-based KDF: `Argon2id` with `Memory_cost` set to `256MB`, `iterations` set to `3` and `salt_length` set to `32`.

### 2.3. Perfect Forward Secrecy:

Rotation key(s): Ephemeral `ML-KEM-1024` (`Kyber1024`) *Key Encapsulation Mechanism* (`KEM`) key pair

Rotation key signing keys: Pre-contact keys (`ML-DSA-87`) to sign Ephemeral keys

### 2.4. Symmetric algorithms
`OTP` (One-Time-Pads): Used for encrypting messages

`AES-256-GCM` (Advanced Encryption Standard with 256-bit key length operating in Galois/Counter mode): Used for encrypting & decrypting local storage. 

### 2.5. Asymmetric algorithms
`ML-DSA-87`: Used for authenticating to server and signing ephemeral `PFS` (Perfect Forward Secrecy) keys

`ML-KEM-1024` Used as ephemeral `PFS` keys that are rotated

## 3. Authentication Flow

### 3.1. Identity Key Generation

`Client` generates a `ML-DSA-87` keypair locally (if he doesn't already have a keypair.)

`Public key` and `user ID` used for authentication; private key stored securely on disk.

### Registration / Login (Authentication)

Client sends 
```
POST /authentication/init
``` 
with payload that consists of `user`'s base64-encoded public key (and `user_id` if re-authenticating).

Server responds with a base64-encoded random challenge.

`Client` decodes challenge, signs it with his `Dilithium` private key.

`Client` sends signature to ```POST /authentication/verify```.

Server *verifies* signature:

**If valid & key exists**: returns JSON Web Token (JWT) with existing `user_id`.

**If valid & key new**: generates new 16-byte random numeric `user_id`, and returns JWT.

`Client` must include `JWT` token in Authorization header for all subsequent requests.


## 4. SMP verification 

ColdWire uses a human-language variant of *Socialist Millionaire Problem* (`SMP`) to verify `per-contact keys`.
Server does not store any contact relationships, all verification state is local to the clients.


### 4.1. Assumptions:

`Alice` wants to add `Bob` as a contact and verify authenticity of `Bob`'s per-contact key.

### 4.2. SMP Initiation (Alice -> Bob)

`Alice` generates per-contact `ML-DSA-87` key pair (`PK_A`, `SK_A`). Stores `SK_A` locally.

`Alice` composes human-language question & normalized answer.

`Alice` sends:
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

### 4.3. SMP STEP 2 (Bob -> Alice)

`Bob` generates per-contact `ML-DSA-87` key pair (`PK_B`, `SK_B`).

`Bob` reads question, inputs answer.

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
  "recipient_id": "Alice's 16 digits user ID"
}
```

### 4.4. SMP STEP 3 (Alice -> Bob)

`Alice` computes expected `proof_1` from Bob and verifies.

If valid, computes proof for `Bob`'s key:
```python
fpB = sha3_512(PK_B)
message = rB + rA + fpB
proof_2 = HMAC(secret, message, sha3_512)
```
`Alice` sends:
```
POST /smp/step_3
```
```json
{
  "proof"       : "proof_2 hex encoded",
  "recipient_id": "Bob's 16 digits user ID"
}
```

### 4.5 SMP Completion (Bob verifies Alice)

`Bob` computes expected `proof_2` and verifies.

**If valid**: mutual key verification established.

*Both* clients mark each others per-contact keys as verified locally.
Now those keys serve as "root of trust" for Perfect Forward Secrecy (PFS) ephemeral keys exchanges.

### 4.6. SMP Security notes

Per-contact keypairs ensure compartmentalization of trust, we don't re-use our main authentication key for optimal cryptographic hygiene.

Verification security depends on entropy of the answer, `SMP` verification must occur within a relatively short timeframe to avoid brute-force feasibility.

`SMP` answer entropy doesn't have to be astronomically large, it just has to have enough entropy to be uncrackable for the duration of the `SMP` verification process.

Server remains unaware of trust relationships. Server is not aware of verification success. Verification is end-to-end.

The reason we use `per-contact keys` instead of our main identity keys is for **plausible unlinkability**, because `per-contact keys` are only exchanged *briefly*.

Neither `Alice` nor `Bob` can prove each other's ownership defintively. 

This **plausible unlinkability** only occurs if the server wasn't always malicious. (I.e. the server did not log `Alice` nor `Bob` requests containing their public_key).

This **plausible unlinkability** only occurs if the server was compromised *After* SMP verification is complete.

Additionally, this **plausible unlinkability** will be the basis on which we build **plausible deniability** later on with `OTP` pads and `PFS`.

`SMP` verification, if done relatively quickly with an answer with sufficent entropy, provides an *unbreakable mathematical guarantee of authenticity* and integrity for the verification of the keys (Assuming no hash collisions).

## 5. Perfect Forward Secrecy
Perfect Forward Secrecy (PFS) ensure that if a ML-KEM-1024 keypair was compromised, it does not affect keys before, and after it.  

### 5.1. Assumptions
`Alice` wants to generate / rotate ephemeral `ML-KEM-1024` (`Kyber1024`) keys with `Bob`.

`Alice` and `Bob` have verified each other's `per-contact` keys using `SMP`

`Alice` is the `SMP` initiator. 

### 5.2. PFS Exchange
`Alice` generates new ephemeral `ML-KEM-1024` keypair and signs them with her `per-contact` keys for `Bob`

`Alice` then checks if she already has a last `hash chain` state for `Bob`, if not, she generates new `hash chain` initial seed:
```python
hash_chain_seed  = random_bytes(32)
```
And saves it in her local state file.


Afterwards, `Alice` computes the next hash in the chain:
```python
next_hash_chain = sha3_512(last_hash_chain_state) 
```

Then adds `next_hash_chain` to start of her `Kyber` public key
```python
kyber_publickey_hashchain = next_hash_chain + kyber_public_key
```

And then she signs the result with her `per-contact` (`Dilithium5`) key, and sends:
```json
[POST] /pfs/send_keys

{
    "kyber_publickey_hashchain": "kyber_publickey_hashchain base64 encoded",
    "kyber_hashchain_signature": "the signature of kyber_publickey_hashchain base64 encoded",
    "recipient": "Bob's user ID"
}
```

`Bob` receives, base64 decodes, and verifies the signature, and if valid, he first checks if he has a last `hash chain` state for `Alice`, if not, he sets the first `64 bytes` of `kyber_publickey_hashchain` as the last `hash chain` state.

If he already had a last `hash chain` state for `Alice`, he would compute it, and compare it with the hash chain `Alice` bundled in `kyber_publickey_hashchain`, and only proceeds if valid.

`Bob` then saves `Alice`'s ephemeral `Kyber1024` public key by extracting `1568 bytes` starting after the first `64 bytes` of `kyber_publickey_hashchain`.

Then `Bob` does the same as `Alice` did, generating his own `hash chain` seed if needed, generating new ephemeral `Kyber1024` keypair, and sending it back to `Alice`

`Alice` then does the same verification steps `Bob` did, and saves his key.

Now `Alice` and `Bob` both have each other ephemeral public keys, Have successfully rotated their ephemeral keys.

### 5.3. PFS rotation counters
`Alice` stores a `rotate_at` and `rotation_counter` variables alongside her ephemeral keys, locally.

`rotation_counter` and `rotate_at` are reset whenever `PFS` keys rotate.

Those counters will be used in `6. Messages` to determine when it is time to rotate ephemeral keys.

### 5.4. Security notes
We use `hash chain`s for replay protection. 

The reason we opted for a `hash chain` instead of a simple `replay_counter`, is to hide the crucial metadata of how many key rotations happened and in which order. This help us later on build plausible deniability

We also use `per-contact` keys (`ML-DSA-87`) for tampering and spoofing detection & protection.


## 6. Messages
Coldwire uses One-Time-Pads (OTP) for encrypting message content.
Pads are shared using `PFS` ephemeral `Kyber1024` keys

### 6.1. Assumptions
`Alice` wants to send a 
```python
"Hello, World!"
``` 
message to `Bob`

`Alice` and `Bob` are already `SMP` verified, and have exchanged their ephemeral keys

### 6.2. Message prepartions
Before `Alice` sends her message to `Bob`, she checks if `rotate_at` equals the `rotation_counter`, if positive, she first rotates her ephemeral keys with `Bob` (see `5. Perfect Forward Secrecy` for more details).

If negative, she calculates if she has enough pads for the `message`, the `64 byte` `hash-chain`, `padding`, and `padding_length` headers, this is calculated like:
```python
OTP_PADDING_LIMIT  = 1024
OTP_PADDING_LENGTH = 2

message = "Hello, World!".encode("utf-8")

next_hash_chain = sha3_512(last_hash_chain + message)

message = next_hash_chain + message

message_otp_padding_length = max(0, OTP_PADDING_LIMIT - OTP_PADDING_LENGTH - len(message))
alice_pads = b"" # Empty

# If length of our message, UTF-8 encoded, with OTP padding length is greater than our available pads 
if len(message) + OTP_PADDING_LENGTH + message_otp_padding_length > len(alice_pads):
    generate_pads()

```

`OTP_PADDING_LENGTH` is `2 bytes`, which can hold up to `65535 bytes` of `padding`.
If `message` length is greater than `OTP_PADDING_LIMIT`, the message is not padded.

Unlike in `5. Perfect Forward Secrecy`, our `hash_chain` here provides both replay protection *and* tampering protection. The reason we don't utilize the `per-contact` keys for signing the message, is to provide plausible deniability.

Messages could been forged by `Bob`.

### 6.3. OTP Pad Generation
If in `6.2. Message Prepartions`, `Alice` did not have enough pads, she would need to generate and sends pads to `Bob`.

`Alice` increments her `rotation_counter` local variable.

`Alice` uses `Bob` ephemeral `Kyber1024` public-key to generate `OTP_PAD_SIZE bytes` of `shared secrets`. `OTP_PAD_SIZE` is default to `11264 bytes` (around 11 Kilobytes)

Those `shared secrets` are now `Alice`'s OTP pads.

The ciphertext result of `Kyber1024` is signed using `per-contact` keys and is sent to `Bob`:
```json
[POST] /messages/send_pads
{
    "otp_hashchain_ciphertext": "Base64 encoded Kyber1024 ciphertext",
    "otp_hashchain_signature": "Base64 encoded signature of ciphertext",
    "recipient": "Bob's user ID"
}
```

`Bob` receives, and decapsulates the `shared secret`s, and treats the first `64 bytes` of the `shared secret`s as the `hash chain` initial seed.

`Bob` then saves both the pad and the `hash chain` seed locally as `Alice`'s.

`Bob` will use that pad to decrypt future messages sent by `Alice`.

`Bob` will also use that `hash chain` to verify messages were not tampered with, nor replayed.

### 6.4. Message sending
Now `Alice` have enough pads to send her messages, and `Bob` has enough pads to decrypt `Alice`'s messages.

`Alice` then proceeds to pad & encrypt her message:
```python
padding = random_bytes(message_otp_padding_length)
padding_len = len(padding).to_bytes(OTP_PADDING_LENGTH, "big") # Big endian
padded_message = padding_len + message + padding 

encrypted_message = otp_encrypt_func(padded_message, alice_pads[:len(padded_message)])
```

Now `Alice` can send her message to `Bob`:
```json
[POST] /messages/send_message
{
    "message_encrypted": "encrypted_message base64 encoded",
    "recipient": "Bob's user ID"
}
```

`Bob` receives, decrypts the message, reads size of padding by reading first `2 bytes` and discards the padding, verifies hash chain, and finally, if valid, `Bob` `client` displays the message.


### 6.5. Security notes
Even though we utilize OTP encryption, which is unbreakable if used right, we ultimately share the pads using `ML-KEM-1024` (`Kyber1024`). 

The unbreakable property of OTPs is only true if the `Kyber1024` was not intercepted, if it were, the security becomes `Kyber1024` security.

Even in worst scenario where `OTP` security = `Kyber1024` security, our protocol still is arguebly more secure than most other messaging protocols.

To summarize: 

**Best case scenario**: Your messages could never be broken, no matter how much computing power your adversary has.

**Worst case scenario**: `OTP` has inherited `Kyber1024` security.

If we compare the *worst case* scenario to a typical `Kyber` + `AES` scheme, our scheme would be arguably more secure because we rely only on **one** hard problem. If `Kyber` holds, everything is safe, if `Kyber` breaks, both scheme fail.

With the `Kyber` + `AES` scheme, you've now doubled your dependecy, significantly increasing the attack-surface.

So our `Kyber` + `OTP` can be thought of as just `Kyber` under *worst case* scenario. Which is still significantly better than most other encrypted protocols, because we now only trust a single-primitive.

Additionally, `OTP` has no modes, no nonces, no padding quirks, no classes of attacks and bugs. Making it incredibly easy to implement in comparsion to `AES` which is fairly complex, and even when implemented per-spec, would still deliever argueably worse security than our `OTP` scheme.

## Security Considerations & Threat Model
Coldwire is designed for:
- Post-quantum confidentiality and authentication.

- Minimal metadata exposure (no timestamps, usernames, presence, contact lists, delivery logs, or message logging).

- Perfect forward secrecy (PFS) via frequent key rotation and one-time pad session material.

Coldwire does not attempt to defend against:

- Traffic analysis at the network layer (timing correlation outside the server).

- Compromise of endpoints (malware, key theft from device).

- Server compromise during per-contact SMP verification (may weaken plausible deniability).

- Attacks exploiting weak SMP shared secrets (low-entropy user-defined answers).

Coldwire assumes:

- The post-quantum primitives (`ML-KEM-1024`, `ML-DSA-87`) remain secure against both classical and quantum adversaries.

- Open-Quantum Safe library correctly implements the post-quantum primitives.

- Users securely verify per-contact keys before exchanging sensitive messages.

Future versions may:
- Add group chat support
- Hydrid traditional encryption alongside Post-Quantum encryption
- Improve support for offline messaging



And lastly, our protocol is experimental, Coldwire is not meant to be the next Signal, or Matrix. Instead, we aim to be the most secure messenger available, even if it costs us some usability trades for security.

