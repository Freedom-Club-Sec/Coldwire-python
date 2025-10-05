# Coldwire Protocol Specification
Version: **`1.0`**

Date: **`2025-09-09`**

Author(s): **`ChadSec1`** (**`Freedom Club Sec`**)

Contact: github.com/Freedom-Club-Sec

Status: **`Work-in-progress`**

Intended Audience: Security engineers, cryptographers, protocol implementers

### 0. Overview

The *`Coldwire`* Protocol is a federated, metadata-resistant, censorship-resistant chat protocol, built on top of HTTP protocol. The purpose of the protocol is to simply relay messages between users and or other servers running *Coldwire*, in a way that does not include any metadata except "ciphertext in", "ciphertext out", and a random "mailbox" user identifier

*`Coldwire`* protocol is designed to evade censorship, and usage detection, by network adversaries (LAN Router-controlling adversaries, ISP adversaries, etc) by blending in with regular browser traffic. It's also designed so that a malicious server, cannot replay nor tamper with requests, and cannot learn any metadata beyond the sender and receiver `User-IDs`.

The protocol incorporates the `Strandlock` protocol, which is an end-to-end encrypted protocol. It handles confidentity, integrity, and authenticity in a user-to-user manner, making our protocol simple because we do not have to implement replay nor tampering protection ourselves, it is handled by the users. 

Additionally, `Strandlock` protocol,  aids with traffic obfsucation by padding every request differently.

### 1. Terminology

For clarity, the following terms are used consistently throughout this specification:

#### Request (`message`, `ciphertext`)
A generic protocol message sent from one party to another, via sending it to a Coldwire server to relay it.

#### Response (`message`, `ciphertext`)
The reply to a Request, carrying the necessary protocol data to complete or continue a Strandlock operation.
We use term "Response" and "Request" interchangably. A response is a request that's given to a party by `Coldwire` server.

#### User-ID (`identifier`)
A long-term, randomly generated identifier which consists of a 16 digits string. It is generated on the server when a user first "registers" on a `Coldwire` server.  

#### User federation ID (`federation identifier`)
A `user-ID` with the URL of the `Coldwire` server appended at the end of it, separated by a `@` (i.e. `1234567890123456@example.com`).

#### User Public-Key (`signing public-key`)
A `ML-DSA-87` public-key, saved on the `Coldwire` server, tied to a specific `User-ID`

#### User Private-Key (`signing private key`, `signing key`)
A `ML-DSA-87` private-key, private key is stored on the user's device locally, and the public-key is stored on the `Coldwire` server as the `signing public-key`.

#### Client Implementation
Refers to a user-client implementation of the `Coldwire protocol`.

#### Server implementation
Refers to a server implementation of the `Coldwire protocol`.

#### General Acknowledgements:
When new data for a user is insert, implementations must append a random id (`32 bytes`), and when user longpolls for data, implementations must check to see if there exists ack paramaters ids, and remove all data starting with the supplied ids.


### 2. HTTP Requests
#### 2.1. Client Headers
`Coldwire` client implementations *must* mimick mainstream, popular browsers headers.

All `Coldwire` client implementations *must* adhere to the following requirements for `HTTP` requests:
- *All* `HTTP` field headers name **must** be lower-case, for compatiability with `HTTP/2` servers.
The HTTP specification requires it, needed incase a Coldwire server implementation is behind another server.

- *All* header fields must be sent in the same exact order that the browser in question orders them.
Helps against network requests fingerprinting.
- Implementations **must** randomly pick a single browser and mimic its headers, and use them for the duration of the session
If you rotate header sets between different requests, that creates a unique fingerprint to network adversaries, so avoid.



#### 2.2. Federated servers headers
`Coldwire` server implementations *must* adhere to the following requirements for `HTTP` requests:
- You **must not** include any headers that may indicate to a server you're intending to receive compressed (gzip, etc) response!
 
- Your `Coldwire` server implementation **must not** return any compressed responses. Return responses as raw uncompressed bytes.

- *All* `HTTP` field headers name **must** be lower-case, for compatiability with `HTTP/2` servers.
The HTTP specification requires it, needed incase a Coldwire server implementation is behind another server.



### 3. Authentication
In `Coldwire` there is no concept of `registration` or `login`, instead, a user generates their `ML-DSA-87` keypair, sends the `public_key` to server, then authenticates by signing the given challenge.

The request payload **must** be in `JSON`, and the response will also be in `JSON`. 

**note** that `JSON` requests and responses only applies for the *authentication API* endpoints.

The `JWT` algorithm must be `HS512` (`SHA-3-512`)

#### 3.1. Authentication Initialization (`Alice`)
`Alice` sends an HTTP `POST` request to the endpoint running `Coldwire`
```
URL: example.com/authenticate/init
```

**If** its `Alice's` first time authenticating to the server, she must not bundle a `user_id` field, only a *base64-encoded* `public_key` field, `JSON` payload:
```json
{
    "public_key": "base64_encoded_public_key"
}
```


**If** `Alice` authenticated at least once before, she **must not** bundle a `public_key` field, only a `user_id` field:
```json
{
    "user_id": "1234567890123456"
}
```


Server responds with a `JSON` response containing a `challenge`, which is a random `64-byte` *base64-encoded* string:
```json
{
    "challenge": "base64_encoded_challenge"
}
```

#### 3.2. Authentication Verification (`Alice`)

`Alice` must decode the `challenge` given to her in `2.1. Initialization` step, and sign it with her `ML-DSA-87` private key, and *base64-encode* the signature, and send it to the server, alongside the challenge string:

```json
{
    "signature": "base64_encoded_signature",
    "challenge": "base64_encoded_challenge"
}
```


After that is done, the server returns a `JSON` response with the `JWT token`, and his user's `User-ID` inside:
```json
{
    "user_id": "1234567890123456",
    "token": "User's JWT Token"
}
```

There is no expiration timestamp in the `JWT token`, the user simply keeps using the same `JWT token` token indefientely, until a server operator decides to rotate their `JWT` secret. 

Even though there are no expiration timestamp, client implementations must always authenticate on application startup.

#### 3.3. Authentication Notes
The reason we do not include an "expiration timestamp" in the `JWT token`, is to help reduce metadata emitting from both the server, and the client.

*Coldwire* server operators are recommended to rotate their `JWT secret` every month for cryptographic hyiegene, if you can rotate it more frequently, that is acceptable. The protocol does not enforce any `JWT secret` rotations.

Additionally, even if a user's `JWT token` is compromised, no catastrophic security issues arise, except potential denial-of-service risks for the user. 

Old messages cannot be retrieved and new messages cannot be read, full contact list cannot be recovered, etc.

New contacts can't be verified because the attacker wouldn't know a contact's `SMP` answer, only the real user does.

If a server `JWT secret` is compromised, no catastrophic security issues arise, except potential denial-of-service risks for the server and its users.

The reason even new messages cannot be read, is because we utilize the `Strandlock protocol` for true end-to-end encryption.

Messages are not just computationally safe, but in some scenarios, the message become uncrackable even with infinite computing power (to an adversary who only has access to a message's ciphertext, and not KEM's ciphertext, in which case OTP security inherits the algorithms in question security properties).

In real world, both a server's `JWT secret` and a user's `JWT token` are highly unlikely to be leaked, unless an endpoint compromise occurs.

`JWT secrets` are highly recommended to be (at least) `128 bytes`. But there are no protocol enforcements regarding this, you can make it as long as you wish.

### 4. Data
`Coldwire`, when `Alice` talks to `Bob`, all the server(s) sees is `Alice's` & `Bob's` `User-ID`, and a ciphertext `blob`.

All requests sent are `HTTP Forms`, with `metadata` as a `Form Field`, and `blob` as a `File Upload`.

All requests sent must bundle an "authorization" header, containing the user's `JWT token`.

#### 4.1. Sending Data (`Alice` -> `Server`)
`Alice` sends data to `Bob` by sending a `POST` request to the `Coldwire` server:
```json
URL: example.com/data/send
```
With `Form` payload:
```json
metadata: {
    "recipient": "Bobs User_ID"
}
```

and bundled within the same request, is a `File Upload` with name `blob`, containing raw bytes (ciphertext, etc)

#### 4.2. Data processor (`Server`)
`Coldwire` server receives data request, verifies the `Alice's` `JWT token`, and checks if the `recipient` is all digits:

if not, checks if `recipient` format is correct (i.e. "1234567890123456@example.com") and sends a request to the target `Coldwire` server.

If `recipient` is all digits, the server checks if they exist in the local database, if not, they return a 400 error. 

If they exist, the `Coldwire` server then processes the `blob`, rejecting it if it's empty.

If the sender or `recipient` contain a "@", request is rejected.

The `Coldwire` server then process the request by constructing a payload which consists of:
```
payload = user_id_utf_8 + \x0 + blob
```

Then the length of the `payload` is calculated, and a `length` prefix of size `3 bytes` in `big-endian` format is inserted at the start of the payload:
```
payload = length_prefix + payload
```


And the data is saved to the `recipient` inbox (any saving medium, can be Redis, SQL database, etc).

#### 4.3. Receiving Data (`Bob` <- `Server`)
`Bob` sends a `GET` request that longpolls the `Coldwire` endpoint:
```
URL: example.com/data/longpoll
```

The `Coldewire` server sends a response of either empty bytes, or many `message_payloads` continunesly concatenated together.

After `Coldwire` server sends a response to `Bob`, it deletes all the previously saved data payloads queue.

`Bob` client parses the response, by using the `length_prefix` at start of each message, `Bob` can separate each message. 

`Bob` then further parses it, by separating a message sender, from the blob, by splitting on the first NULL byte (`\0`)

`Bob` client verifies the format of the `sender` identifier is correct, simply dismissing message if not.

`Bob` then processes the `blob` using the `Strandlock protocol`


#### 4.4. Notes
Replay protection, tampering protection, authentication, MiTM protection, etc, are all handled by the `Strandlock protocol`.

The reason we send request in `Form` and `File Uploads`, and receive back response as `raw bytes`, is to save bandwidth. 
The `Strandlock protocol` can be quite heavy (some ciphertext reaching MBs in size).



### 5. Federation
Federation protocol between different `Coldwire` servers.

All `Coldwire` servers must have a long-term `ML-DSA-87` keypair saved securely, locally.

#### 5.1. Federation Info
All requests payloads and responses are sent and returned in `JSON` format.

When a `Coldwire` server (`server A`) process a request from another `Coldwire` server (`server B`), `server A` checks if they have `server B` public-key saved, if not, they fetch it by sending a `GET` request to the following endpoint:
```
URL: example.com/federation/info
```

The `server_B` constructs a response to be signed:
```
response = server_url_utf_8 + refetch_date_utf_8
```
`server_B_url_utf_8` being the server's own URL, and `refetch_date_utf_8` being the timestamp in UTC for when the requester should refetch the key again, in format:
```
%Y-%m-%d
```

`server B` signs the response with it's private signing key, and returns a `JSON` response of:
```json
{
    "public_key": "base64_encoded_server_public_key"
    "refetch_date": "UTC timestamp of when to refetch key"
    "signature": "base64_encoded_response_signature"
}
```

After `server A` receives the response from `server B`, they verify the signature. If valid, they save the `public_key` and `refetch_date` alongside `server B`'s` URL.


#### 5.2. Federation send
When `Alice` who is using a Coldwire server (`server A`) sends `Bob` a request who is using another Coldwire server (`server B`), `server A` constructs a `Form` payload with field `metadata` and a `File Upload` with file name of `blob`.

The `metadata` field payload data:
```
{
    "recipient": "recipient 16-digits User-ID, no URL",
    "sender": "sender 16-digits User-ID, no URL",
    "url": "server_A URL with no HTTP/S prefixes."
}
```

`server A` also creates a `ML-DSA-87- signature with following data:
```
signature = create_signature(ML_DSA_87_NAME, url.encode("utf-8") + recipient.encode("utf-8") + sender.encode("utf-8") + blob)
```

The `blob` field payload data:
```
blob_payload = signature + blob
```
`blob` being the ciphertext `Alice` is sending to `Bob.


`server B` receives the request, processes it by doing sanity checks against the provided User-IDs (i.e., are they correct format, etc), and sanity checks against provided `url` (is it valid domain and or IP, etc), and it checks if `recipient` exists in the database. If any of checks failed, `server B` must return a 40x error code to `server A`.


`server B` then checks if they have `server A` public-key saved, if not, they fetch and save it (see `5.1. Federation Info`).
`server B` then checks the saved `server A's` refetch_date, if the date is due (=< today), `server B` refetches `server A` public-key.


If all the previous checks and operations succeed, `server B` separates the `signature` from the `blob`:
```
signature = blob[:ML_DSA_87_SIGN_LEN]
```
And sets blob:
```
blob = blob[ML_DSA_87_SIGN_LEN:]
```
`ML_DSA_87_SIGN_LEN` being the signature length that `ML-DSA-87` produces (`4627 bytes`)

Then, `server B` checks signature using `server A's` public-key.
If not valid, `server B` returns a 40x error code.

If valid:
`server B` adds `url` to `sender`, separated by "`@`", then UTF-8 encoding it:
```
sender_with_url_utf_8 = sender + "@" + url
sender_with_url_utf_8 = sender_with_url.encode("utf-8")
```

`server B` then checks if there's a NULL byte in `sender_with_url`, if there is, abort process, and return `40x` status code.

If all checks pass, `server B` stores the data in same way described in `4.2. Data processor (Server)`:
The `Coldwire` server then process the data by constructing a payload which consists of:
```
payload = sender_with_url_utf_8 + \x0 + blob
```
Then the length of the payload is calculated, and a length prefix of size `3 bytes` in `big-endian` format is inserted at the start of the payload:
```
payload = length_prefix + payload
```
And the data is saved to the recipient inbox (any saving medium, can be Redis, SQL database, etc).
