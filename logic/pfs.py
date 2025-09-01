"""
    logic/pfs.py
    -----------------
    Handles Perfect Forward Secrecy (PFS) ephemeral keys exchange and rotation for contacts.

    Handles:
    - Generates and rotates ephemeral (one-time use) ML-KEM-1024 keys and (medium-term) Classic McEliece keys.
    - Uses per-contact hash chains to prevent replay attacks, and verifies authenticity using ML-DSA-87.
    - Sends and receives signed ephemeral keys using long-term signing keys.
    - Updates local account storage with new key material after successful exchange.
"""

from core.requests import http_request
from logic.storage import save_account_data
from core.crypto import (
    generate_kem_keys,
    verify_signature,
    create_signature,
    random_number_range
)
from core.constants import (
    ALGOS_BUFFER_LIMITS,
    ML_KEM_1024_NAME,
    ML_DSA_87_NAME,
    ML_KEM_1024_PK_LEN,
    ML_DSA_87_SIGN_LEN,
    XCHACHA20POLY1305_NONCE_LEN,
    CLASSIC_MCELIECE_8_F_NAME,
    CLASSIC_MCELIECE_8_F_PK_LEN,
    CLASSIC_MCELIECE_8_F_ROTATE_AT,
    KEYS_HASH_CHAIN_LEN
)
from core.trad_crypto import (
        sha3_512,
        encrypt_xchacha20poly1305,
        decrypt_xchacha20poly1305
)
from base64 import b64encode, b64decode
import secrets
import copy
import json
import logging
import threading
import queue

logger = logging.getLogger(__name__)


def send_new_ephemeral_keys(user_data: dict, user_data_lock: threading.Lock, contact_id: str, ui_queue: queue.Queue) -> None:
    """
    Generate, encrypt, and send fresh ephemeral keys to a contact.

    - Maintains a per-contact hash chain for signing key material.
    - Generates new Kyber1024 keys every call.
    - Optionally rotates McEliece keys if rotation threshold is reached.
    - Signs all key material with the long-term signing key.
    - Sends to the server using an authenticated HTTP request.
    - If successful, stores new keys in `user_data["tmp"]` for later update.

    Args:
        user_data (dict): Shared user account state.
        user_data_lock (threading.Lock): Lock protecting shared state.
        contact_id (str): Target contact's ID.
        ui_queue (queue.Queue): UI queue for showing error messages.
    """

    with user_data_lock:
        user_data_copied = copy.deepcopy(user_data)
 
    server_url       = user_data_copied["server_url"]
    auth_token       = user_data_copied["token"]
    
    our_strand_key     = user_data_copied["contacts"][contact_id]["our_strand_key"]

    rotation_counter = user_data_copied["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotation_counter"] 
    rotate_at        = user_data_copied["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotate_at"]

    lt_sign_private_key = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["private_key"]
    
    # Check if we already have a hash chain for ourselves
    if not user_data_copied["contacts"][contact_id]["lt_sign_keys"]["our_hash_chain"]:
        with user_data_lock:
            # Set up the hash chain's initial seed
            user_data["contacts"][contact_id]["lt_sign_keys"]["our_hash_chain"] = secrets.token_bytes(KEYS_HASH_CHAIN_LEN)
            
            our_hash_chain = user_data["contacts"][contact_id]["lt_sign_keys"]["our_hash_chain"] 
    else:
        our_hash_chain = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["our_hash_chain"] 
        # We continue the hash chain
        our_hash_chain = sha3_512(our_hash_chain)

    # Generate new ML-KEM-1024 keys for us
    kyber_private_key, kyber_public_key = generate_kem_keys(ML_KEM_1024_NAME)
    publickeys_hashchain = our_hash_chain + kyber_public_key

    rotate_mceliece = False
    if (rotate_at == rotation_counter) or (user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["private_key"] is None):
        mceliece_private_key, mceliece_public_key = generate_kem_keys(CLASSIC_MCELIECE_8_F_NAME)
        publickeys_hashchain += mceliece_public_key
        rotate_mceliece = True

    # Sign them with our per-contact long-term private key
    publickeys_hashchain_signature = create_signature(ML_DSA_87_NAME, publickeys_hashchain, lt_sign_private_key)


    ciphertext_nonce, ciphertext_blob = encrypt_xchacha20poly1305(
            our_strand_key, 
            publickeys_hashchain_signature + publickeys_hashchain
        )

    try:
        http_request(f"{server_url}/pfs/send_keys", "POST", payload={
                "ciphertext_blob": b64encode(ciphertext_nonce + ciphertext_blob).decode(),
                "recipient"      : contact_id,
            }, auth_token=auth_token)
    except Exception:
        ui_queue.put({"type": "showerror", "title": "Error", "message": "Failed to send our ephemeral keys to the server"})
        return
    

    # We update at the very end to ensure if any of previous steps fail, we do not desync our state
    with user_data_lock:

        user_data["tmp"]["new_ml_kem_keys"][contact_id] = {
                "private_key": kyber_private_key,
                "public_key": kyber_public_key
            }
        
        if rotate_mceliece:
            user_data["tmp"]["new_code_kem_keys"][contact_id] = {
                "private_key": mceliece_private_key,
                "public_key": mceliece_public_key
            }

            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotation_counter"] = 0
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotate_at"]        = CLASSIC_MCELIECE_8_F_ROTATE_AT




        user_data["contacts"][contact_id]["lt_sign_keys"]["our_hash_chain"] = our_hash_chain



def update_ephemeral_keys(user_data: dict, user_data_lock: threading.Lock) -> None:
    """
    Commit newly generated ephemeral keys to permanent storage.

    - Moves keys from `user_data["tmp"]` into `user_data["contacts"]`.
    - Clears temporary key buffers after update.
    - Saves account state to disk.

    Args:
        user_data (dict): Shared user account state.
        user_data_lock (threading.Lock): Lock protecting shared state.
    """
    with user_data_lock:
        new_ml_kem_keys = user_data["tmp"]["new_ml_kem_keys"]
        new_code_kem_keys = user_data["tmp"]["new_code_kem_keys"]

    for contact_id, v in new_ml_kem_keys.items():
        with user_data_lock:
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][ML_KEM_1024_NAME]["private_key"] = v["private_key"]
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][ML_KEM_1024_NAME]["public_key"] = v["public_key"]

    for contact_id, v in new_code_kem_keys.items():
        with user_data_lock:
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["private_key"] = v["private_key"]
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["public_key"] = v["public_key"]


    with user_data_lock:
        user_data["tmp"]["new_ml_kem_keys"] = {}
        user_data["tmp"]["new_code_kem_keys"] = {}

    
    save_account_data(user_data, user_data_lock)




def pfs_data_handler(user_data: dict, user_data_lock: threading.Lock, user_data_copied: dict, ui_queue: queue.Queue, message: dict) -> None:
    """
    Handle incoming PFS (Perfect Forward Secrecy) key messages from contacts.

    - Validates the contact exists and their signing key is verified.
    - Verifies the signature on the ephemeral keys + hash chain.
    - Updates stored contact ephemeral keys and hash chains.
    - If we don't have keys yet for this contact, triggers sending ours.
    - Saves updated account state to disk.

    Args:
        user_data (dict): Shared user account state.
        user_data_lock (threading.Lock): Lock protecting shared state.
        user_data_copied (dict): A read-only copy of user_data for consistency.
        ui_queue (queue.Queue): UI queue for notifications/errors.
        message (dict): Incoming PFS message from the server.
    
    Returns:
        None
    """
    contact_id = message["sender"]

    if contact_id not in user_data_copied["contacts"]:
        logger.error("Contact is not saved., maybe we (or they) are not synced? Ignoring this PFS message.")
        logger.debug("Our saved contacts: %s", str(user_data_copied["contacts"]))
        return

    # Contact's per-contact signing public-key
    contact_lt_public_key = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"]
    
    contact_strand_key = user_data_copied["contacts"][contact_id]["contact_strand_key"]

    if not contact_lt_public_key:
        logger.error("Contact long-term signing key is missing... 0 clue how we reached here, but we aint continuing..")
        return 

    if not contact_strand_key:
        logger.error("Contact strand key key is missing... 0 clue how we reached here, but we aint continuing..")
        return 


    if not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["verified"]:
        logger.error("Contact long-term signing key is not verified! We will ignore this PFS message.")
        return

    ciphertext_blob = b64decode(message["ciphertext_blob"], validate = True)
    
    # Everything from here is not validated by server
    try:
        pfs_plaintext = decrypt_xchacha20poly1305(contact_strand_key, ciphertext_blob[:XCHACHA20POLY1305_NONCE_LEN], ciphertext_blob[XCHACHA20POLY1305_NONCE_LEN:])
    except Exception as e:
        logger.error("Failed to decrypt `ciphertext_blob` from contact (%s) with error: %s", contact_id, str(e))
        return

    if (len(pfs_plaintext) < ML_KEM_1024_PK_LEN + ML_DSA_87_SIGN_LEN + KEYS_HASH_CHAIN_LEN) or len(pfs_plaintext) > ML_KEM_1024_PK_LEN + ML_DSA_87_SIGN_LEN + CLASSIC_MCELIECE_8_F_PK_LEN + KEYS_HASH_CHAIN_LEN:
        logger.error("Contact (%s) gave us a PFS request with malformed strand plaintext length (%d)", contact_id, len(pfs_plaintext))
        return

    contact_hashchain_signature  = pfs_plaintext[:ML_DSA_87_SIGN_LEN]
    contact_publickeys_hashchain = pfs_plaintext[ML_DSA_87_SIGN_LEN:]

    contact_hash_chain           = contact_publickeys_hashchain[:KEYS_HASH_CHAIN_LEN]

    try:
        valid_signature = verify_signature(ML_DSA_87_NAME, contact_publickeys_hashchain, contact_hashchain_signature, contact_lt_public_key)
        if not valid_signature:
            logger.error("Invalid ephemeral public-key + hashchain signature from contact (%s)", contact_id)
            return
    except Exception as e:
        logger.error("Contact (%s) gave us a PFS request with malformed strand signature which generated this error: %s", contact_id, str(e))
        return


    # If we do not have a hashchain for the contact, we don't need to compute the chain, just save.
    if not user_data_copied["contacts"][contact_id]["lt_sign_keys"]["contact_hash_chain"]:
        with user_data_lock:
            user_data["contacts"][contact_id]["lt_sign_keys"]["contact_hash_chain"] = contact_hash_chain
    
    else:
        contact_last_hash_chain = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["contact_hash_chain"]
        contact_last_hash_chain = sha3_512(contact_last_hash_chain)

        if contact_last_hash_chain != contact_hash_chain:
            logger.error("Contact keys hash chain does not match our computed hash chain! Skipping this PFS message...")
            return

    contact_kyber_public_key = contact_publickeys_hashchain[KEYS_HASH_CHAIN_LEN: ALGOS_BUFFER_LIMITS[ML_KEM_1024_NAME]["PK_LEN"] + KEYS_HASH_CHAIN_LEN]

    if len(contact_publickeys_hashchain) == ML_KEM_1024_PK_LEN + CLASSIC_MCELIECE_8_F_PK_LEN + KEYS_HASH_CHAIN_LEN:
        logger.info("contact (%s) has rotated their Kyber and McEliece keys", contact_id)

        contact_mceliece_public_key = contact_publickeys_hashchain[ALGOS_BUFFER_LIMITS[ML_KEM_1024_NAME]["PK_LEN"] + KEYS_HASH_CHAIN_LEN:]
        with user_data_lock:
            user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_keys"][CLASSIC_MCELIECE_8_F_NAME] = contact_mceliece_public_key

    elif len(contact_publickeys_hashchain) == ML_KEM_1024_PK_LEN + KEYS_HASH_CHAIN_LEN:
        logger.info("contact (%s) has rotated their Kyber keys", contact_id)

    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_keys"]["contact_hash_chain"] = contact_hash_chain
        user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_keys"][ML_KEM_1024_NAME] = contact_kyber_public_key

        our_kyber_private_key = user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][ML_KEM_1024_NAME]["private_key"]
        our_mceliece_private_key = user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["private_key"]

        new_ml_kem_keys = user_data["tmp"]["new_ml_kem_keys"]
        new_code_kem_keys = user_data["tmp"]["new_code_kem_keys"]

    if (our_kyber_private_key is None or our_mceliece_private_key is None) and ((contact_id not in new_ml_kem_keys) and (contact_id not in new_code_kem_keys)):
        logger.info("We are sending the contact (%s) our ephemeral keys because we didnt do it before.", contact_id)
        send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue)

    save_account_data(user_data, user_data_lock)

