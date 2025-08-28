from core.requests import http_request
from logic.storage import save_account_data
from core.crypto import (
    generate_kem_keys,
    verify_signature,
    create_signature,
    random_number_range
)
from core.constants import (
    ML_KEM_1024_NAME,
    CLASSIC_MCELIECE_8_F_NAME,
)
from core.trad_crypto import sha3_512
from base64 import b64encode, b64decode
import secrets
import copy
import json
import logging

logger = logging.getLogger(__name__)


def send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue) -> None:
    with user_data_lock:
        user_data_copied = copy.deepcopy(user_data)

  
    server_url = user_data_copied["server_url"]
    auth_token = user_data_copied["token"]

    lt_sign_private_key = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["private_key"]
    
    # Check if we already have a hash chain for ourselves
    if not user_data_copied["contacts"][contact_id]["lt_sign_keys"]["our_hash_chain"]:
        with user_data_lock:
            # Set up the hash chain's initial seed
            user_data["contacts"][contact_id]["lt_sign_keys"]["our_hash_chain"] = secrets.token_bytes(64)
            
            our_hash_chain = user_data["contacts"][contact_id]["lt_sign_keys"]["our_hash_chain"] 
    else:
        our_hash_chain = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["our_hash_chain"] 
        # We continue the hash chain
        our_hash_chain = sha3_512(our_hash_chain)

    # Generate new Kyber1024 keys for us
    kyber_private_key, kyber_public_key = generate_kem_keys(ML_KEM_1024_NAME)

    # Sign them with our per-contact long-term private key
    kyber_key_hashchain_signature = create_signature("Dilithium5", our_hash_chain + kyber_public_key, lt_sign_private_key)
    
    payload = {
            "kyber_publickey_hashchain": b64encode(our_hash_chain + kyber_public_key).decode(),
            "kyber_hashchain_signature": b64encode(kyber_key_hashchain_signature).decode(),
            "recipient"                : contact_id,
        }


    try:
        http_request(f"{server_url}/pfs/send_keys", "POST", payload=payload, auth_token=auth_token)
    except Exception:
        ui_queue.put({"type": "showerror", "title": "Error", "message": "Failed to send our ephemeral keys to the server"})
        return
    

    # We update at the very end to ensure if any of previous steps fail, we do not desync our state
    with user_data_lock:

        user_data["tmp"]["new_ml_kem_keys"][contact_id] = {
                "private_key": kyber_private_key,
                "public_key": kyber_public_key
            }

        user_data["contacts"][contact_id]["lt_sign_keys"]["our_hash_chain"] = our_hash_chain

        # Set rotation counters to rotate every 2 pad batches sent
        # TODO: Maybe rotate on every batch instead? and rework the counters, like we don't even need counters if we rotate on every batch sent.
        # ANOTHER NOTE: Uhhh, why we doing this with mceliece in here??? Just fucking move it
        user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotation_counter"] = 0
        user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotate_at"] = 2




def update_ephemeral_keys(user_data, user_data_lock) -> None:
    with user_data_lock:
        new_ml_kem_keys = user_data["tmp"]["new_ml_kem_keys"]

    for contact_id, v in new_ml_kem_keys.items():
        with user_data_lock:
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][ML_KEM_1024_NAME]["private_key"] = v["private_key"]
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][ML_KEM_1024_NAME]["public_key"] = v["public_key"]

    if len(new_ml_kem_keys) != 0:
        with user_data_lock:
            user_data["tmp"]["new_ml_kem_keys"] = {}

        save_account_data(user_data, user_data_lock)




def pfs_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, message) -> None:
    contact_id = message["sender"]

    if contact_id not in user_data_copied["contacts"]:
        logger.error("Contact is missing, maybe we (or they) are not synced? Not sure, but we will ignore this PFS request for now")
        logger.debug("Our saved contacts: %s", json.dumps(user_data_copied["contacts"], indent=2))
        return

    # Contact's main long-term public signing key
    contact_lt_public_key = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"]


    if not contact_lt_public_key:
        logger.error("Contact long-term signing key is missing... 0 clue how we reached here, but we aint continuing..")
        return 

    if not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["verified"]:
        logger.error("Contact long-term signing key is not verified! it is possible that this is a MiTM attack, we ignoring this PFS for now.")
        return

    contact_kyber_hashchain_signature = b64decode(message["kyber_hashchain_signature"], validate=True)
    contact_kyber_publickey_hashchain = b64decode(message["kyber_publickey_hashchain"], validate=True)

    valid_signature = verify_signature("Dilithium5", contact_kyber_publickey_hashchain, contact_kyber_hashchain_signature, contact_lt_public_key)
    if not valid_signature:
        logger.error("Invalid ephemeral kyber public-key + hashchain signature! possible MiTM ?")
        return


    contact_kyber_public_key = contact_kyber_publickey_hashchain[64:]
    contact_hash_chain       = contact_kyber_publickey_hashchain[:64]

    # If we do not have a hashchain for the contact, we don't need to compute the chain, just save.
    if not user_data_copied["contacts"][contact_id]["lt_sign_keys"]["contact_hash_chain"]:
        with user_data_lock:
            user_data["contacts"][contact_id]["lt_sign_keys"]["contact_hash_chain"] = contact_hash_chain
    
    else:
        contact_last_hash_chain = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["contact_hash_chain"]
        contact_last_hash_chain = sha3_512(contact_last_hash_chain)

        if contact_last_hash_chain != contact_hash_chain:
            logger.error("Contact hash chain does not match our computed hash chain, we are skipping this PFS message...")
            return

    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_keys"]["contact_hash_chain"] = contact_hash_chain
        user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_keys"][ML_KEM_1024_NAME] = contact_kyber_public_key

        our_kyber_private_key = user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][ML_KEM_1024_NAME]["private_key"]

    if our_kyber_private_key is None:
        send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue)

    save_account_data(user_data, user_data_lock)

    logger.info("contact (%s) has rotated their Kyber keys", contact_id)

