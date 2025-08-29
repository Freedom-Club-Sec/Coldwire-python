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
    CLASSIC_MCELIECE_8_F_NAME,
    CLASSIC_MCELIECE_8_F_ROTATE_AT
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
        
        rotation_counter = user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotation_counter"] 
        rotate_at = user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotate_at"]

        server_url = user_data["server_url"]
        auth_token = user_data["token"]

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
    publickeys_hashchain = our_hash_chain + kyber_public_key

    pfs_type = "partial"
    if (rotate_at == rotation_counter) or (user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["private_key"] is None):
        mceliece_private_key, mceliece_public_key = generate_kem_keys(CLASSIC_MCELIECE_8_F_NAME)
        publickeys_hashchain += mceliece_public_key
        pfs_type = "full"

    # Sign them with our per-contact long-term private key
    publickeys_hashchain_signature = create_signature("Dilithium5", publickeys_hashchain, lt_sign_private_key)
    
    payload = {
            "publickeys_hashchain": b64encode(publickeys_hashchain).decode(),
            "hashchain_signature" : b64encode(publickeys_hashchain_signature).decode(),
            "recipient"           : contact_id,
            "pfs_type"            : pfs_type
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
        
        if pfs_type == "full":
            user_data["tmp"]["new_code_kem_keys"][contact_id] = {
                "private_key": mceliece_private_key,
                "public_key": mceliece_public_key
            }

            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotation_counter"] = 0
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotate_at"] = CLASSIC_MCELIECE_8_F_ROTATE_AT




        user_data["contacts"][contact_id]["lt_sign_keys"]["our_hash_chain"] = our_hash_chain



def update_ephemeral_keys(user_data, user_data_lock) -> None:
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

    contact_hashchain_signature = b64decode(message["hashchain_signature"], validate=True)
    contact_publickeys_hashchain = b64decode(message["publickeys_hashchain"], validate=True)

    valid_signature = verify_signature("Dilithium5", contact_publickeys_hashchain, contact_hashchain_signature, contact_lt_public_key)
    if not valid_signature:
        logger.error("Invalid ephemeral public-key + hashchain signature from contact (%s)", contact_id)
        return

    if message["pfs_type"] not in ["full", "partial"]:
        logger.error("contact (%s) sent message of unknown pfs_type (%s)", contact_id, message["pfs_type"])
        return

    contact_hash_chain = contact_publickeys_hashchain[:64]

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

    contact_kyber_public_key = contact_publickeys_hashchain[64: ALGOS_BUFFER_LIMITS[ML_KEM_1024_NAME]["PK_LEN"] + 64]
    if message["pfs_type"] == "full":
        logger.info("contact (%s) has rotated their Kyber and McEliece keys", contact_id)

        contact_mceliece_public_key = contact_publickeys_hashchain[ALGOS_BUFFER_LIMITS[ML_KEM_1024_NAME]["PK_LEN"] + 64:]
        with user_data_lock:
            user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_keys"][CLASSIC_MCELIECE_8_F_NAME] = contact_mceliece_public_key

    elif message["pfs_type"] == "partial":
        logger.info("contact (%s) has rotated their Kyber keys", contact_id)

    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_keys"]["contact_hash_chain"] = contact_hash_chain
        user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_keys"][ML_KEM_1024_NAME] = contact_kyber_public_key

        our_kyber_private_key = user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][ML_KEM_1024_NAME]["private_key"]
        our_mceliece_private_key = user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["private_key"]

        new_ml_kem_keys = user_data["tmp"]["new_ml_kem_keys"]
        new_code_kem_keys = user_data["tmp"]["new_code_kem_keys"]

    if (our_kyber_private_key is None or our_mceliece_private_key is None) and ((contact_id not in new_ml_kem_keys) and (contact_id not in new_code_kem_keys)):
        send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue)
        logger.info("We are sending the contact (%s) our ephemeral keys because we didnt do it before.", contact_id)

    save_account_data(user_data, user_data_lock)

