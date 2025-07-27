from core.requests import http_request
from logic.storage import save_account_data
from core.crypto import generate_kem_keys, verify_signature, create_signature, generate_sign_keys, random_number_range
from core.trad_crypto import derive_key_argon2id, sha3_512
from base64 import b64encode, b64decode
import secrets
import hmac
import time
import copy
import json
import logging
import oqs


logger = logging.getLogger(__name__)


def send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue) -> None:
    with user_data_lock:
        user_data_copied = copy.deepcopy(user_data)

  
    server_url = user_data_copied["server_url"]
    auth_token = user_data_copied["token"]

    lt_sign_private_key = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["private_key"]
    
    # Check if we already have a hash chain for ourselves
    if not user_data_copied["contacts"][contact_id]["ephemeral_keys"]["our_hash_chain"]:
        with user_data_lock:
            # Set up the hash chain's initial seed
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_hash_chain"] = secrets.token_bytes(64)
            
            our_hash_chain = user_data["contacts"][contact_id]["ephemeral_keys"]["our_hash_chain"] 
    else:
        our_hash_chain = user_data_copied["contacts"][contact_id]["ephemeral_keys"]["our_hash_chain"] 
        # We continue the hash chain
        our_hash_chain = sha3_512(our_hash_chain)

    # Generate new Kyber1024 keys for us
    kyber_private_key, kyber_public_key = generate_kem_keys()

    # Sign them with our per-contact long-term private key
    kyber_key_hashchain_signature = create_signature("Dilithium5", our_hash_chain + kyber_public_key, lt_sign_private_key)
    
    payload = {
            "kyber_publickey_hashchain": b64encode(our_hash_chain + kyber_public_key).decode(),
            "kyber_hashchain_signature": b64encode(kyber_key_hashchain_signature).decode(),
            "recipient"                : contact_id,
        }


    try:
        response = http_request(f"{server_url}/pfs/send_keys", "POST", payload=payload, auth_token=auth_token)
    except:
        ui_queue.put({"type": "showerror", "title": "Error", "message": "Failed to send our ephemeral keys to the server"})
        return
    

    # We update at the very end to ensure if any of previous steps fail, we do not desync our state
    with user_data_lock:
        user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["private_key"] = kyber_private_key
        user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["public_key"] = kyber_public_key


        # This one should prevent any pad generation and sending, until contact sends us his new ephemeral keys too
        # user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_key"]      = None


        user_data["contacts"][contact_id]["ephemeral_keys"]["our_hash_chain"] = our_hash_chain

        # Set rotation counters to rotate every 2 pad batches sent
        # TODO: Maybe rotate on every batch instead? and rework the counters, like we don't even need counters if we rotate on every batch sent.
        user_data["contacts"][contact_id]["ephemeral_keys"]["rotation_counter"] = 0
        user_data["contacts"][contact_id]["ephemeral_keys"]["rotate_at"] = 2

        # = True, to make it easy for us to delete it later when we receive keys from contact
        user_data["tmp"]["ephemeral_key_send_lock"][contact_id] = True





def pfs_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, message) -> None:
    contact_id = message["sender"]

    if (not (contact_id in user_data_copied["contacts"])):
        logger.error("Contact is missing, maybe we (or they) are not synced? Not sure, but we will ignore this PFS request for now")
        logger.debug("Our saved contacts: %s", json.dumps(user_data_copied["contacts"], indent=2))
        return

    # Contact's main long-term public signing key
    contact_lt_public_key = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"]


    if not contact_lt_public_key:
        logger.error("Contact long-term signing key is missing... 0 clue how we reached here, but we aint continuing..")
        return 

    if not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["verified"]:
        logger.error("Contact long-term signing key is not verified! it is possible that this is a MiTM attack by the server, we ignoring this PFS for now.")
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
    if not user_data_copied["contacts"][contact_id]["ephemeral_keys"]["contact_hash_chain"]:
        with user_data_lock:
            user_data["contacts"][contact_id]["ephemeral_keys"]["contact_hash_chain"] = contact_hash_chain
    
    else:
        contact_last_hash_chain = user_data_copied["contacts"][contact_id]["ephemeral_keys"]["contact_hash_chain"]
        contact_last_hash_chain = sha3_512(contact_last_hash_chain)

        if contact_last_hash_chain != contact_hash_chain:
            logger.error("Contact hash chain does not match our computed hash chain, we are skipping this PFS message...")
            return

    with user_data_lock:
        user_data["contacts"][contact_id]["ephemeral_keys"]["contact_hash_chain"] = contact_hash_chain
        user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_key"] = contact_kyber_public_key


    # TODO: Investigate possible infinite loopback
    # Details: What if contact_id wasn't in tmp (i.e. user closed the app and re-opened later )
    # then we re-send the keys ?! And not only that, if the contact also offline, and he receive it
    # he will also resend keys
    # and if we are offline, we also resend keys.
    # so on and so fourth
    # Maybe ephemeral_key_send_lock need to be in the contact info, not in tmp ?

    if contact_id in user_data_copied["tmp"]["ephemeral_key_send_lock"]:
        logger.debug("We don't have to re-send keys, as we already have sent them, time to inform user of success :)")

        # Incase this was auto-fired by SMP's step 4, we don't want to give the user another popup
        if not (contact_id in user_data_copied["tmp"]["pfs_do_not_inform"]):
            logger.info("Successfully initialized ephemeral keys with contacts (%s)", contact_id)
            ui_queue.put({"type": "showinfo", "title": "Success", "message": f"Successfully initialized ephemeral keys with contact ({contact_id[:32]})"})
        else:
            logger.info("Not informing the user of successful ephemeral keys initialization because step was likely automatically fired")
            
            # We delete incase user end up rotating per-contact long-term keys within the same session
            with user_data_lock:
                del user_data["tmp"]["pfs_do_not_inform"][contact_id]
    else:
        # Send our ephemeral keys back to the contact
        send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue)

    with user_data_lock:
        if contact_id in user_data["tmp"]["ephemeral_key_send_lock"]:
            del user_data["tmp"]["ephemeral_key_send_lock"][contact_id]


    save_account_data(user_data, user_data_lock)

