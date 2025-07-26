from core.requests import http_request
from logic.storage import save_account_data
from logic.get_user import get_target_lt_public_key
from core.crypto import generate_kem_keys, verify_signature, create_signature, generate_sign_keys, random_number_range
from core.trad_crypto import derive_key_argon2id, sha3_512
from base64 import b64encode, b64decode
import hashlib
import secrets
import hmac
import time
import copy
import json
import logging
import oqs


logger = logging.getLogger(__name__)


def rotate_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]

        d5_private_key = user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["private_key"]

    # Generate new Kyber1024 keys for us and send them to contact
    kyber_private_key, kyber_public_key = generate_kem_keys()

    # Sign it with our per-contact long-term private key
    kyber_key_signature = create_signature("Dilithium5", kyber_public_key, d5_private_key)
    
    payload = {
            "kyber_public_key": b64encode(kyber_public_key).decode(),
            "kyber_signature" : b64encode(kyber_key_signature).decode(),
            "recipient"       : contact_id,
            "pfs_type"        : "rotate"
        }


    try:
        response = http_request(f"{server_url}/pfs/send_keys", "POST", payload=payload, auth_token=auth_token)
    except:
        ui_queue.put({"type": "showerror", "title": "Error", "message": "Failed to send our rotated ephemeral keys to the server"})
        return
    

    # We update at the very end to ensure if any of previous steps fail, we do not desync our state
    with user_data_lock:
        user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["private_key"] = kyber_private_key
        user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["public_key"] = kyber_public_key

        rotation_counter = user_data["contacts"][contact_id]["ephemeral_keys"]["rotation_counter"]
        rotate_at        = user_data["contacts"][contact_id]["ephemeral_keys"]["rotate_at"]
        if rotation_counter == rotate_at:
            # Reset rotation counter because we rotated successfully
            user_data["contacts"][contact_id]["ephemeral_keys"]["rotation_counter"] = 0
            user_data["contacts"][contact_id]["ephemeral_keys"]["rotate_at"]        = 2







# TODO: Some of code here is duplicated in rotate_ephemeral_keys function, maybe clean it up?

def send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue) -> None:
    with user_data_lock:
        user_data_copied = copy.deepcopy(user_data)
  
    server_url = user_data_copied["server_url"]
    auth_token = user_data_copied["token"]


    lt_sign_private_key = user_data_copied["lt_auth_sign_keys"]["private_key"]

    # If we haven't generated and sent a long-term per-contact dilithium5 key used for signing messages
    if not user_data_copied["contacts"][contact_id]["message_sign_keys"]["our_keys"]["private_key"]:
        d5_private_key, d5_public_key = generate_sign_keys()
       
        # These keys are fine to save now, even if the request below fails
        with user_data_lock:
            user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["private_key"] = d5_private_key
            user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["public_key"] =  d5_public_key

    else:
        d5_private_key = user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["private_key"]
        d5_public_key  = user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["public_key"]

    
    # Generate new Kyber1024 keys for us and send them to contact
    kyber_private_key, kyber_public_key = generate_kem_keys()

    # Sign it with our per-contact long-term private key
    kyber_key_signature = create_signature("Dilithium5", kyber_public_key, d5_private_key)
    
    payload = {
            "kyber_public_key": b64encode(kyber_public_key).decode(),
            "kyber_signature" : b64encode(kyber_key_signature).decode(),
            "recipient"       : contact_id,
            "pfs_type"        : "init"
        }


    if not user_data_copied["contacts"][contact_id]["message_sign_keys"]["contact_public_key"]:
        # We avoid sending d5 public key and signature, because if we have the contact public_key
        # it means he has received our d5 public_key already
        # This is important step to avoid over-using our long-term key, which might weaken its security

        d5_key_signature = create_signature("Dilithium5", d5_public_key, lt_sign_private_key)
        payload["d5_public_key"] = b64encode(d5_public_key).decode()
        payload["d5_signature"] = b64encode(d5_key_signature).decode()

    try:
        response = http_request(f"{server_url}/pfs/send_keys", "POST", payload=payload, auth_token=auth_token)
    except:
        ui_queue.put({"type": "showerror", "title": "Error", "message": "Failed to send our ephemeral keys to the server"})
        return
    

    # We update at the very end to ensure if any of previous steps fail, we do not desync our state
    with user_data_lock:
        user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["private_key"] = kyber_private_key
        user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["public_key"] = kyber_public_key

        # Set rotation counters to rotate every 2 pads sent
        user_data["contacts"][contact_id]["ephemeral_keys"]["rotation_counter"] = 0
        user_data["contacts"][contact_id]["ephemeral_keys"]["rotate_at"] = 2

        # = True, to make it easy for us to delete it later when we receive keys from contact
        user_data["tmp"]["ephemeral_key_send_lock"][contact_id] = True



def perfect_forward_secrecy_worker(user_data, user_data_lock, ui_queue, stop_flag):
    while not stop_flag.is_set():
        with user_data_lock:
            user_data_copied = copy.deepcopy(user_data)

        server_url = user_data_copied["server_url"]
        auth_token = user_data_copied["token"]


        try:
            # Random longpoll number to help obfsucate traffic against analysis
            response = http_request(f"{server_url}/pfs/longpoll", "GET", auth_token=auth_token, longpoll=random_number_range(5, 30))
        except TimeoutError:
            continue

        logger.debug("PFS messages: %s", json.dumps(response, indent=2))

        for message in response["messages"]:
            with user_data_lock:
                user_data_copied = copy.deepcopy(user_data)


            contact_id = message["sender"]

            if (not (contact_id in user_data_copied["contacts"])):
                logger.debug("Contact is missing, maybe we (or they) are not synced? Not sure, but we will ignore this PFS request for now")
                logger.debug("Our contacts: %s", json.dumps(user_data_copied["contacts"], indent=2))
                continue

            contact_lt_public_key = user_data_copied["contacts"][contact_id]["lt_sign_public_key"]

            if not contact_lt_public_key:
                logger.debug("Contact long-term signing key is missing... 0 clue how we reached here, but we aint continuing..")
                continue

            if not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["verified"]:
                logger.debug("Contact long-term signing key is not verified.. it is possible that this is a MiTM attack by the server, we ignoring this PFS for now.")
                continue


            if message["pfs_type"] == "rotate":
                d5_public_key = user_data_copied["contacts"][contact_id]["message_sign_keys"]["contact_public_key"]
                contact_kyber_key_signature = b64decode(message["kyber_signature"], validate=True)
                contact_kyber_public_key    = b64decode(message["kyber_public_key"], validate=True)

                valid_signature = verify_signature("Dilithium5", contact_kyber_public_key, contact_kyber_key_signature, d5_public_key)
                if not valid_signature:
                    logger.debug("Invalid ephemeral kyber public-key signature.. possible MiTM ?")
                    continue


                with user_data_lock:
                    user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_key"] = contact_kyber_public_key
     
                save_account_data(user_data, user_data_lock)

                logger.info("Contact (%s) has rotated his ephemeral kyber keys")

            elif message["pfs_type"] == "init":

                if (not user_data_copied["contacts"][contact_id]["message_sign_keys"]["contact_public_key"]) and ((not ("d5_public_key" in message)) or not ("d5_signature" in message)):
                    logger.debug("Contact did not send the per-contact Dilithium5 public key or its signature.. skipping PFS message")
                    continue

           

                # Check if contact wants to send or rotate long-term per-contact signing keys
                if ("d5_public_key" in message) and ("d5_signature" in message):
                    d5_public_key = b64decode(message["d5_public_key"], validate=True)
                    d5_signature  = b64decode(message["d5_signature"], validate=True)
                    valid_signature = verify_signature("Dilithium5", d5_public_key, d5_signature, contact_lt_public_key)
                    if not valid_signature:
                        logger.debug("Invalid per-contact Dilithium5 public-key signature.. possible MiTM ?")
                        continue

                    # This is so it allows multiple key rotation within the same session without restarting the app
                    with user_data_lock:
                        if contact_id in user_data["tmp"]["ephemeral_key_send_lock"]:
                            del user_data["tmp"]["ephemeral_key_send_lock"][contact_id]

                else:
                    d5_public_key = user_data_copied["contacts"][contact_id]["message_sign_keys"]["contact_public_key"]



                contact_kyber_key_signature = b64decode(message["kyber_signature"], validate=True)
                contact_kyber_public_key    = b64decode(message["kyber_public_key"], validate=True)

                valid_signature = verify_signature("Dilithium5", contact_kyber_public_key, contact_kyber_key_signature, d5_public_key)
                if not valid_signature:
                    logger.debug("Invalid ephemeral kyber public-key signature.. possible MiTM ?")
                    continue


                with user_data_lock:
                    user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_key"] = contact_kyber_public_key
     


                if contact_id in user_data_copied["tmp"]["ephemeral_key_send_lock"]:
                    logger.debug("We don't have to re-send keys, as we already have sent them, time to inform user of success :)")

                    # Incase this was autofired by SMP's step 4, we don't want to give the user another popup
                    if not (contact_id in user_data_copied["tmp"]["pfs_do_not_inform"]):
                        ui_queue.put({"type": "showinfo", "title": "Success", "message": f"Successfully initialized ephemeral keys with contact ({contact_id[:32]})"})
                    else:
                        logger.info("Not informing the user of successful ephemeral keys initialization because step was likely automatically fired")
                        
                        # We delete incase user end up rotating keys within the same session
                        with user_data_lock:
                            del user_data["tmp"]["pfs_do_not_inform"][contact_id]
                else:
                    # Send and or rotate our ephemeral keys as well
                    send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue)

                with user_data_lock:
                    user_data["contacts"][contact_id]["message_sign_keys"]["contact_public_key"] = d5_public_key

                    if contact_id in user_data["tmp"]["ephemeral_key_send_lock"]:
                        del user_data["tmp"]["ephemeral_key_send_lock"][contact_id]


                save_account_data(user_data, user_data_lock)

