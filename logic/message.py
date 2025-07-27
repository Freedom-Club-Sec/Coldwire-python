from core.requests import http_request
from logic.storage import save_account_data
from logic.pfs import send_new_ephemeral_keys
from core.crypto import *
from core.constants import *
from base64 import b64decode, b64encode
import copy
import json
import logging

logger = logging.getLogger(__name__)


def generate_and_send_pads(user_data, user_data_lock, contact_id: str, contact_kyber_key, our_private_key, ui_queue) -> bool:
    with user_data_lock: 
        server_url = user_data["server_url"]
        auth_token = user_data["token"]
        replay_protection_number = user_data["contacts"][contact_id]["our_pads"]["replay_protection_number"]

    ciphertext_blob, pads = generate_kyber_shared_secrets(contact_kyber_key)

    if not replay_protection_number:
        # 1 because at this point, replay_protection_number is None.
        replay_protection_number = randomize_replay_protection_number(1)
    else:

        # This +1 is needed to ensure it at least increments by 1
        replay_protection_number += 1
        replay_protection_number = randomize_replay_protection_number(replay_protection_number)

    json_inner_payload = json.dumps({
            "ciphertext_blob": b64encode(ciphertext_blob).decode(),
            "replay_protection_number": replay_protection_number 
        })

    inner_payload_signature = create_signature("Dilithium5", json_inner_payload.encode("utf-8"), our_private_key)
    inner_payload_signature = b64encode(inner_payload_signature).decode()

    payload = {
            "json_payload": json_inner_payload,
            "payload_signature": inner_payload_signature,
            "recipient": contact_id
        }
    try:
        response = http_request(f"{server_url}/messages/send_pads", "POST", payload=payload, auth_token=auth_token)
    except:
        ui_queue.put({"type": "showerror", "title": "Error", "message": "Failed to send our one-time-pads key batch to the server"})
        return False
    
    # We update & save only at the end, so if request fails, we do not desync our state.
    with user_data_lock:
        user_data["contacts"][contact_id]["our_pads"]["pads"] = pads
        user_data["contacts"][contact_id]["our_pads"]["replay_protection_number"] = replay_protection_number

    save_account_data(user_data, user_data_lock)

    return True


def send_message_processor(user_data, user_data_lock, contact_id: str, message: str, ui_queue) -> bool:
    # We don't deepcopy here as real-time states are required here for maximum future-proofing.

    with user_data_lock:
        if contact_id in user_data["tmp"]["ephemeral_key_send_lock"]:
            ui_queue.put({
                "type": "showwarning",
                "title": "Warning",
                "message": f"We are waiting for ({contact_id[:32]}) to come online to exchange keys"
                })
            return False
        
        server_url = user_data["server_url"]
        auth_token = user_data["token"]


        contact_kyber_public_key = user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_key"]
        our_lt_private_key       = user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["private_key"]


     
    if (not contact_kyber_public_key):
        logger.debug("This shouldn't usually happen, contact kyber keys are not initialized even once yet???")
        ui_queue.put({
                "type": "showwarning",
                "title": f"Warning for {contact_id[:32]}",
                "message": f"Ephemeral keys have not yet initialized, maybe contact is offline. We will notify you when keys are initialized"
            })

        send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue)
        return False



    with user_data_lock:
        our_pads = user_data["contacts"][contact_id]["our_pads"]["pads"]

    # If we have keys, but no one-time-pads, we send new pads to the contact
    if not our_pads:
        logger.debug("We have no pads to send message")

        with user_data_lock:
        
            rotation_counter = user_data["contacts"][contact_id]["ephemeral_keys"]["rotation_counter"]
            rotate_at        = user_data["contacts"][contact_id]["ephemeral_keys"]["rotate_at"]


        # We rotate keys before generating and sending new batch of pads because
        # ephemeral key exchanges always get processed before messages do.
        # Which means if we generate and send pads with contact's, we would be using his old key, which would get overriden by the request, even if we send pads first
        # This is because of our server archiecture which prioritizes PFS requests before messages.
        #
        if rotation_counter == rotate_at:
            logger.info("We are rotating our ephemeral keys for contact (%s)", contact_id)
            ui_queue.put({"type": "showinfo", "title": "Perfect Forward Secrecy", "message": f"We are rotating our ephemeral keys for contact ({contact_id[:32]})"})
            send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue)

            save_account_data(user_data, user_data_lock)
            return False

        if not generate_and_send_pads(user_data, user_data_lock, contact_id, contact_kyber_public_key, our_lt_private_key, ui_queue):
            return False
        

        with user_data_lock:
            our_pads = user_data["contacts"][contact_id]["our_pads"]["pads"]

            user_data["contacts"][contact_id]["ephemeral_keys"]["rotation_counter"] += 1

        logger.debug("Incremented rotation_counter by 1. (%d)", rotation_counter)
        

    with user_data_lock:
        replay_protection_number = user_data["contacts"][contact_id]["our_pads"]["replay_protection_number"]

    message_encoded = message.encode("utf-8")

    message_otp_padding_length = max(0, OTP_PADDING_LIMIT - OTP_PADDING_LENGTH - len(message_encoded))

    if (len(message_encoded) + OTP_PADDING_LENGTH + message_otp_padding_length) > len(our_pads):
        ui_queue.put({"type": "showerror", "title": "Failed to send message", "message": f"Your message size ({len(message_encoded) + OTP_PADDING_LENGTH + message_otp_padding_length}) is larger than our pads size ({len(our_pads)}), please send a shorter message"})
        return False

    message_otp_pad = our_pads[:len(message_encoded) + OTP_PADDING_LENGTH + message_otp_padding_length]

    logger.debug("Our pad size is %d and new size after the message is %d", len(our_pads), len(our_pads) - len(message_otp_pad))
    # We one-time-pad encrypt the message with padding
    #
    # NOTE: The padding only protects short-messages which are easy to infer what is said based purely on message length 
    # With messages larger than padding_limit, we assume the message entropy give enough security to make an adversary assumption
    # of message context (almost) useless. 
    #
    message_encrypted = otp_encrypt_with_padding(message_encoded, message_otp_pad, padding_limit = message_otp_padding_length)
    message_encrypted = b64encode(message_encrypted).decode()

    # Unlike in other functions, we truncate pads here and update replay_protection_number regardless of request being successful or not
    # because a malicious server could make our requests fail to force us to re-use the same pad for our next message 
    # which would break all of our security
    with user_data_lock:
        user_data["contacts"][contact_id]["our_pads"]["pads"] = user_data["contacts"][contact_id]["our_pads"]["pads"][len(message_encoded) + OTP_PADDING_LENGTH + message_otp_padding_length:]

        replay_protection_number  = user_data["contacts"][contact_id]["our_pads"]["replay_protection_number"]

        # This ensures the replay counter always gets incremented by at very least 1
        replay_protection_number += 1

        # This helps obfsucate how many total messages were sent incase the request is intercepted
        # Adversaries might be able to come with a modest guess of how many total messages were sent
        # but never actually the exact amount, this provides some form of plausible deniability.
        replay_protection_number = randomize_replay_protection_number(replay_protection_number)

        user_data["contacts"][contact_id]["our_pads"]["replay_protection_number"] = replay_protection_number

        

    save_account_data(user_data, user_data_lock)
   

    json_inner_payload = json.dumps({
            "message_encrypted": message_encrypted,
            "replay_protection_number": replay_protection_number
        })

    json_inner_payload_signature = create_signature("Dilithium5", json_inner_payload.encode("utf-8"), our_lt_private_key)
    json_inner_payload_signature = b64encode(json_inner_payload_signature).decode()

    payload = {
            "json_payload": json_inner_payload,
            "payload_signature": json_inner_payload_signature,
            "recipient": contact_id
        }
    try:
        response = http_request(f"{server_url}/messages/send_message", "POST", payload=payload, auth_token=auth_token)
    except:
        ui_queue.put({"type": "showerror", "title": "Error", "message": "Failed to send our message to the server"})
        return False
   

    logger.info("Successfuly sent the message to contact (%s)", contact_id)

    return True



def messages_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, message):
    contact_id = message["sender"]

    if (not (contact_id in user_data_copied["contacts"])):
        logger.warning("Contact is missing, maybe we (or they) are not synced? Not sure, but we will ignore this Message request for now")
        logger.debug("Our contacts: %s", json.dumps(user_data_copied["contacts"], indent=2))
        return


    if not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["verified"]:
        logger.warning("Contact long-term signing key is not verified.. it is possible that this is a MiTM attack by the server, we ignoring this Message for now.")
        return


    contact_public_key = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"]

    if not contact_public_key:
        logger.warning("Contact per-contact Dilithium5 public key is missing.. skipping message")
        return


    logger.debug("Received a new message of type: %s", message["msg_type"])

    if message["msg_type"] == "new_otp_batch":
        payload_signature  = b64decode(message["payload_signature"], validate=True)
        valid_signature = verify_signature("Dilithium5", message["json_payload"].encode("utf-8"), payload_signature, contact_public_key)
        if not valid_signature:
            logger.debug("Invalid OTP batch signature.. possible MiTM ?")
            return

        json_payload = json.loads(message["json_payload"])

        ciphertext_blob          = b64decode(json_payload["ciphertext_blob"], validate=True)
        replay_protection_number = int(json_payload["replay_protection_number"])

        our_kyber_key = user_data_copied["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["private_key"]

        try:
            contact_pads = decrypt_kyber_shared_secrets(ciphertext_blob, our_kyber_key)
        except:
            logger.debug("Failed to decrypt shared_secrets, possible MiTM?")
            return

        with user_data_lock:
            user_data["contacts"][contact_id]["contact_pads"]["pads"]                     = contact_pads
            user_data["contacts"][contact_id]["contact_pads"]["replay_protection_number"] = replay_protection_number

        logger.info("Saved contact (%s) new batch of One-Time-Pads", contact_id)

        save_account_data(user_data, user_data_lock)

    elif message["msg_type"] == "new_message":
        payload_signature  = b64decode(message["payload_signature"], validate=True)
        valid_signature = verify_signature("Dilithium5", message["json_payload"].encode("utf-8"), payload_signature, contact_public_key)
        if not valid_signature:
            logger.debug("Invalid new message signature.. possible MiTM ?")
            return

        json_payload             = json.loads(message["json_payload"])
        message_encrypted        = b64decode(json_payload["message_encrypted"], validate=True)
        replay_protection_number = int(json_payload["replay_protection_number"])

        with user_data_lock:
            contact_pads                     = user_data["contacts"][contact_id]["contact_pads"]["pads"]
            contact_replay_protection_number = user_data["contacts"][contact_id]["contact_pads"]["replay_protection_number"]
       

        if (not contact_pads) or (len(message_encrypted) > len(contact_pads)):
            logger.warning("Message payload is larger than our local pads for the contact, we are skipping this message..")
            return

        if (not contact_replay_protection_number) or (replay_protection_number <= contact_replay_protection_number):
            logger.warning("Message replay_protection_number is equal or smaller than our saved replay_protection_number, this could be a possible replay attack, skipping this message...")
            return


        message_decrypted = otp_decrypt_with_padding(message_encrypted, contact_pads[:len(message_encrypted)])
       
        # immediately truncate the pads
        contact_pads = contact_pads[len(message_encrypted):] 

        # and immediately save the new pads and replay protection number
        with user_data_lock:
            user_data["contacts"][contact_id]["contact_pads"]["pads"]                     = contact_pads
            user_data["contacts"][contact_id]["contact_pads"]["replay_protection_number"] = replay_protection_number

        save_account_data(user_data, user_data_lock)

        logger.info("Truncated pads and updated replay_protect_number for contact (%s)", contact_id)

        try:
            message_decoded = message_decrypted.decode("utf-8")
        except:
            logger.error("Failed to decode UTF-8 message, we will not be showing this message.")
            return

        ui_queue.put({
            "type": "new_message",
            "contact_id": contact_id,
            "message": message_decoded
        })
