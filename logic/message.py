"""
logic/message.py
-----------
Message sending, receiving, and one-time-pad key exchange logic.
Handles:
- Generation and transmission of hybrid ciphertext OTP batches
- Ephemeral key rotation enforcement for PFS
- Message encryption/decryption with hash chain integrity checks
- Incoming message processing and replay/tampering protection
"""

from core.requests import http_request
from logic.storage import save_account_data
from logic.pfs import send_new_ephemeral_keys
from core.trad_crypto import sha3_512
from core.crypto import (
    generate_shared_secrets,
    decrypt_shared_secrets,
    create_signature,
    verify_signature,
    one_time_pad,
    otp_encrypt_with_padding,
    otp_decrypt_with_padding
)
from core.constants import (
    ALGOS_BUFFER_LIMITS,
    OTP_PAD_SIZE,
    OTP_PADDING_LIMIT,
    OTP_PADDING_LENGTH,
    ML_KEM_1024_NAME,
    CLASSIC_MCELIECE_8_F_NAME,
    ML_DSA_87_NAME,  
)
from base64 import b64decode, b64encode
import json
import logging

logger = logging.getLogger(__name__)


def generate_and_send_pads(user_data, user_data_lock, contact_id: str, ui_queue) -> bool:
    """
        Generates a new hash-chained OTP batch, signs it with Dilithium, and sends it to the server.
        Updates local pad and hash chain state upon success.
        Returns:
            bool: True if successful, False otherwise.
    """
    with user_data_lock: 
        server_url = user_data["server_url"]
        auth_token = user_data["token"]
 
        contact_kyber_public_key    = user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_keys"][ML_KEM_1024_NAME]
        contact_mceliece_public_key = user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_keys"][CLASSIC_MCELIECE_8_F_NAME]
        our_lt_private_key          = user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["private_key"]
 


    kyber_ciphertext_blob   , kyber_shared_secrets    = generate_shared_secrets(contact_kyber_public_key, ML_KEM_1024_NAME)
    mceliece_ciphertext_blob, mceliece_shared_secrets = generate_shared_secrets(contact_mceliece_public_key, CLASSIC_MCELIECE_8_F_NAME)

    otp_batch_signature = create_signature(ML_DSA_87_NAME, kyber_ciphertext_blob + mceliece_ciphertext_blob, our_lt_private_key)
    otp_batch_signature = b64encode(otp_batch_signature).decode()

    payload = {
            "otp_hashchain_ciphertext": b64encode(kyber_ciphertext_blob + mceliece_ciphertext_blob).decode(),
            "otp_hashchain_signature": otp_batch_signature,
            "recipient": contact_id
        }
    try:
        http_request(f"{server_url}/messages/send_pads", "POST", payload=payload, auth_token=auth_token)
    except Exception:
        ui_queue.put({"type": "showerror", "title": "Error", "message": "Failed to send our one-time-pads key batch to the server"})
        return False

    pads = one_time_pad(kyber_shared_secrets, mceliece_shared_secrets)

    # We update & save only at the end, so if request fails, we do not desync our state.
    with user_data_lock:
        user_data["contacts"][contact_id]["our_pads"]["pads"]       = pads[64:]
        user_data["contacts"][contact_id]["our_pads"]["hash_chain"] = pads[:64]

    save_account_data(user_data, user_data_lock)

    return True


def send_message_processor(user_data, user_data_lock, contact_id: str, message: str, ui_queue) -> bool:
    """
    Encrypts and sends a message to the contact.
    Handles:
        - OTP pad consumption and regeneration
        - Ephemeral key rotation
        - Hash chain integrity
        - Server transmission
    Returns:
        bool: True if successful, False otherwise.
    """

    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]

        contact_kyber_public_key    = user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_keys"][ML_KEM_1024_NAME]
        contact_mceliece_public_key = user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_keys"][CLASSIC_MCELIECE_8_F_NAME]

        our_pads         = user_data["contacts"][contact_id]["our_pads"]["pads"]
       
     
    if contact_kyber_public_key is None or contact_mceliece_public_key is None:
        logger.debug("This shouldn't happen, contact ephemeral keys are not initialized even once yet???")
        ui_queue.put({
                "type": "showwarning",
                "title": f"Warning for {contact_id[:32]}",
                "message": "Ephemeral keys have not yet initialized, and we are not sure why."
            })

        return False


        
    # If we don't have any one-time-pads, we send new pads to the contact
    if not our_pads:
        logger.debug("We have no OTP pads to use.")

        if not generate_and_send_pads(user_data, user_data_lock, contact_id, ui_queue):
            return False
        

        with user_data_lock:
            our_pads = user_data["contacts"][contact_id]["our_pads"]["pads"]
             
    with user_data_lock:
        our_hash_chain  = user_data["contacts"][contact_id]["our_pads"]["hash_chain"]


    message_encoded = message.encode("utf-8")
    next_hash_chain = sha3_512(our_hash_chain + message_encoded)
    message_encoded = next_hash_chain + message_encoded

    message_otp_padding_length = max(0, OTP_PADDING_LIMIT - OTP_PADDING_LENGTH - len(message_encoded))

    if (len(message_encoded) + OTP_PADDING_LENGTH + message_otp_padding_length) > len(our_pads):
        logger.info("Your message size (%d)  is larger than our pads size (%s), therefore we are generating new pads for you", len(message_encoded) + OTP_PADDING_LENGTH + message_otp_padding_length, len(our_pads))
        
        if not generate_and_send_pads(user_data, user_data_lock, contact_id, ui_queue):
            return False

        with user_data_lock:
            our_pads        = user_data["contacts"][contact_id]["our_pads"]["pads"]
            our_hash_chain  = user_data["contacts"][contact_id]["our_pads"]["hash_chain"]
        
        # We remove old hashchain from message and calculate new next hash in the chain
        message_encoded = message_encoded[64:]
        next_hash_chain = sha3_512(our_hash_chain + message_encoded)
        message_encoded = next_hash_chain + message_encoded


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

    # Unlike in other functions, we truncate pads here and compute the next hash chain regardless of request being successful or not
    # because a malicious server could make our requests fail to force us to re-use the same pad for our next message 
    # which would break all of our security
    with user_data_lock:
        user_data["contacts"][contact_id]["our_pads"]["pads"]       = user_data["contacts"][contact_id]["our_pads"]["pads"][len(message_encoded) + OTP_PADDING_LENGTH + message_otp_padding_length:]
        user_data["contacts"][contact_id]["our_pads"]["hash_chain"] = next_hash_chain

    save_account_data(user_data, user_data_lock)
   
    try:
        http_request(f"{server_url}/messages/send_message", "POST", payload = {
                    "message_encrypted": message_encrypted,
                    "recipient": contact_id
                }, 
                auth_token=auth_token
            )
    except:
        ui_queue.put({"type": "showerror", "title": "Error", "message": "Failed to send our message to the server"})
        return False
   

    logger.info("Successfuly sent the message to contact (%s)", contact_id)

    return True



def messages_data_handler(user_data: dict, user_data_lock, user_data_copied: dict, ui_queue, message: dict) -> None:
    """
    Handles incoming messages and OTP batches.
    Verifies signatures, decrypts payloads, updates pads/hash chain, and forwards plaintext to UI.
    Skips or logs suspicious or invalid messages.
    """
    contact_id = message["sender"]

    if (not (contact_id in user_data_copied["contacts"])):
        logger.warning("Contact is missing, maybe we (or they) are not synced? Not sure, but we will ignore this Message request for now")
        logger.debug("Our contacts: %s", json.dumps(user_data_copied["contacts"], indent=2))
        return


    if not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["verified"]:
        logger.warning("Contact long-term signing key is not verified.. it is possible that this is a MiTM attack, we ignoring this message for now.")
        return


    contact_public_key = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"]

    if contact_public_key is None:
        logger.warning("Contact per-contact Dilithium 5 public key is missing.. skipping message")
        return


    logger.debug("Received a new message of type: %s", message["msg_type"])

    if message["msg_type"] == "new_otp_batch":
        otp_hashchain_signature  = b64decode(message["otp_hashchain_signature"], validate=True)
        otp_hashchain_ciphertext = b64decode(message["otp_hashchain_ciphertext"], validate=True)

        valid_signature = verify_signature(ML_DSA_87_NAME, otp_hashchain_ciphertext, otp_hashchain_signature, contact_public_key)
        if not valid_signature:
            logger.debug("Invalid OTP_hashchain_ciphertext signature.. possible MiTM ?")
            return

        our_kyber_key = user_data_copied["contacts"][contact_id]["ephemeral_keys"]["our_keys"][ML_KEM_1024_NAME]["private_key"]
        our_mceliece_key = user_data_copied["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["private_key"]

        # / 32 because shared secret is 32 bytes
        try:
            contact_kyber_pads = decrypt_shared_secrets(otp_hashchain_ciphertext[:ALGOS_BUFFER_LIMITS[ML_KEM_1024_NAME]["CT_LEN"] * int(OTP_PAD_SIZE / 32)], our_kyber_key, ML_KEM_1024_NAME)
        except:
            logger.error("Failed to decrypt Kyber's shared_secrets, possible MiTM?")
            return

        try:
            contact_mceliece_pads = decrypt_shared_secrets(otp_hashchain_ciphertext[ALGOS_BUFFER_LIMITS[ML_KEM_1024_NAME]["CT_LEN"] * int(OTP_PAD_SIZE / 32):], our_mceliece_key, CLASSIC_MCELIECE_8_F_NAME)
        except:
            logger.error("Failed to decrypt McEliece's shared_secrets, possible MiTM?")
            return
        
        contact_pads = one_time_pad(contact_kyber_pads, contact_mceliece_pads)

        with user_data_lock:
            user_data["contacts"][contact_id]["contact_pads"]["pads"]       = contact_pads[64:]
            user_data["contacts"][contact_id]["contact_pads"]["hash_chain"] = contact_pads[:64]

            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotation_counter"] += 1
            
            new_ml_kem_keys  = user_data["tmp"]["new_ml_kem_keys"]

            rotation_counter = user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotation_counter"]

        
        logger.debug("Incremented McEliece's rotation_counter by 1 (now is %d) for contact (%s)", rotation_counter, contact_id)

        logger.info("Saved contact (%s) new batch of One-Time-Pads and hash chain seed", contact_id)
        save_account_data(user_data, user_data_lock)


        if contact_id not in new_ml_kem_keys:
            logger.info("Rotating our ephemeral keys") 
            send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue)
            save_account_data(user_data, user_data_lock)



    elif message["msg_type"] == "new_message":
        message_encrypted = b64decode(message["message_encrypted"], validate=True)

        with user_data_lock:
            contact_pads       = user_data["contacts"][contact_id]["contact_pads"]["pads"]
            contact_hash_chain = user_data["contacts"][contact_id]["contact_pads"]["hash_chain"]

        if (not contact_pads) or (len(message_encrypted) > len(contact_pads)):
            # TODO: Maybe reset our local pads as well?
            logger.warning("Message payload is larger than our local pads for the contact, we are skipping this message..")
            return

        message_decrypted = otp_decrypt_with_padding(message_encrypted, contact_pads[:len(message_encrypted)])
        # immediately truncate the pads
        contact_pads = contact_pads[len(message_encrypted):] 

        hash_chain        = message_decrypted[:64] 
        message_decrypted = message_decrypted[64:]

        next_hash_chain = sha3_512(contact_hash_chain + message_decrypted)

        if next_hash_chain != hash_chain:
            logger.warning("Message hash chain did not match, this could be a possible replay attack, or a failed tampering attempt. Skipping this message...")
            return


        # and save the new pads and the hash chain
        with user_data_lock:
            user_data["contacts"][contact_id]["contact_pads"]["pads"]       = contact_pads
            user_data["contacts"][contact_id]["contact_pads"]["hash_chain"] = next_hash_chain

        save_account_data(user_data, user_data_lock)

        logger.info("Truncated pads and updated computed the next hash chain for contact (%s)", contact_id)

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
