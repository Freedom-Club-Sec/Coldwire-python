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
    KEYS_HASH_CHAIN_LEN,
    OTP_PAD_SIZE,
    OTP_SIZE_LENGTH,
    ML_KEM_1024_NAME,
    ML_KEM_1024_CT_LEN,
    ML_DSA_87_NAME,  
    ML_DSA_87_SIGN_LEN,
    CLASSIC_MCELIECE_8_F_NAME,
    CLASSIC_MCELIECE_8_F_CT_LEN
)
from base64 import b64decode, b64encode
import json
import logging

logger = logging.getLogger(__name__)


def generate_and_send_pads(user_data, user_data_lock, contact_id: str, ui_queue) -> bool:
    """
        Generates a new OTP batch, signs it with ML-DSA-87, encrypt everything and send it to the server.
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
 
        our_strand_key = user_data["contacts"][contact_id]["our_strand_key"]



    kyber_ciphertext_blob   , kyber_shared_secrets    = generate_shared_secrets(contact_kyber_public_key, ML_KEM_1024_NAME)
    mceliece_ciphertext_blob, mceliece_shared_secrets = generate_shared_secrets(contact_mceliece_public_key, CLASSIC_MCELIECE_8_F_NAME)

    otp_batch_signature = create_signature(ML_DSA_87_NAME, kyber_ciphertext_blob + mceliece_ciphertext_blob, our_lt_private_key)

    ciphertext_nonce, ciphertext_blob = encrypt_xchacha20poly1305(
            our_strand_key, 
            b"\x00" + otp_batch_signature + kyber_ciphertext_blob + mceliece_ciphertext_blob
        )


    try:
        http_request(f"{server_url}/messages/send", "POST", payload={
                "ciphertext_blob": b64encode(ciphertext_nonce + ciphertext_blob).decode(),
                "recipient": contact_id
            }, auth_token=auth_token)
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

    if contact_id not in user_data_copied["contacts"]:
        logger.error("Contact (%s) is not saved! Skipping message", contact_id)
        logger.debug("Our contacts: %s", str(user_data_copied["contacts"]))
        return


    if not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["verified"]:
        logger.warning("Contact (%s) is not verified! Skipping message", contact_id)
        return


    contact_public_key = user_data_copied["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"]
    contact_strand_key = user_data_copied["contacts"][contact_id]["contact_strand_key"]

    if contact_public_key is None:
        logger.error("Contact (%s) per-contact ML-DSA-87 public key is missing! Skipping message..", contact_id)
        return

    if not contact_strand_key:
        logger.error("Contact (%s) strand key key is missing! Skipping message...", contact_id)
        return 


    ciphertext_blob = b64decode(message["ciphertext_blob"], validate = True)
    
    # Everything from here is not validated by server
    try:
        msgs_plaintext = decrypt_xchacha20poly1305(contact_strand_key, ciphertext_blob[:XCHACHA20POLY1305_NONCE_LEN], ciphertext_blob[XCHACHA20POLY1305_NONCE_LEN:])
    except Exception as e:
        logger.error("Failed to decrypt `ciphertext_blob` from contact (%s) with error: %s", contact_id, str(e))
        return

    # b"\x00" + otp_batch_signature + kyber_ciphertext_blob + mceliece_ciphertext_blob
   
    if msgs_plaintext[0] == 0:
        logger.debug("Received a new OTP pads batch from contact (%s).", contact_id)

        if len(msgs_plaintext) != ( (ML_KEM_1024_CT_LEN + CLASSIC_MCELIECE_8_F_CT_LEN) * (OTP_PAD_SIZE // 32)) + ML_DSA_87_SIGN_LEN + 1:
            logger.error("Contact (%s) gave us a message request with malformed strand plaintext length (%d)", contact_id, len(msgss_plaintext))
            return

        otp_hashchain_signature  = msgs_plaintext[:ML_DSA_87_SIGN_LEN]
        otp_hashchain_ciphertext = msgs_plaintext[ML_DSA_87_SIGN_LEN:]

        try:
            valid_signature = verify_signature(ML_DSA_87_NAME, otp_hashchain_ciphertext, otp_hashchain_signature, contact_public_key)
            if not valid_signature:
                logger.error("Invalid `otp_hashchain_ciphertext` signature from contact (%s)! This might be a MiTM attack.", contact_id)
                return
        except Exception as e:
            logger.error("Contact (%s) gave us a messages request with malformed strand signature which generated this error: %s", contact_id, str(e))
            return

        our_kyber_key = user_data_copied["contacts"][contact_id]["ephemeral_keys"]["our_keys"][ML_KEM_1024_NAME]["private_key"]
        our_mceliece_key = user_data_copied["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["private_key"]

        # / 32 because shared secret is 32 bytes
        try:
            contact_kyber_pads = decrypt_shared_secrets(otp_hashchain_ciphertext[:ML_KEM_1024_CT_LEN * (OTP_PAD_SIZE // 32)], our_kyber_key, ML_KEM_1024_NAME)
        except Exception as e:
            logger.error("Failed to decrypt Kyber's shared_secrets from contact (%s), received error: %s", contact_id, str(e))
            return

        try:
            contact_mceliece_pads = decrypt_shared_secrets(otp_hashchain_ciphertext[ML_KEM_1024_CT_LEN * (OTP_PAD_SIZE // 32):], our_mceliece_key, CLASSIC_MCELIECE_8_F_NAME)
        except Exception as e:
            logger.error("Failed to decrypt McEliece's shared_secrets from contact (%s), received error: %s", contact_id, str(e))
            return
        
        contact_pads = one_time_pad(contact_kyber_pads, contact_mceliece_pads)
        contact_strand_key = contact_pads[:32]
        contact_hash_chain = contact_pads[32:32 + KEY_HASH_CHAIN_LEN]
        contact_pads = contact_pads[32 + KEY_HASH_CHAIN_LEN:]

        with user_data_lock:
            user_data["contacts"][contact_id]["contact_pads"]["pads"]       = contact_pads
            user_data["contacts"][contact_id]["contact_pads"]["hash_chain"] = contact_hash_chain

            user_data["contacts"][contact_id]["contact_strand_key"]         = contact_strand_key

            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotation_counter"] += 1
            
            new_ml_kem_keys  = user_data["tmp"]["new_ml_kem_keys"]

            rotation_counter = user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"][CLASSIC_MCELIECE_8_F_NAME]["rotation_counter"]

        
        logger.debug("Incremented McEliece's rotation_counter by 1 (now is %d) for contact (%s)", rotation_counter, contact_id)

        logger.info("Saved contact (%s) new batch of One-Time-Pads, new strand key, and new hash chain seed", contact_id)
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
            # I feel like we should do something more when we hit this case, but I am not sure.
            logger.error("Message payload is larger than our local pads for the contact (%s), we are skipping this message.. This is most likely a bug, please open an issue on Github (https://github.com/Freedom-Club-Sec/Coldwire)", contact_id)
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
