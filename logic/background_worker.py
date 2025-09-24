from core.requests import http_request
from logic.smp import smp_unanswered_questions, smp_data_handler
from logic.pfs import pfs_data_handler
from logic.message import messages_data_handler
from logic.user import validate_identifier
from core.constants import (
    LONGPOLL_MIN,
    LONGPOLL_MAX,
    COLDWIRE_LEN_OFFSET,
    SMP_TYPES,
    PFS_TYPES,
    MSG_TYPES,
    XCHACHA20POLY1305_NONCE_LEN,
    ML_KEM_1024_NAME,
    ML_KEM_1024_CT_LEN
)
from core.crypto import (
        random_number_range,
        decap_shared_secret
)
from core.trad_crypto import (
        decrypt_xchacha20poly1305
)
from base64 import b64decode, urlsafe_b64encode
import copy
import logging

logger = logging.getLogger(__name__)


def decode_blob_stream(data: bytes) -> list:
    messages = []

    offset = 0
    while offset < len(data):
        if offset + COLDWIRE_LEN_OFFSET + 32 > len(data):
            raise ValueError("Incomplete length prefix, malformed or corrupted data.")

        ack_id = data[offset : offset + 32]
        offset += 32

        msg_len = int.from_bytes(data[offset : offset + COLDWIRE_LEN_OFFSET], "big")
        offset += COLDWIRE_LEN_OFFSET
        if offset + msg_len > len(data):
            raise ValueError("Incomplete message data")

        messages.append(ack_id + data[offset:offset + msg_len])
        offset += msg_len
    return messages


def parse_blobs(blobs: list[bytes]) -> dict:
    parsed_messages = []

    for raw in blobs:
        try:
            ack_id = raw[:32]
            raw = raw[32:]
            sender, blob = raw.split(b"\0", 1)
            sender = sender.decode("utf-8")
            parsed_messages.append({
                "sender": sender,
                "blob": blob,
                "ack_id": ack_id
                })
        except ValueError as e:
            logger.error("Invalid message format! Error: %s", str(e))
            continue

    return parsed_messages

def background_worker(user_data, user_data_lock, ui_queue, stop_flag):
    # Incase we received a SMP question request last time and user did not answer it.
    # NOTE: this is not needed anymore, as we have implemented acknowlegements
    # smp_unanswered_questions(user_data, user_data_lock, ui_queue)

    # Acknowledgements
    acks = {}

    while not stop_flag.is_set():
        with user_data_lock:
            server_url = user_data["server_url"]
            auth_token = user_data["token"]
    
        try:
            # Random longpoll number to help obfsucate traffic against analysis
            response = http_request(
                    f"{server_url}/data/longpoll", 
                    "GET", 
                    auth_token = auth_token, 
                    metadata = acks if acks else None,
                    doseq = True,
                    longpoll = random_number_range(LONGPOLL_MIN, LONGPOLL_MAX)
                )
            acks = {}
        except TimeoutError:
            logger.debug("Data longpoll request has timed out, retrying...")
            continue

        data = decode_blob_stream(response)
        data = parse_blobs(data)


        for message in data:
            logger.debug("Received data: %s", str(message)[:3000])

            # Sanity check universal message fields
            if not validate_identifier(message["sender"]):
                logger.error("Impossible condition, either you have discovered a bug in Coldwire, or the server is attempting to denial-of-service you. Skipping data message with malformed sender identifier (%s)...", message["sender"])
                continue

            sender = message["sender"]
            blob   = message["blob"]

            ack_id = urlsafe_b64encode(message["ack_id"]).decode().rstrip("=")
            if "acks" not in acks:
                acks["acks"] = [ack_id]
            else:
                acks["acks"].append(ack_id)

            with user_data_lock:
                try:
                    user_data["contacts"][sender]["locked"] = True
                except Exception:
                    pass

                user_data_copied = copy.deepcopy(user_data)

            # Everything from here is not validated by server

            blob_plaintext = None
            
            if sender in user_data_copied["contacts"]: 

                contact_next_strand_key   = user_data_copied["contacts"][sender]["contact_next_strand_key"]
                contact_next_strand_nonce = user_data_copied["contacts"][sender]["contact_next_strand_nonce"]

                if contact_next_strand_key and contact_next_strand_nonce:
                    try:
                        blob_plaintext = decrypt_xchacha20poly1305(contact_next_strand_key, contact_next_strand_nonce, blob)

                        contact_next_strand_key   = blob_plaintext[:32]
                        contact_next_strand_nonce = blob_plaintext[32:32 + XCHACHA20POLY1305_NONCE_LEN]
                        blob_plaintext = blob_plaintext[32 + XCHACHA20POLY1305_NONCE_LEN:]

                        with user_data_lock:
                            user_data["contacts"][sender]["contact_next_strand_key"]   = contact_next_strand_key
                            user_data["contacts"][sender]["contact_next_strand_nonce"] = contact_next_strand_nonce

                    except Exception as e:
                        logger.error("Unable to decrypt incoming data from contact (%s). Error: %s", sender, str(e))
                        
                        continue
                else:
                    # just assume at this point that it's not encrypted.
                    logger.debug("Contact (%s) does not have a strand key and or a strand nonce! We will just gonna assume blob_plaintext = blob", sender)
                    blob_plaintext = blob

            else:
                logger.debug("Contact (%s) not saved.. we just gonna assume blob_plaintext = blob", sender)
                blob_plaintext = blob


            # SMP
            if bytes([blob_plaintext[0]]) in SMP_TYPES.values():
                smp_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, sender, blob_plaintext)

            # PFS
            elif bytes([blob_plaintext[0]]) in PFS_TYPES.values():
                pfs_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, sender, blob_plaintext)
            
            # MSG
            elif bytes([blob_plaintext[0]]) in MSG_TYPES.values():
                messages_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, sender, blob_plaintext)

            else:
                logger.error(
                        "Skipping data with unknown data type (%d) from contact (%s)...", 
                        blob_plaintext[0],
                        sender
                    )


            with user_data_lock:
                try:
                    user_data["contacts"][sender]["locked"] = False
                except Exception:
                    pass
