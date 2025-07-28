from core.requests import http_request
from logic.smp import smp_unanswered_questions, smp_data_handler
from logic.pfs import pfs_data_handler
from logic.message import messages_data_handler
from core.constants import (
    LONGPOLL_MIN,
    LONGPOLL_MAX
)
from core.crypto import random_number_range
import copy
import logging
import json

logger = logging.getLogger(__name__)

def background_worker(user_data, user_data_lock, ui_queue, stop_flag):
    # Incase we received a SMP question request last time right before the background worker was about to exit
    smp_unanswered_questions(user_data, user_data_lock, ui_queue)

    while not stop_flag.is_set():
        with user_data_lock:
            server_url = user_data["server_url"]
            auth_token = user_data["token"]
    
        try:
            # Random longpoll number to help obfsucate traffic against analysis
            response = http_request(f"{server_url}/data/longpoll", "GET", auth_token=auth_token, longpoll=random_number_range(LONGPOLL_MIN, LONGPOLL_MAX))
        except TimeoutError:
            logger.debug("Data longpoll request has timed out, retrying...")
            continue

        logger.debug("SMP messages: %s", json.dumps(response, indent = 2))

        for message in response["messages"]:
            # Sanity check universal message fields
            if (not "sender" in message) or (not message["sender"].isdigit()) or (len(message["sender"]) != 16):
                logger.error("Impossible condition, either you have discovered a bug in Coldwire, or the server is attempting to denial-of-service you. Skipping data message with no (or malformed) sender...")

                if "sender" in message:
                    logger.debug("Impossible condition's sender is: %s", message["sender"])

                continue

            with user_data_lock:
                user_data_copied = copy.deepcopy(user_data)

            if message["data_type"] == "smp":
                smp_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, message)

            elif message["data_type"] == "pfs":
                pfs_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, message)

            elif message["data_type"] == "message":
                messages_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, message)

            else:
                logger.error(
                        "Impossible condition, either you have discovered a bug in Coldwire, or the server is attempting to denial-of-service you. Skipping data message with unknown data type (%s)...", 
                        message["data_type"]
                    )
