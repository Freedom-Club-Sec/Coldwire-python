"""
    logic/smp.py
    ----------
    The socialist millionaire problem
    A variant of Yao's millionaire problem

    Guranteed verification certainity IF the answer has enough entropy (for the duration of the process.)

    This is not **strictly** a SMP implementation, but it is a simplified, human-language variant
    we made for verifying a contact's long-term public-key.

    Our implementation is inspired by Off-The-Record Messaging's SMP implementation.


    Query server for new SMP verification messages
    Check which step we are on
    Act accordingly

    Step 1 is initiated by the contact, whom sets a question and an answer, then sends the question to our user
    We assume user starts at step 2, step 1 is done by the contact who initiated the verification process  
    Step 2, we ask our user to provide an answer to the contact's question
    Then we compute a proof for our version of the contact's public-key fingerprint
    Step 3, the contact receives our proof and tries to compuate the same proof
    if it matches, he marks us as verified, otherwise, a failure notice is sent and both user and contact SMP state is deleted
    After it matches, contact compuates a proof for his version of our public-key fingerprint
    And sends it over
    Step 4 user receive this proof and try to compute an identical one
    If we succeed, the verification process is complete and we mark contact's as verified
   
    This provides a strong guarantee of authenticity and integrity for our long-term public keys 
    IF the answer has enough entropy to be uncrackable *just* for the duration of the process
       
"""

from core.requests import http_request
from logic.storage import save_account_data
from logic.contacts import save_contact
from logic.pfs import send_new_ephemeral_keys
from core.crypto import (
        generate_sign_keys, 
        generate_kem_keys,
        generate_shared_secrets,
        decrypt_shared_secrets,
        one_time_pad
)
from core.trad_crypto import derive_key_argon2id, sha3_512
from base64 import b64encode, b64decode
from core.constants import (
        SMP_NONCE_LENGTH,
        SMP_QUESTION_MAX_LEN,
        SMP_ANSWER_OUTPUT_LEN,
        ML_KEM_1024_NAME
)
import hashlib
import secrets
import hmac
import logging


logger = logging.getLogger(__name__)


def normalize_answer(s: str) -> str:
    return s.strip().lower()


# This is step 1.
def initiate_smp(user_data: dict, user_data_lock, contact_id: str, question: str, answer: str) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]
    
    our_nonce = b64encode(secrets.token_bytes(SMP_NONCE_LENGTH)).decode()

    signing_private_key, signing_public_key = generate_sign_keys()

    try:
        response = http_request(f"{server_url}/smp/initiate", "POST", payload = {
            "nonce": our_nonce,
            "signing_public_key": b64encode(signing_public_key).decode(),
            "recipient": contact_id

        }, auth_token=auth_token)
    except Exception:
        raise ValueError("Could not connect to server")

    if (not ("status" in response)) or response["status"] != "success":
        if "error" in response:
            raise ValueError(response["error"][:512])
        raise ValueError("Server sent malformed response")
    

    
    answer = normalize_answer(answer)

    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["pending_verification"] = True
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["question"]             = question
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["answer"]               = answer
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_nonce"]            = our_nonce
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"]             = 1

        user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["private_key"] = signing_private_key
        user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["public_key"]  = signing_public_key



    logger.debug("Initiated SMP for %s", contact_id)
    save_account_data(user_data, user_data_lock)



def smp_step_2(user_data, user_data_lock, contact_id, message, ui_queue) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]

    signing_private_key, signing_public_key = generate_sign_keys()
    
    question_private_key, question_public_key = generate_kem_keys(ML_KEM_1024_NAME)

    our_nonce = b64encode(secrets.token_bytes(SMP_NONCE_LENGTH)).decode()

    try:
        http_request(f"{server_url}/smp/step_2", "POST", payload = {
            "nonce": our_nonce,
            "signing_public_key": b64encode(signing_public_key).decode(),
            "question_public_key": b64encode(question_public_key).decode(),
            "recipient": contact_id

        }, auth_token=auth_token)
    except Exception:
        logger.error("Failed to send proof request to server, either you are offline or the server is down")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return

   
    # We only update after the request is sent successfully
    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["pending_verification"] = True

        user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_nonce"] = our_nonce
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_nonce"] = message["nonce"]
        
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_kem_keys"]["private_key"] = b64encode(question_private_key).decode()
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_kem_keys"]["public_key"]  = b64encode(question_public_key).decode()

        user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["private_key"] = signing_private_key
        user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["public_key"]  = signing_public_key

        user_data["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"] = b64decode(message["signing_public_key"], validate = True)



def smp_step_3(user_data, user_data_lock, contact_id, message, ui_queue) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]

        question = user_data["contacts"][contact_id]["lt_sign_key_smp"]["question"]

    contact_question_public_key = b64decode(message["question_public_key"], validate = True)

    question_pads_ciphertext, question_pads = generate_shared_secrets(contact_question_public_key, ML_KEM_1024_NAME, otp_pad_size = SMP_QUESTION_MAX_LEN)
    question_ciphertext = b64encode(one_time_pad(question.encode("utf-8"), question_pads)).decode()

    try:
        http_request(f"{server_url}/smp/step_3", "POST", payload = {
            "question_ciphertext": question_ciphertext,
            "question_pads_ciphertext": b64encode(question_pads_ciphertext).decode(),
            "recipient": contact_id

        }, auth_token=auth_token)
    except Exception:
        logger.error("Failed to send proof request to server, either you are offline or the server is down")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return

   
    # We only update after the request is sent successfully
    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"] = b64decode(message["signing_public_key"], validate=True)
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_kem_public_key"] = message["question_public_key"]
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_nonce"]   = message["nonce"]
        


def smp_step_4_request_answer(user_data, user_data_lock, contact_id, message, ui_queue) -> None:
    with user_data_lock:
        our_question_private_key = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_kem_keys"]["private_key"])

    pads = decrypt_shared_secrets(b64decode(message["question_pads_ciphertext"], validate = True), our_question_private_key, ML_KEM_1024_NAME, otp_pad_size = SMP_QUESTION_MAX_LEN)
    question = one_time_pad(b64decode(message["question_ciphertext"], validate = True), pads) 

    with user_data_lock: 
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["question"] = question.decode("utf-8")
        user_data["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"] = 4


    ui_queue.put({
        "type": "smp_question",
        "contact_id": contact_id,
        "question": question.decode("utf-8")
    })


def smp_step_4_answer_provided(user_data, user_data_lock, contact_id, answer, ui_queue) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]

        contact_signing_public_key = user_data["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"]
        contact_nonce = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_nonce"], validate=True)

        our_nonce     = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_nonce"], validate=True)

        user_data["contacts"][contact_id]["lt_sign_key_smp"]["answer"] = answer

    answer = normalize_answer(answer)

    contact_key_fingerprint = sha3_512(contact_signing_public_key)

    # Derieve a high-entropy secret key from the low-entropy answer
    argon2id_salt = sha3_512(our_nonce + contact_nonce)
    answer_secret, _ = derive_key_argon2id(answer.encode("utf-8"), salt = argon2id_salt, output_length = SMP_ANSWER_OUTPUT_LEN)

    # Compute our proof
    our_proof = contact_nonce + our_nonce + contact_key_fingerprint
    our_proof = hmac.new(answer_secret, our_proof, hashlib.sha3_512).hexdigest()

    logger.debug("Our proof of contact (%s) public-key fingerprint: %s", contact_id, our_proof)


    try:
        http_request(f"{server_url}/smp/step_4", "POST", payload = {
            "proof": our_proof,
            "recipient": contact_id
        }, auth_token=auth_token)
    except Exception:
        logger.error("Failed to send proof request to server, either you are offline or the server is down")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return



def smp_step_5(user_data, user_data_lock, contact_id, message, ui_queue) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]

        answer = user_data["contacts"][contact_id]["lt_sign_key_smp"]["answer"]

        contact_signing_public_key  = user_data["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"]
        contact_question_public_key = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_kem_public_key"])

        our_public_key     = user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["public_key"]
        our_nonce          = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_nonce"], validate=True)
        contact_nonce      = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_nonce"], validate=True)

    our_key_fingerprint = sha3_512(our_public_key)

    # Derieve a high-entropy secret key from the low-entropy answer
    argon2id_salt = sha3_512(contact_nonce + our_nonce)
    answer_secret, _ = derive_key_argon2id(answer.encode("utf-8"), salt = argon2id_salt, output_length = SMP_ANSWER_OUTPUT_LEN)

    # Compute the proof
    our_proof = our_nonce + contact_nonce + our_key_fingerprint
    our_proof = hmac.new(answer_secret, our_proof, hashlib.sha3_512).digest()

    contact_proof_raw = bytes.fromhex(message["proof"])
    
    logger.debug("SMP Proof sent to us: %s", contact_proof_raw)
    logger.debug("Our compute message: %s", our_proof)


    # Verify Contact's version of our public-key fingerprint matches our actual public-key fingerprint
    # We compare using compare_digest to prevent timing analysis by avoiding content-based short circuiting behaviour
    if not hmac.compare_digest(our_proof, contact_proof_raw):
        logger.warning("SMP Verification failed")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return


    # We compute proof for contact's public key (signing public key, and the question public key)
    contact_key_fingerprint = sha3_512(contact_signing_public_key + contact_question_public_key)

    our_proof = contact_nonce + our_nonce + contact_key_fingerprint
    our_proof = hmac.new(answer_secret, our_proof, hashlib.sha3_512).hexdigest()

    logger.debug("Our proof to contact: %s", our_proof)

    try:
        http_request(f"{server_url}/smp/step_5", "POST", payload = {
            "proof": our_proof,
            "recipient": contact_id
        }, auth_token=auth_token)
    except Exception:
        logger.error("Failed to send proof request to server, either you are offline or the server is down")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return

    # We call smp_success at very end to ensure if the requests step fail, we don't alter our local state
    smp_success(user_data, user_data_lock, contact_id, ui_queue)


def smp_step_6(user_data, user_data_lock, contact_id, message, ui_queue) -> None:
    with user_data_lock:
        answer = user_data["contacts"][contact_id]["lt_sign_key_smp"]["answer"]

        contact_signing_public_key  = user_data["contacts"][contact_id]["lt_sign_keys"]["contact_public_key"]
        
        our_question_public_key = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_kem_keys"]["public_key"])
        our_signing_public_key  = user_data["contacts"][contact_id]["lt_sign_keys"]["our_keys"]["public_key"]

        our_nonce          = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["our_nonce"], validate=True)
        contact_nonce      = b64decode(user_data["contacts"][contact_id]["lt_sign_key_smp"]["contact_nonce"], validate=True)

    our_key_fingerprint = sha3_512(our_signing_public_key + our_question_public_key)

    # Derieve a high-entropy secret key from the low-entropy answer
    argon2id_salt = sha3_512(our_nonce + contact_nonce)
    answer_secret, _ = derive_key_argon2id(answer.encode("utf-8"), salt = argon2id_salt, output_length = SMP_ANSWER_OUTPUT_LEN)

    # Compute the proof
    our_proof = our_nonce + contact_nonce + our_key_fingerprint
    our_proof = hmac.new(answer_secret, our_proof, hashlib.sha3_512).digest()

    contact_proof_raw = bytes.fromhex(message["proof"])
    
    logger.debug("SMP Proof sent to us: %s", contact_proof_raw)
    logger.debug("Our compute message: %s", our_proof)


    # Verify Contact's version of our public-key fingerprint matches our actual public-key fingerprint
    # We compare using compare_digest to prevent timing analysis by avoiding content-based short circuiting behaviour
    if not hmac.compare_digest(our_proof, contact_proof_raw):
        logger.warning("SMP Verification failed")
        smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue)
        return

    smp_success(user_data, user_data_lock, contact_id, ui_queue)


    # Attempt to automatically exchanger per-contact and ephemeral keys
    # We only attempt here and not inside of smp_success because we don't want both contact's attempting to exchange keys at the same time
    # cuz contact likely still hasnt verified us yet.. (ik its confuysing but just pretend u understand)
    #

    send_new_ephemeral_keys(user_data, user_data_lock, contact_id, ui_queue)


def smp_success(user_data, user_data_lock, contact_id, ui_queue) -> None:
    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_key_smp"] = {
            "verified": True,
            "pending_verification": False,
            "question": None,
            "answer": None,
            "our_nonce": None,
            "contact_nonce": None,
            "smp_step": None,
            "contact_kem_public_key": None,
            "our_kem_keys": {
                "private_key": None,
                "public_key": None
            }

        }


    # :32 to ensure no weird visual effects or even bufferoverflows can be exploited in underlying tkinter.
    ui_queue.put({"type": "showinfo",  "title": "Success", "message": f"Successfully verified contact ({contact_id[:32]})!"})


def smp_failure(user_data, user_data_lock, contact_id, ui_queue) -> None:
    with user_data_lock:
        user_data["contacts"][contact_id]["lt_sign_key_smp"] = {
            "verified": False,
            "pending_verification": False,
            "question": None,
            "answer": None,
            "our_nonce": None,
            "contact_nonce": None,
            "smp_step": None,
            "contact_kem_public_key": None,
            "our_kem_keys": {
                "private_key": None,
                "public_key": None
            }


        }

    ui_queue.put({"type": "showerror", "title": "Error", "message": "Verification has failed! Please re-try."})


def smp_failure_notify_contact(user_data, user_data_lock, contact_id, ui_queue) -> None:
    with user_data_lock:
        server_url = user_data["server_url"]
        auth_token = user_data["token"]

    smp_failure(user_data, user_data_lock, contact_id, ui_queue)

    try:
        http_request(f"{server_url}/smp/failure", "POST", payload = {"recipient": contact_id}, auth_token=auth_token)
    except Exception:
        logger.error("Failed to send SMP failure to server, either you are offline or the server is down")
        pass
  


def smp_unanswered_questions(user_data, user_data_lock, ui_queue):
    with user_data_lock:
        for contact_id in user_data["contacts"]:
            if user_data["contacts"][contact_id]["lt_sign_key_smp"]["question"] and user_data["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"] == 2:
                logger.info("We had an unanswered question from contact (%s)", contact_id)
                ui_queue.put({
                    "type": "smp_question",
                    "contact_id": contact_id,
                    "question": user_data["contacts"][contact_id]["lt_sign_key_smp"]["question"]
                })


def smp_data_handler(user_data, user_data_lock, user_data_copied, ui_queue, message):
    contact_id = message["sender"]

    if (not "step" in message):
        logger.error("Message has no 'step'. Maybe malicious server ? anyhow, we will ignore this SMP request. Message: %s", repr(message))
        return

    if not (message["step"] in [1, 2, 3, 4, 5, 6, -1]):
        logger.error("SMP 'step' is not in range of values we accept. We will ignore this SMP request. Step: %d", message["step"])
        return

    # Check if we don't have this contact saved
    if (not (contact_id in user_data_copied["contacts"])):
        # We assume it has to be step 1 because the contact did not exist before
        if message["step"] != 1:
            logger.error("something wrong, we or they are not synced? Not sure, but we will ignore this SMP request because the step should've been 1, instead we got (%d)", message["step"])
            return

        logger.info("We received a new SMP request for a contact we did not have saved")


        # Save them in-memory
        save_contact(user_data, user_data_lock, contact_id)

        # Perform the next SMP step
        smp_step_2(user_data, user_data_lock, contact_id, message, ui_queue)

        logger.debug("Saved new contact: %s", contact_id)

        # Send request to UI to visually add the contact to contact list
        ui_queue.put({
                        "type": "new_contact",
                        "contact_id": contact_id
                     })

    # Same thing as above code, except that we don't fetch nor save the contact here
    # as they're already fetched and saved
    elif message["step"] == 1:
        smp_step_2(user_data, user_data_lock, contact_id, message, ui_queue)
        
    elif message["step"] == 2:
        if (not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["pending_verification"]) or (user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"] != 1):
            logger.error("something wrong, we or they are not synced? Not sure, but we will ignore this SMP request for now")
            return

        smp_step_3(user_data, user_data_lock, contact_id, message, ui_queue)
    elif message["step"] == 3:
        if (not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["pending_verification"]): # or (user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"] != 2):
            logger.error("something wrong, we or they are not synced? Not sure, but we will ignore this SMP request for now")
            return

        smp_step_4_request_answer(user_data, user_data_lock, contact_id, message, ui_queue)

    elif message["step"] == 4:
        if (not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["pending_verification"]): # or (user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"] != 3):
            logger.error("something wrong, we or they are not synced? Not sure, but we will ignore this SMP request for now")
            return

        smp_step_5(user_data, user_data_lock, contact_id, message, ui_queue)

    elif message["step"] == 5:
        if (not user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["pending_verification"]): # or (user_data_copied["contacts"][contact_id]["lt_sign_key_smp"]["smp_step"] != 4):
            logger.error("something wrong, we or they are not synced? Not sure, but we will ignore this SMP request for now")
            return

        smp_step_6(user_data, user_data_lock, contact_id, message, ui_queue)



    # SMP failure on contact side
    elif (message["step"] == -1):
        # Delete SMP state for contact
        smp_failure(user_data, user_data_lock, contact_id, ui_queue)

    else:
        logger.error("This is an impossible condition, either you have discovered a bug in Coldwire, or the server is malicious. Skipping weird SMP step (%d)...", message["step"])
        return

    save_account_data(user_data, user_data_lock)



