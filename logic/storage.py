from pathlib import Path
from base64 import b64encode, b64decode
import core.trad_crypto as crypto
import json
import copy
import logging


ACCOUNT_FILE_PATH = "account.coldwire"

logger = logging.getLogger(__name__)


def check_account_file() -> bool:
    return Path(ACCOUNT_FILE_PATH).is_file()

def load_account_data(password = None) -> dict:
    user_data = None
    if not password:
        with open(ACCOUNT_FILE_PATH, "r", encoding="utf-8") as f:
            user_data = json.load(f)
    else:
        with open(ACCOUNT_FILE_PATH, "rb") as f:
            blob = f.read()

            # first 12 bytes is nonce, and last 32 bytes is the password salt, 
            # and the ciphertext is inbetween.
            password_kdf, _ = crypto.derive_key_argon2id(password.encode(), salt=blob[-32:])
            
            blob = blob[:-32]

            user_data = json.loads(crypto.decrypt_aes_gcm(password_kdf, blob[:12], blob[12:]))



    user_data["tmp"] = {
        "ephemeral_key_send_lock": {},
        "pfs_do_not_inform": {}
    }

    
    # This is so we dont have to keep decoding the keys throughout the codebase
    user_data["lt_auth_sign_keys"]["private_key"] = b64decode(user_data["lt_auth_sign_keys"]["private_key"], validate=True)
    user_data["lt_auth_sign_keys"]["public_key"]  = b64decode(user_data["lt_auth_sign_keys"]["public_key"], validate=True)

    for contact_id in user_data["contacts"]:
        user_data["contacts"][contact_id]["lt_sign_public_key"] = b64decode(user_data["contacts"][contact_id]["lt_sign_public_key"], validate=True)
        

        # They probably haven't exchanged yet, so it's fine to skip decoding them 
        try:
            user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_key"] = b64decode(user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_key"], validate=True)
        except TypeError:
            pass
        
        try:
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["private_key"] = b64decode(user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["private_key"], validate=True)
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["public_key"] = b64decode(user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["public_key"], validate=True)
        except TypeError:
            pass

        try:
            user_data["contacts"][contact_id]["message_sign_keys"]["contact_public_key"] = b64decode(user_data["contacts"][contact_id]["message_sign_keys"]["contact_public_key"], validate=True)
        except TypeError:
            pass
        
        try:
            user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["private_key"] = b64decode(user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["private_key"], validate=True)
            user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["public_key"] = b64decode(user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["public_key"], validate=True)
        except TypeError:
            pass

        try:
            user_data["contacts"][contact_id]["our_pads"]["pads"] = b64decode(user_data["contacts"][contact_id]["our_pads"]["pads"], validate=True)
        except TypeError:
            pass

        try:
            user_data["contacts"][contact_id]["contact_pads"]["pads"] = b64decode(user_data["contacts"][contact_id]["contact_pads"]["pads"], validate=True)
        except TypeError:
            pass

        try:
            user_data["contacts"][contact_id]["ephemeral_keys"]["contact_hash_chain"] = b64decode(user_data["contacts"][contact_id]["ephemeral_keys"]["contact_hash_chain"], validate=True)
        except TypeError:
            pass

        try:
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_hash_chain"] = b64decode(user_data["contacts"][contact_id]["ephemeral_keys"]["our_hash_chain"], validate=True)
        except TypeError:
            pass



    logger.debug("Loaded user_data from file (%s)", ACCOUNT_FILE_PATH)

    return user_data


def save_account_data(user_data: dict, user_data_lock, password = None) -> None:
    with user_data_lock:
        user_data = copy.deepcopy(user_data)
    
    if password == None and "password" in user_data:
        password = user_data["password"]

    del user_data["tmp"]

    # We base64 it back before JSON serializing
    user_data["lt_auth_sign_keys"]["private_key"] = b64encode(user_data["lt_auth_sign_keys"]["private_key"]).decode()
    user_data["lt_auth_sign_keys"]["public_key"]  = b64encode(user_data["lt_auth_sign_keys"]["public_key"]).decode()

    for contact_id in user_data["contacts"]:
        user_data["contacts"][contact_id]["lt_sign_public_key"] = b64encode(user_data["contacts"][contact_id]["lt_sign_public_key"]).decode()
        
        # They probably haven't exchanged yet, so it's fine to skip decoding them 
        try:
            user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_key"] = b64encode(user_data["contacts"][contact_id]["ephemeral_keys"]["contact_public_key"]).decode()
        except TypeError:
            pass

        try:
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["private_key"] = b64encode(user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["private_key"]).decode()
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["public_key"] = b64encode(user_data["contacts"][contact_id]["ephemeral_keys"]["our_keys"]["public_key"]).decode()
        except TypeError:
            pass

        
        try:
            user_data["contacts"][contact_id]["message_sign_keys"]["contact_public_key"] = b64encode(user_data["contacts"][contact_id]["message_sign_keys"]["contact_public_key"]).decode()
        except TypeError:
            pass
        
        try:
            user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["private_key"] = b64encode(user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["private_key"]).decode()
            user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["public_key"] = b64encode(user_data["contacts"][contact_id]["message_sign_keys"]["our_keys"]["public_key"]).decode()
        except TypeError:
            pass

        try:
            user_data["contacts"][contact_id]["our_pads"]["pads"] = b64encode(user_data["contacts"][contact_id]["our_pads"]["pads"]).decode()
        except TypeError:
            pass

        try:
            user_data["contacts"][contact_id]["contact_pads"]["pads"] = b64encode(user_data["contacts"][contact_id]["contact_pads"]["pads"]).decode()
        except TypeError:
            pass

        try:
            user_data["contacts"][contact_id]["ephemeral_keys"]["contact_hash_chain"] = b64encode(user_data["contacts"][contact_id]["ephemeral_keys"]["contact_hash_chain"]).decode()
        except TypeError:
            pass

        try:
            user_data["contacts"][contact_id]["ephemeral_keys"]["our_hash_chain"] = b64encode(user_data["contacts"][contact_id]["ephemeral_keys"]["our_hash_chain"]).decode()
        except TypeError:
            pass




    if not password:
        with open(ACCOUNT_FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(user_data, f, indent=2)
    else:
        password_kdf, password_salt = crypto.derive_key_argon2id(password.encode())


        nonce, ciphertext = crypto.encrypt_aes_gcm(password_kdf, json.dumps(user_data).encode("utf-8"))
        with open(ACCOUNT_FILE_PATH, "wb") as f:
            f.write(nonce + ciphertext + password_salt)


    logger.debug("Saved user_data to file (%s)", ACCOUNT_FILE_PATH)


