import secrets
import string
import json
import math

from core.constants import (
    ML_KEM_1024_NAME,
    CLASSIC_MCELIECE_8_F_NAME,
    CLASSIC_MCELIECE_8_F_ROTATE_AT
)

def generate_nickname_id(length: int = 4) -> str:
    # Calculate nickname ID: digits get >= letters
    digit_len  = math.ceil(length / 2)
    letter_len = length - digit_len

    digits  = ''.join(secrets.choice(string.digits)        for _ in range(digit_len))
    letters = ''.join(secrets.choice(string.ascii_letters) for _ in range(letter_len))

    return letters + digits

def generate_random_nickname(user_data: dict, user_data_lock, contact_id: str, nicknames_prefixes_file: str = "assets/nicknames.json", nickname_id_len = 4) -> str:
    with open(nicknames_prefixes_file, "r", encoding="utf-8") as f:
        nickname_prefixes = json.load(f)["nicknames"]

    with user_data_lock:
        existing_nicknames = {v["nickname"] for v in user_data.get("contacts", {}).values()}


    while True:
        nickname = secrets.choice(nickname_prefixes) + " " + generate_nickname_id(length = nickname_id_len)
        if nickname not in existing_nicknames:
            return nickname


def save_contact(user_data: dict, user_data_lock, contact_id: str) -> None:
    with user_data_lock:
        if contact_id in user_data["contacts"]:
            raise ValueError("Contact already saved!")

        
        user_data["contacts"][contact_id] = {
                "nickname": None,
                "lt_sign_keys": {
                    "contact_public_key": None,
                    "our_keys": {
                            "private_key": None,
                            "public_key": None        
                        }, 
                    "our_hash_chain": None,
                    "contact_hash_chain": None

                },
                "lt_sign_key_smp": {
                    "verified": False,
                    "pending_verification": False,
                    "question": None,
                    "answer": None,
                    "our_nonce": None,
                    "contact_nonce": None,
                    "smp_step": None,
                    "tmp_proof": None,
                    "contact_kem_public_key": None,
                    "our_kem_keys": {
                        "private_key": None,
                        "public_key": None
                    }
                },
                "ephemeral_keys": {
                    "contact_public_keys": {
                        CLASSIC_MCELIECE_8_F_NAME: None,
                        ML_KEM_1024_NAME: None
                    },
                    "our_keys": {
                        CLASSIC_MCELIECE_8_F_NAME: {
                            "public_key": None,
                            "private_key": None,
                            "rotation_counter": 0,
                            "rotate_at": CLASSIC_MCELIECE_8_F_ROTATE_AT,
                        },
                        ML_KEM_1024_NAME: {
                            "public_key": None,
                            "private_key": None,
                        },

                    }
                },
                "our_pads": {
                    "hash_chain": None,
                    "pads": None
                },
                "contact_pads": {
                    "hash_chain": None,
                    "pads": None
                },
            }

