import copy

def save_contact(user_data: dict, user_data_lock, contact_id: str, contact_public_key: bytes) -> None:
    with user_data_lock:
        if contact_id in user_data["contacts"]:
            raise ValueError("Contact already saved!")

        for i, v in user_data["contacts"].items():
            if v["lt_sign_public_key"] == contact_public_key:
                raise ValueError("Contact long-term auth signing public-key is duplicated, and we have no idea why")
       
        
        user_data["contacts"][contact_id] = {
                "lt_sign_public_key": contact_public_key,
                "lt_sign_key_smp": {
                    "verified": False,
                    "pending_verification": False,
                    "question": None,
                    "answer": None,
                    "our_nonce": None,
                    "contact_nonce": None,
                    "smp_step": None,
                },
                "ephemeral_keys": {
                    "contact_public_key": None,
                    "our_keys": {
                        "public_key": None,
                        "private_key": None,
                        },
                    "rotation_counter": None,
                    "rotate_at": None,
                    "our_hash_chain": None,
                    "contact_hash_chain": None

                },
                "message_sign_keys": {
                    "contact_public_key": None,
                    "our_keys": {
                        "private_key": None,
                        "public_key": None        
                    }
                },
                "our_pads": {
                    "replay_protection_number": None,
                    "pads": None
                },
                "contact_pads": {
                    "replay_protection_number": None,
                    "pads": None
                },
            }

