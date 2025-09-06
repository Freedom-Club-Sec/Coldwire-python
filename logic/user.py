def build_initial_user_data() -> dict:
    return {
            "server_url": None, 
            "contacts": {}, 
            "tmp": {}, 
            "settings": {
                "proxy_info": None,
                "ignore_new_contacts_smp": False, 
            }
        }


def validate_identifier(identifier) -> bool:
    if identifier.isdigit() and len(identifier) == 16:
        return True


    split = identifier.split("@")
    if len(split) != 2:
        return False

    if not split[0].isdigit():
        return False

    # Max domain length is 253 bytes
    if len(split[1] > 253):
        return False


    return True

