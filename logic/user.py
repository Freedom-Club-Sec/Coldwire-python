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
