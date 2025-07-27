from core.requests import http_request

def check_if_contact_exists(user_data: dict, user_data_lock, contact_id: str) -> bool:
    with user_data_lock:
        url = user_data["server_url"]

    try:
        response = http_request(f"{url}/get_user?user_id={contact_id}", "GET")
    except:
        raise ValueError("Could not connect to server, try again")

    if not "status" in response:
        raise ValueError("Server gave a malformed response")

    if response["status"] == "failure":
        if not 'error' in response:
            raise ValueError("Server gave a malformed response")
        else:
            raise ValueError(response["error"][:1024])

    if response["status"] == "success":
        return True 

    return False
