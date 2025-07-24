from base64 import b64decode
from core.requests import http_request

def get_target_lt_public_key(user_data: dict, target_id: str) -> bytes:
    url = user_data["server_url"]

    try:
        response = http_request(f"{url}/get_user?user_id={target_id}", "GET")
    except:
        raise ValueError("Could not connect to server, try again")

    if not "status" in response:
        raise ValueError("Server gave a malformed response! This could be a malicious act, we suggest you retry and if problem persists use another server")

    if response["status"] == "failure" or not response.get("public_key"):
        if not 'error' in response:
            raise ValueError("Server gave a malformed response! This could be a malicious act, we suggest you retry and if problem persists use another server")
        else:
            raise ValueError(response["error"][:1024])

    if response["status"] == "success":

        # Dry run to validate server's base64. Helps prevents denial-of-service startup crashes -
        # when client first reads parses their account file
        try:
            return b64decode(response["public_key"], validate=True)
        except:
            raise ValueError("Server gave a malformed public_key! This could be a malicious act, we suggest you retry and if problem persists use another server")
