from base64 import b64encode, b64decode
from core.requests import http_request
from core.crypto import create_signature 

def authenticate_account(user_data: dict) -> dict:
    url = user_data["server_url"] 

    private_key = user_data["lt_auth_sign_keys"]["private_key"]
    public_key_encoded = user_data["lt_auth_sign_keys"]["public_key"]
    public_key_encoded = b64encode(public_key_encoded).decode()

    try:
        user_id = user_data.get("user_id") or ""

        response = http_request(url + "/authenticate/init", "POST", payload = {"public_key": public_key_encoded, "user_id": user_id })
        if not 'challenge' in response:
            raise ValueError("Server did not give authenticatation challenge! Are you sure this is a Coldwire server ?")
    except Exception:
        if user_data["settings"]["proxy_info"] is not None:
            raise ValueError("Could not connect to server! Are you sure your proxy settings are valid ?")
        else:
            raise ValueError("Could not connect to server! Are you sure the URL is valid ?")

    try:
        challenge = b64decode(response["challenge"], validate=True)
    except Exception:
        raise ValueError("Server gave a malformed challenge! Are you sure this is Coldwire server ?")


    signature = create_signature("Dilithium5", challenge, private_key)

    try:
        response = http_request(url + "/authenticate/verify", "POST", payload = {"signature": b64encode(signature).decode(), "challenge": response["challenge"]})
    except Exception:
        raise ValueError("Server gave a malformed response, your account is probably missing from the server")

    required_keys = ["status", "user_id", "token"]
    missing = [k for k in required_keys if k not in response]

    if missing:
        raise ValueError("Server gave a malformed response! Are you sure this is Coldwire server ?")

    if response["status"] != "success":
        if "error" in response:
            raise ValueError(response["error"])
        else:
            raise ValueError("Server gave an unknown error")

    user_data["user_id"] = response["user_id"]
    user_data["token"] = response["token"]

    return user_data
    
