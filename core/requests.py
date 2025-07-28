from urllib import request
import json

def http_request(url: str, method: str, auth_token: str = None, payload: dict = None, longpoll: int = -1) -> dict:
    if payload:
        payload = json.dumps(payload).encode()

    if payload:
        req = request.Request(url, data=payload, method=method.upper())
        req.add_header("Content-Type", "application/json")
    else:
        req = request.Request(url, method=method.upper())
    
    if auth_token:
        req.add_header("Authorization", "Bearer " + auth_token)

    # NOTE: urllib raises a HTTPError for status code >= 400
    if longpoll == -1:
        with request.urlopen(req) as response:
            return json.loads(response.read().decode())
    else:
        with request.urlopen(req, timeout=longpoll) as response:
            return json.loads(response.read().decode())

