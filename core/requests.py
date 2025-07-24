from urllib import request
import urllib
import json
import time

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

    # urllib raises a HTTPError for status code >= 400
    # try:
    if longpoll == -1:
        with request.urlopen(req) as response:
            return json.loads(response.read().decode())
    else:
        with request.urlopen(req, timeout=longpoll) as response:
            return json.loads(response.read().decode())


    # except urllib.error.HTTPError as e:
    #    return json.loads(e.read().decode())
