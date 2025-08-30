from urllib import request, error
import urllib
import json
import logging

logger = logging.getLogger(__name__)

_ORIGINAL_SOCKET = None

def socks_monkey_patch(proxy_info: dict = None):
    import socks
    import socket
    global _ORIGINAL_SOCKET
    
    if proxy_info["username"] and proxy_info["password"]:
        socks.set_default_proxy(
            socks.SOCKS5 if proxy_info["type"] == "SOCKS5" else socks.SOCKS4,
            proxy_info["host"], 
            proxy_info["port"],
            username=proxy_info["username"],
            password=proxy_info["password"]
        )
    else:
        socks.set_default_proxy(
            socks.SOCKS5 if proxy_info["type"] == "SOCKS5" else socks.SOCKS4,
            proxy_info["host"], 
            proxy_info["port"],
        )

    _ORIGINAL_SOCKET = socket.socket  # save our socket before patching monkey patching socks
    socket.socket = socks.socksocket 


def http_monkey_patch(proxy_info: dict = None):
    if proxy_info and proxy_info["type"] == "HTTP":
        proxy_str = f"{proxy_info['host']}:{proxy_info['port']}"
        if proxy_info["username"] and proxy_info["password"]:
            proxy_str = f"{proxy_info['username']}:{proxy_info['password']}@{proxy_str}"

        proxy_handler = request.ProxyHandler({
            'http': 'http://' + proxy_str,
            'https': 'http://' + proxy_str
        })

        opener = request.build_opener(proxy_handler)
        request.install_opener(opener)


def undo_monkey_patching():
    # This undos the custom opener for urllib
    request.install_opener(request.build_opener())
    
    # This tries to undo the monkey patching we did using Pysocks
    if _ORIGINAL_SOCKET:
        import socket
        socket.socket = _ORIGINAL_SOCKET


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

    try:
        if longpoll == -1:
            with request.urlopen(req) as response:
                return json.loads(response.read().decode())
        else:
            with request.urlopen(req, timeout=longpoll) as response:
                return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        logger.error("We received error from server: %s", body)
        raise Exception(body)
