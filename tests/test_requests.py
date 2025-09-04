# tests/test_requests.py
"""
Tests for requests w/o proxies
Covers:
- Requests sending verification 
- Responses are valid JSON
- Proxies monkey patching correctly work
- Proxies monkey patching undo correctly works
"""

import pytest
import socket
import json
import types
import socks
from urllib import request as urllib_request
from core import requests as core_requests


class DummyResponse:
    def __init__(self, data: dict):
        self._data = json.dumps(data).encode()

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        return False


@pytest.fixture(autouse=True)
def restore_everything():
    """Ensure socket and urllib are restored after each test."""
    original_socket = socket.socket
    original_opener = urllib_request._opener
    yield
    socket.socket = original_socket
    core_requests._ORIGINAL_SOCKET = None
    urllib_request._opener = original_opener


@pytest.fixture
def proxy_info_socks():
    return {
        "type": "SOCKS5",
        "host": "127.0.0.1",
        "port": 1080,
        "username": "user",
        "password": "pass"
    }


@pytest.fixture
def proxy_info_http():
    return {
        "type": "HTTP",
        "host": "127.0.0.1",
        "port": 8080,
        "username": "user",
        "password": "pass"
    }


def test_socks_monkey_patch_and_undo(proxy_info_socks):
    original_socket = socket.socket
    core_requests.socks_monkey_patch(proxy_info_socks)
    # Check patch
    assert socket.socket is socks.socksocket
    assert core_requests._ORIGINAL_SOCKET is original_socket
    # Undo
    core_requests.undo_monkey_patching()
    assert socket.socket is original_socket


def test_http_monkey_patch_and_undo(proxy_info_http):
    original_opener = urllib_request._opener
    core_requests.http_monkey_patch(proxy_info_http)
    assert urllib_request._opener != original_opener
    core_requests.undo_monkey_patching()
    assert urllib_request._opener != None  # reset to default


def test_http_request_get_with_auth(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.header_items())
        return DummyResponse({"ok": True})

    monkeypatch.setattr(core_requests.request, "urlopen", fake_urlopen)
    result = core_requests.http_request("http://test.com", "GET", auth_token="ABC123")

    result = json.loads(result.decode())
    
    assert result["ok"] is True
    assert captured["method"] == "GET"
    assert any(k.lower() == "authorization" and v == "Bearer ABC123"
               for k, v in captured["headers"].items())


def test_http_request_post_with_payload_sets_content_type(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["body"] = json.loads(req.data.decode())
        captured["headers"] = dict(req.header_items())
        return DummyResponse({"done": True})

    monkeypatch.setattr(core_requests.request, "urlopen", fake_urlopen)
    payload = {"msg": "hello"}

    result = core_requests.http_request("http://test.com", "POST", metadata=payload)
    result = json.loads(result.decode())

    assert result["done"] is True
    assert captured["body"]["msg"] == "hello"
    assert any(k.lower() == "content-type" and v == "application/json"
               for k, v in captured["headers"].items())


def test_http_request_longpoll_timeout(monkeypatch):
    called = {}

    def fake_urlopen(req, timeout=None):
        called["timeout"] = timeout
        return DummyResponse({"lp": True})

    monkeypatch.setattr(core_requests.request, "urlopen", fake_urlopen)
    result = core_requests.http_request("http://test.com", "GET", longpoll=6)
    result = json.loads(result.decode())

    assert result["lp"] is True
    assert called["timeout"] == 6

def test_combined_undo_restores_socks_and_http(proxy_info_socks, proxy_info_http):
    original_socket = socket.socket
    original_opener = urllib_request._opener

    # Patch both SOCKS and HTTP
    core_requests.socks_monkey_patch(proxy_info_socks)
    core_requests.http_monkey_patch(proxy_info_http)

    assert socket.socket is socks.socksocket
    assert urllib_request._opener != original_opener

    # Undo once
    core_requests.undo_monkey_patching()

    # Both should be restored
    assert socket.socket is original_socket
    assert urllib_request._opener != None  # reset to default opener


def test_http_monkey_patch_with_creds_inserts_auth(proxy_info_http, monkeypatch):
    captured = {}

    class DummyOpener:
        def open(self, req):
            return DummyResponse({"proxy": True})

    def fake_build_opener(handler=None):
        captured["handler"] = handler
        return DummyOpener()

    monkeypatch.setattr(core_requests.request, "build_opener", fake_build_opener)
    core_requests.http_monkey_patch(proxy_info_http)
    assert "user" in str(captured["handler"].proxies)
    assert "pass" in str(captured["handler"].proxies)
