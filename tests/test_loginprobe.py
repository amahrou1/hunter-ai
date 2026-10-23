"""The gated-login kit: a small, CODE-CAPPED set of default/collected-credential
guesses and differential username enumeration - never a brute force. Tests the
detection logic and the hard attempt cap against a local fake login server."""

from __future__ import annotations

import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import pytest

from hunter import loginprobe


def _server(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/login"


def _opener():
    return urllib.request.build_opener()


def _redirect_login(valid_user="admin", valid_pw="admin"):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            q = parse_qs(self.rfile.read(n).decode())
            if q.get("username", [""])[0] == valid_user and q.get("password", [""])[0] == valid_pw:
                self.send_response(302)
                self.send_header("Set-Cookie", "session=abc; Path=/")
                self.send_header("Location", "/dashboard")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Invalid username or password. Try again.")
        def log_message(self, *a):
            pass
    return H


def test_detects_working_default_credential():
    srv, url = _server(_redirect_login("admin", "admin"))
    try:
        res = loginprobe.probe(url, _opener(), loginprobe.DEFAULT_CREDS)
        assert len(res["working"]) == 1
        assert res["working"][0]["user"] == "admin"
        assert "****" not in res["working"][0].get("password", "")  # masked, not raw
    finally:
        srv.shutdown()


def test_no_working_credential_is_clean():
    srv, url = _server(_redirect_login("realadmin", "S3cret!longpw"))
    try:
        res = loginprobe.probe(url, _opener(), loginprobe.DEFAULT_CREDS)
        assert res["working"] == []
    finally:
        srv.shutdown()


def test_attempt_cap_is_enforced():
    # a list far longer than the cap must stop at MAX_ATTEMPTS
    srv, url = _server(_redirect_login("nobody", "nopw"))
    try:
        big = [(f"u{i}", f"p{i}") for i in range(500)]
        res = loginprobe.probe(url, _opener(), big, max_attempts=loginprobe.MAX_ATTEMPTS)
        assert res["tried"] <= loginprobe.MAX_ATTEMPTS
        assert "cap" in (res.get("note") or "")
    finally:
        srv.shutdown()


def test_password_is_masked():
    assert loginprobe._mask("admin") == "a***n"
    assert loginprobe._mask("") == "(empty)"
    assert loginprobe._mask("ab") == "**"


def test_username_enumeration_by_response_difference():
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            u = parse_qs(self.rfile.read(n).decode()).get("username", [""])[0]
            self.send_response(200)
            self.end_headers()
            if u in ("admin", "root", "support"):
                self.wfile.write(b"Password incorrect for this account. Please contact your administrator again.")
            else:
                self.wfile.write(b"No such user")
        def log_message(self, *a):
            pass
    srv, url = _server(H)
    try:
        res = loginprobe.enumerate_users(url, _opener())
        found = {c["user"] for c in res["valid_candidates"]}
        assert {"admin", "root", "support"} <= found
        assert "demo" not in found
    finally:
        srv.shutdown()


def test_enum_cap_is_enforced():
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"x")
        def log_message(self, *a):
            pass
    srv, url = _server(H)
    try:
        res = loginprobe.enumerate_users(url, _opener(),
                                         usernames=[f"u{i}" for i in range(500)],
                                         max_enum=loginprobe.MAX_ENUM)
        assert res["tried"] <= loginprobe.MAX_ENUM
    finally:
        srv.shutdown()


def test_json_mode_login():
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            import json
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n).decode() or "{}")
            if body.get("username") == "admin" and body.get("password") == "admin":
                self.send_response(200); self.send_header("Set-Cookie", "token=x; Path=/"); self.end_headers()
                self.wfile.write(b'{"ok":true,"dashboard":"/home"}')
            else:
                self.send_response(401); self.end_headers(); self.wfile.write(b'{"error":"invalid"}')
        def log_message(self, *a):
            pass
    srv, url = _server(H)
    try:
        res = loginprobe.probe(url, _opener(), [("admin", "admin")], json_mode=True)
        assert len(res["working"]) == 1
    finally:
        srv.shutdown()


def test_detect_fields_reads_form():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers()
            self.wfile.write(b'<form><input name="email" type="text"><input name="pass" type="password"></form>')
        def log_message(self, *a): pass
    srv, _ = _server(H)
    page = f"http://127.0.0.1:{srv.server_address[1]}/login"
    try:
        fm = loginprobe.detect_fields(page, _opener())
        assert fm == {"user": "email", "password": "pass"}
    finally:
        srv.shutdown()


def test_detect_fields_none_when_no_form():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"<html>no form here</html>")
        def log_message(self, *a): pass
    srv, _ = _server(H)
    page = f"http://127.0.0.1:{srv.server_address[1]}/x"
    try:
        assert loginprobe.detect_fields(page, _opener()) is None
    finally:
        srv.shutdown()
