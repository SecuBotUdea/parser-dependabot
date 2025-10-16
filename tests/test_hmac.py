# tests/test_hmac.py
import hashlib
import hmac

from app.webhook import verify_signature


def test_verify_signature_valid():
    body = b'{"foo":"bar"}'
    secret = b"testsecret"
    mac = hmac.new(secret, msg=body, digestmod=hashlib.sha256).hexdigest()
    header = f"sha256={mac}"
    assert verify_signature(body, header, secret_bytes=secret) is True


def test_verify_signature_invalid():
    body = b'{"foo":"bar"}'
    header = "sha256=deadbeef"
    assert verify_signature(body, header, secret_bytes=b"wrong") is False
