import hashlib
import hmac
import logging
import os
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("webhook.security")

DEBUG = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
WEBHOOK_SECRET_BYTES = WEBHOOK_SECRET.encode() if WEBHOOK_SECRET else b""


def _to_bytes(x: Optional[bytes | str]) -> bytes:
    if x is None:
        return b""
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    return str(x).encode()


def verify_signature(
    body: bytes,
    signature_header: Optional[str],
    secret_bytes: Optional[bytes | str] = None,
) -> bool:
    if not isinstance(body, (bytes, bytearray, memoryview)):
        try:
            body = str(body).encode()
        except Exception:
            body = b""

    if not signature_header:
        if DEBUG:
            logger.debug("verify_signature: missing signature header")
        return False

    if isinstance(signature_header, (bytes, bytearray)):
        try:
            signature_header = signature_header.decode("utf-8", errors="ignore")
        except Exception:
            signature_header = str(signature_header)

    signature_header = signature_header.strip()
    if "=" not in signature_header:
        if DEBUG:
            logger.debug(
                "verify_signature: signature header no '=': %r", signature_header
            )
        return False

    sha_name, signature = signature_header.split("=", 1)
    if sha_name.strip().lower() != "sha256":
        if DEBUG:
            logger.debug("verify_signature: unsupported digest %r", sha_name)
        return False

    signature = signature.strip().lower()
    secret = (
        _to_bytes(secret_bytes)
        if secret_bytes is not None
        else WEBHOOK_SECRET_BYTES or b""
    )

    try:
        mac = hmac.new(secret, msg=body, digestmod=hashlib.sha256)
        expected_hex = mac.hexdigest().lower()
        result = hmac.compare_digest(expected_hex, signature)
        if DEBUG:
            logger.debug("verify_signature: result=%s signature=%s", result, signature)
        return result
    except Exception as exc:
        logger.exception("verify_signature: unexpected error: %s", exc)
        return False
