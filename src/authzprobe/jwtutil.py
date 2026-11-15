"""Tiny HS256 JWT helpers (stdlib only)."""
import base64
import hashlib
import hmac
import json
import time


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint(secret: str, claims: dict, ttl: int = 3600) -> str:
    now = int(time.time())
    body = {"iat": now, "exp": now + ttl}
    body.update(claims)
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps(body, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{head}.{payload}".encode(), hashlib.sha256).digest()
    return f"{head}.{payload}.{_b64(sig)}"


def decode_unverified(token: str):
    """Return the payload of a JWT without verifying it, or None if it isn't one."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        data = json.loads(_unb64(parts[1]))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def verify(secret: str, token: str):
    """Verify an HS256 JWT and return its payload, or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    expected = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    try:
        if not hmac.compare_digest(expected, _unb64(parts[2])):
            return None
    except Exception:
        return None
    payload = decode_unverified(token)
    if payload and payload.get("exp") and payload["exp"] < time.time():
        return None
    return payload


def key_role(key: str):
    """Role of a Supabase API key: 'anon', 'service_role', or None if unknown.

    Handles legacy JWT keys and the new sb_publishable_/sb_secret_ keys.
    """
    if not key:
        return None
    if key.startswith("sb_publishable_"):
        return "anon"
    if key.startswith("sb_secret_"):
        return "service_role"
    payload = decode_unverified(key)
    if payload:
        return payload.get("role")
    return None


def is_jwt(key: str) -> bool:
    return decode_unverified(key or "") is not None
