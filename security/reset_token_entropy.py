"""Password-reset token hardening.

The insecure scheme this module replaces built the token out of a timestamp and
the user id.  Both are public and guessable, the token never expired and could
be replayed, so anyone who saw a reset link could take the account over again
and again.

Design rules enforced here:

* Tokens are 256-bit values from ``secrets`` (the OS CSPRNG).  Timestamps and
  user ids are never part of the secret.
* Only a SHA-256 digest of a token is stored; the raw token lives solely in the
  email that is sent to the account owner.
* Tokens expire after ``TTL_SECONDS`` (15 minutes).
* Tokens are single-use.  Consumption is atomic, and a successful redemption
  revokes every other outstanding token for the same user.
* A token is bound to the device fingerprint that requested it (secondary
  signal only -- fingerprints are spoofable, so they never replace expiry,
  single-use and the email channel).
* A successful reset always notifies the account's original address.
* Failures are deliberately indistinguishable to the caller so the endpoint
  cannot be used to enumerate accounts, and failed attempts are rate limited.

All public functions tolerate arbitrary arguments (the contract tests call each
one with two positional arguments) but reject anything that is not a valid
token instead of guessing.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
from collections import Counter

__all__ = [
    "csprng",
    "expiry",
    "single_use",
    "device_bind",
    "notify_owner",
    "token_store",
    "compare",
    "rate_limit",
    "validation",
    "audit",
    "revoke_all",
    "error_map",
    "cleanup",
    "entropy_check",
    "fallback",
    "issue_token",
    "reset_password",
]

# --- policy constants -------------------------------------------------------

TOKEN_BYTES = 32              # 256 bits of CSPRNG output
MIN_TOKEN_CHARS = 32          # token_urlsafe(32) -> 43 chars
MAX_TOKEN_CHARS = 512
TTL_SECONDS = 15 * 60         # reset link lifetime
MAX_ATTEMPTS = 5              # redemptions per key per window
WINDOW_SECONDS = 15 * 60
MAX_AUDIT_EVENTS = 10_000

TOKEN_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

# Keys are always HMAC'd; the raw token, the raw fingerprint and passwords are
# never persisted.
_BINDING_KEY = secrets.token_bytes(32)

_LOCK = threading.RLock()
_STORE: dict = {"tokens": {}}
_RATE: dict[str, list[float]] = {}
_AUDIT: list[dict] = []
_OUTBOX: list[dict] = []

_REDACT = frozenset(
    {"token", "raw_token", "password", "new_password", "old_password", "secret",
     "device_fp", "fingerprint"}
)

GENERIC_FAILURE = (
    "This reset link is invalid or has expired. Request a new one."
)


# --- helpers ----------------------------------------------------------------

def _as_float(value, default):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _now(now=None) -> float:
    return _as_float(now, time.time())


def _digest(token) -> str:
    """Digest of a token; the raw value is never stored or logged."""
    if isinstance(token, bytes):
        raw = token
    else:
        raw = str(token).encode("utf-8", "surrogatepass")
    return hashlib.sha256(raw).hexdigest()


# --- primitives -------------------------------------------------------------

def csprng(nbytes=TOKEN_BYTES, *_args, **_kwargs) -> str:
    """Return a URL-safe token from the OS CSPRNG (never below 256 bits)."""
    nbytes = int(_as_float(nbytes, TOKEN_BYTES))
    nbytes = max(TOKEN_BYTES, nbytes)
    return secrets.token_urlsafe(nbytes)


def expiry(ttl=TTL_SECONDS, now=None, *_args, **_kwargs) -> dict:
    """Describe when a token issued now stops being valid (15 minutes)."""
    ttl = _as_float(ttl, TTL_SECONDS)
    if ttl <= 0:
        ttl = float(TTL_SECONDS)
    created = _now(now)
    return {
        "created_at": created,
        "expires_at": created + ttl,
        "ttl": ttl,
        "ttl_seconds": int(ttl),
    }


def device_bind(device_fp, user_id=None, token=None, *_args, **_kwargs) -> str:
    """HMAC binding of (user, token, device fingerprint).

    Stored instead of the raw fingerprint.  Verification uses ``compare`` so
    the check is constant-time.
    """
    msg = "\x00".join(str(part) for part in (user_id, token, device_fp))
    return hmac.new(_BINDING_KEY, msg.encode("utf-8", "surrogatepass"),
                    hashlib.sha256).hexdigest()


def compare(left, right, *_args, **_kwargs) -> bool:
    """Constant-time comparison; type/encoding errors are failures, not raises."""
    try:
        a = left.encode("utf-8") if isinstance(left, str) else bytes(left)
        b = right.encode("utf-8") if isinstance(right, str) else bytes(right)
    except Exception:
        hmac.compare_digest(b"\x00", b"\x01")  # keep timing uniform
        return False
    return hmac.compare_digest(a, b)


def entropy_check(token, *_args, min_bits=128.0, **_kwargs) -> dict:
    """Measure the Shannon entropy of a candidate token.

    Used by tests/monitoring to catch a regression back to guessable tokens
    (e.g. ``f"{timestamp}{user_id}"`` scores far below the threshold).
    """
    min_bits = _as_float(min_bits, 128.0)
    if not isinstance(token, str) or not token:
        return {"ok": False, "reason": "not_a_string", "bits": 0.0,
                "length": 0, "min_bits": min_bits}

    length = len(token)
    counts = Counter(token)
    per_char = -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )
    bits = per_char * length
    alphabet_ok = set(token) <= TOKEN_ALPHABET
    ok = bool(length >= MIN_TOKEN_CHARS and bits >= min_bits and alphabet_ok)
    return {
        "ok": ok,
        "bits": round(bits, 2),
        "length": length,
        "alphabet_ok": alphabet_ok,
        "min_bits": min_bits,
        "reason": None if ok else "insufficient_entropy",
    }


def validation(token, device_fp=None, *_args, min_chars=MIN_TOKEN_CHARS,
               max_chars=MAX_TOKEN_CHARS, **_kwargs) -> dict:
    """Validate token shape before any store lookup."""
    errors: list[str] = []
    if not isinstance(token, str):
        errors.append("token_not_a_string")
    else:
        if len(token) < min_chars:
            errors.append("token_too_short")
        if len(token) > max_chars:
            errors.append("token_too_long")
        if not set(token) <= TOKEN_ALPHABET:
            errors.append("token_has_invalid_characters")
    if device_fp is not None and not str(device_fp).strip():
        errors.append("device_fingerprint_missing")
    return {
        "ok": not errors,
        "errors": errors,
        "message": GENERIC_FAILURE if errors else None,
    }


def token_store(store=None, *_args, **_kwargs) -> dict:
    """Return a token store, creating the process-wide one when none is given."""
    if isinstance(store, dict) and isinstance(store.get("tokens"), dict):
        return store
    return _STORE


def _consume_digest(digest, store, now) -> bool:
    """Atomically mark a token digest as used; called with the lock held."""
    tokens = token_store(store)["tokens"]
    ts = _now(now)
    with _LOCK:
        record = tokens.get(digest)
        if not isinstance(record, dict):
            return False
        if record.get("used_at") is not None:
            return False
        if ts >= record.get("expires_at", 0):
            return False
        record["used_at"] = ts
        return True


def single_use(token, store=None, now=None, *_args, **_kwargs) -> bool:
    """Atomically consume a token.  True only for the first valid redemption.

    A replay (or a token consumed by a concurrent request) returns False.
    """
    return _consume_digest(_digest(token), store, now)


def rate_limit(key, limit=MAX_ATTEMPTS, window=WINDOW_SECONDS, now=None,
               *_args, **_kwargs) -> dict:
    """Sliding-window attempt limiter keyed by user id, IP or device."""
    ts = _now(now)
    limit = max(1, int(_as_float(limit, MAX_ATTEMPTS)))
    window = max(1.0, _as_float(window, WINDOW_SECONDS))
    bucket_key = str(key)
    with _LOCK:
        attempts = _RATE.setdefault(bucket_key, [])
        cutoff = ts - window
        attempts[:] = [t for t in attempts if t > cutoff]
        allowed = len(attempts) < limit
        if allowed:
            attempts.append(ts)
        retry_after = 0.0
        if not allowed and attempts:
            retry_after = round(max(0.0, window - (ts - attempts[0])), 3)
        return {
            "allowed": allowed,
            "remaining": max(0, limit - len(attempts)),
            "retry_after": retry_after,
            "limit": limit,
            "window": window,
        }


def audit(event, *_args, **_fields) -> dict:
    """Append a redacted audit event.  Tokens and passwords never enter it."""
    safe = {
        key: ("[redacted]" if key in _REDACT else value)
        for key, value in _fields.items()
    }
    record = {"at": time.time(), "event": str(event), "fields": safe}
    with _LOCK:
        _AUDIT.append(record)
        if len(_AUDIT) > MAX_AUDIT_EVENTS:
            del _AUDIT[: len(_AUDIT) - MAX_AUDIT_EVENTS]
    return record


def notify_owner(email, user_id=None, event="password_reset", now=None,
                 *_args, **_kwargs) -> dict:
    """Notify the account's original address after a security event.

    A successful password reset must always reach the old address so the real
    owner can react if the reset was not theirs.  The raw token is never put in
    the notification record.
    """
    record = {
        "at": _now(now),
        "to": str(email) if email is not None else None,
        "user_id": user_id,
        "event": str(event),
        "delivered": bool(email),
    }
    with _LOCK:
        _OUTBOX.append(record)
    return record


def revoke_all(user_id, store=None, now=None, *_args, **_kwargs) -> int:
    """Invalidate every outstanding reset token for a user (returns count)."""
    tokens = token_store(store)["tokens"]
    target = str(user_id)
    with _LOCK:
        doomed = [
            digest
            for digest, record in tokens.items()
            if isinstance(record, dict) and str(record.get("user_id")) == target
        ]
        for digest in doomed:
            tokens.pop(digest, None)
    return len(doomed)


def error_map(code, *_args, **_kwargs) -> str:
    """Map internal failure reasons to one generic, non-enumerating message."""
    code = str(code).strip().lower()
    if code in {"rate_limited", "too_many_attempts"}:
        return "Too many reset attempts. Please try again in a few minutes."
    # expired / used / unknown / device_mismatch deliberately collapse into the
    # same response so callers cannot probe which case applies.
    return GENERIC_FAILURE


def cleanup(store=None, now=None, *_args, **_kwargs) -> int:
    """Drop expired and already-consumed tokens plus stale rate-limit buckets."""
    ts = _now(now)
    tokens = token_store(store)["tokens"]
    removed = 0
    with _LOCK:
        for digest, record in list(tokens.items()):
            if not isinstance(record, dict):
                tokens.pop(digest, None)
                removed += 1
                continue
            expired = ts >= record.get("expires_at", 0)
            consumed = record.get("used_at") is not None
            if expired or consumed:
                tokens.pop(digest, None)
                removed += 1

        cutoff = ts - WINDOW_SECONDS
        for key in list(_RATE):
            _RATE[key] = [t for t in _RATE[key] if t > cutoff]
            if not _RATE[key]:
                _RATE.pop(key, None)
    return removed


def fallback(cause=None, *_args, **_kwargs) -> dict:
    """Fail closed when a primitive (e.g. the CSPRNG) is unavailable.

    There is intentionally no weaker fallback: we never fall back to
    ``random``, timestamps or user ids.  The caller refuses the reset instead.
    """
    audit("reset.fallback", cause=str(cause) if cause is not None else None)
    return {
        "ok": False,
        "action": "fail_closed",
        "generated_token": False,
        "cause": str(cause) if cause is not None else None,
        "message": GENERIC_FAILURE,
    }


# --- end-to-end flow --------------------------------------------------------

def issue_token(user_id, email, device_fp, store=None, now=None,
                *_args, **_kwargs) -> dict:
    """Mint a fresh reset token and record its digest.

    Returns ``{"ok": True, "token": <raw>, "expires_at": ...}``; the raw token
    must only travel to the owner's mailbox.
    """
    try:
        token = csprng()
    except Exception as exc:  # noqa: BLE001 - never degrade to weak randomness
        return fallback(exc)

    shape = validation(token, device_fp)
    if not shape["ok"]:
        return {"ok": False, "error": "bad_token_shape",
                "message": shape["message"]}

    digest = _digest(token)
    window = expiry(TTL_SECONDS, now)
    record = {
        "user_id": user_id,
        "email": email,
        "device_hash": device_bind(device_fp, user_id, digest),
        "issued_at": window["created_at"],
        "expires_at": window["expires_at"],
        "used_at": None,
    }
    with _LOCK:
        token_store(store)["tokens"][digest] = record

    audit("reset.issued", user_id=user_id)
    return {
        "ok": True,
        "token": token,
        "expires_at": window["expires_at"],
        "ttl_seconds": window["ttl_seconds"],
    }


def reset_password(token, new_password, device_fp, store=None, now=None,
                   *_args, **_kwargs) -> dict:
    """Redeem a token: validate -> bind -> expire -> consume -> revoke -> notify."""
    ts = _now(now)
    store = token_store(store)
    digest = _digest(token)
    fail = {"ok": False, "error": "invalid_token", "message": GENERIC_FAILURE}

    shape = validation(token, device_fp)
    if not shape["ok"]:
        audit("reset.rejected", reason="malformed")
        return fail

    if not rate_limit(f"reset:{device_fp}", now=ts)["allowed"]:
        audit("reset.rejected", reason="rate_limited")
        return {"ok": False, "error": "rate_limited",
                "message": error_map("rate_limited")}

    with _LOCK:
        record = store["tokens"].get(digest)
        snapshot = dict(record) if isinstance(record, dict) else None

    if snapshot is None:
        audit("reset.rejected", reason="unknown")
        return fail
    if ts >= snapshot["expires_at"]:
        audit("reset.rejected", reason="expired", user_id=snapshot.get("user_id"))
        return fail
    if snapshot.get("used_at") is not None:
        audit("reset.rejected", reason="replayed", user_id=snapshot.get("user_id"))
        return fail

    expected = device_bind(device_fp, snapshot.get("user_id"), digest)
    if not compare(expected, snapshot.get("device_hash")):
        audit("reset.rejected", reason="device_mismatch",
              user_id=snapshot.get("user_id"))
        return fail

    if not isinstance(new_password, str) or len(new_password) < 8:
        audit("reset.rejected", reason="weak_password",
              user_id=snapshot.get("user_id"))
        return {"ok": False, "error": "weak_password",
                "message": "Choose a password with at least 8 characters."}

    # Atomic single-use guard: two concurrent requests, only one wins.
    if not _consume_digest(digest, store, ts):
        audit("reset.rejected", reason="replayed",
              user_id=snapshot.get("user_id"))
        return fail

    revoke_all(snapshot.get("user_id"), store, now=ts)

    if snapshot.get("email"):
        notify_owner(snapshot["email"], user_id=snapshot.get("user_id"),
                     event="password_reset", now=ts)

    audit("reset.succeeded", user_id=snapshot.get("user_id"))
    return {"ok": True, "user_id": snapshot.get("user_id"),
            "message": "Password updated. The account owner has been notified."}
