"""
Verify Auditail approval receipts before executing a high-risk action.

    from auditail.verify import verify_receipt
    r = verify_receipt(receipt, account="key_...", action="create_payout", payload=payout)
    if not r.valid:
        raise PermissionError(r.reason)

Requires the optional `cryptography` package:  pip install "auditail[verify]"
"""

import base64
import hashlib
import json
import time
import urllib.request
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional

from .client import DEFAULT_REDACT, _redact

DEFAULT_KEYS_URL = "https://api.auditail.io/.well-known/auditail-keys.json"
_key_cache: Dict[str, Any] = {}


@dataclass
class ReceiptResult:
    valid: bool
    reason: Optional[str] = None
    claims: Optional[Dict[str, Any]] = None


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_MAX_SAFE_INT = 2**53


def _js_number(x: float) -> str:
    """Format a float exactly like JavaScript's Number.prototype.toString (ECMAScript Number::toString)."""
    if x != x or x in (float("inf"), float("-inf")):
        return "null"  # JSON.stringify turns NaN and Infinity into null
    if x == 0:
        return "0"  # also covers -0.0
    sign = "-" if x < 0 else ""
    d = Decimal(repr(abs(x))).normalize()  # repr is the shortest round-trip form, same digits JavaScript picks
    t = d.as_tuple()
    digits = "".join(map(str, t.digits))
    k = len(digits)
    n = k + t.exponent
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        out = (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + ("+" if e > 0 else "-") + str(abs(e))
    return sign + out


def _js_key(k: str) -> bytes:
    return k.encode("utf-16-be", "surrogatepass")  # JavaScript sorts object keys by UTF-16 code units


def canonical_json(v: Any) -> str:
    """
    Deterministic JSON (sorted keys, no whitespace) that matches the Auditail server and the JS SDK byte for byte,
    including JavaScript's number formatting. Integers beyond 2**53 are treated the way JavaScript reads them
    (rounded to the nearest double), so send large identifiers as strings.
    """
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v) if abs(v) <= _MAX_SAFE_INT else _js_number(float(v))
    if isinstance(v, float):
        return _js_number(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonical_json(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(((str(k), x) for k, x in v.items()), key=lambda kv: _js_key(kv[0]))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical_json(x) for k, x in items) + "}"
    return json.dumps(str(v), ensure_ascii=False)


def payload_hash(payload: Dict[str, Any], redact_keys: Optional[Iterable[str]] = None) -> str:
    keys = DEFAULT_REDACT | {k.lower() for k in (redact_keys or [])}
    return hashlib.sha256(canonical_json(_redact(payload, keys)).encode("utf-8")).hexdigest()


def fetch_public_keys(url: str = DEFAULT_KEYS_URL) -> List[Dict[str, Any]]:
    """Fetch Auditail public keys (cached 5 minutes). For the strongest guarantee, pin them via public_keys=."""
    hit = _key_cache.get(url)
    if hit and time.time() - hit[0] < 300:
        return hit[1]
    req = urllib.request.Request(url, headers={"user-agent": "auditail-python-verify/1"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        keys = [k for k in json.load(resp).get("keys", []) if k.get("alg") == "Ed25519"]
    _key_cache[url] = (time.time(), keys)
    return keys


def _verify_sig(public_key_b64url: str, sig: bytes, data: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError('verify_receipt needs the "cryptography" package: pip install "auditail[verify]"') from exc
    try:
        Ed25519PublicKey.from_public_bytes(_b64url_decode(public_key_b64url)).verify(sig, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_receipt(
    receipt: str,
    account: str,
    action: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    agent_id: Optional[str] = None,
    environment: Optional[str] = None,
    redact_keys: Optional[Iterable[str]] = None,
    public_keys: Optional[List[Dict[str, Any]]] = None,
    keys_url: str = DEFAULT_KEYS_URL,
    clock_skew_seconds: int = 60,
    now: Optional[float] = None,
    require_human_approval: bool = False,
) -> ReceiptResult:
    """
    Check an approval receipt. Never raises for an invalid receipt; returns ReceiptResult(valid=False, reason=...).
    A valid result proves Auditail approved exactly this action and payload: a human (typ "approval") or your
    server-side policy (typ "decision"). Pass require_human_approval=True to accept only the former. You must still make
    receipts single-use: store claims["aid"] and reject receipts you have already accepted.
    """
    if not account:
        return ReceiptResult(False, "account is required")
    if not isinstance(receipt, str) or receipt.count(".") != 2 or not receipt.startswith("atr1."):
        return ReceiptResult(False, "malformed: expected atr1.<claims>.<signature>")
    prefix, body, sig = receipt.split(".")
    try:
        claims = json.loads(_b64url_decode(body))
    except Exception:
        return ReceiptResult(False, "malformed claims")
    try:
        keys = public_keys if public_keys is not None else fetch_public_keys(keys_url)
    except Exception as exc:
        return ReceiptResult(False, f"could not fetch Auditail public keys: {exc}")
    key = next((k for k in keys if k.get("kid") == claims.get("kid")), None)
    if not key:
        return ReceiptResult(False, f"unknown signing key {claims.get('kid')}", claims)
    try:
        signature = _b64url_decode(sig)
    except Exception:
        return ReceiptResult(False, "malformed signature", claims)
    if not _verify_sig(key["publicKey"], signature, f"{prefix}.{body}".encode("ascii")):
        return ReceiptResult(False, "bad signature (receipt was altered or not issued by Auditail)", claims)

    fail = lambda reason: ReceiptResult(False, reason, claims)  # noqa: E731
    if claims.get("v") != 1 or claims.get("typ") not in ("approval", "decision"):
        return fail("not an Auditail receipt")
    if require_human_approval and claims.get("typ") != "approval":
        return fail("a human approval is required, but this receipt is a policy decision")
    if claims.get("acct") != account:
        return fail("receipt belongs to a different Auditail account")
    if action is not None and claims.get("act") != action:
        return fail(f'receipt is for action "{claims.get("act")}", not "{action}"')
    if agent_id is not None and claims.get("agent") != agent_id:
        return fail(f'receipt is for agent "{claims.get("agent")}", not "{agent_id}"')
    if environment is not None and claims.get("env") != environment:
        return fail(f'receipt is for environment "{claims.get("env")}", not "{environment}"')
    t = int(now if now is not None else time.time())
    if t > claims.get("exp", 0) + clock_skew_seconds:
        return fail("receipt has expired")
    if claims.get("iat", 0) > t + clock_skew_seconds:
        return fail("receipt is not valid yet")
    if payload is not None and payload_hash(payload, redact_keys) != claims.get("ph"):
        return fail("payload does not match the approved payload")
    return ReceiptResult(True, None, claims)
