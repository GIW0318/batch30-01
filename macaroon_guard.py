import hashlib
import hmac
from datetime import datetime, timezone

_ROOT_LABEL = b"macaroon-guard-root"
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _chain_value(identifier, caveats):
    chain = hmac.new(_ROOT_LABEL, identifier.encode("utf-8"), hashlib.sha256).hexdigest()
    for caveat in caveats:
        if not isinstance(caveat, dict) or not isinstance(caveat.get("cid"), str):
            raise ValueError("malformed caveat")
        vid = caveat.get("vid") or ""
        block = caveat["cid"] + "\n" + vid
        chain = hmac.new(chain.encode("utf-8"), block.encode("utf-8"), hashlib.sha256).hexdigest()
    return chain


def _parse_caveat(cid):
    if not isinstance(cid, str):
        raise ValueError("malformed caveat")
    for op in (" = ", " < "):
        if op in cid:
            key, _, value = cid.partition(op)
            key = key.strip()
            value = value.strip()
            if not key or not value:
                raise ValueError("malformed caveat")
            if "||" in value:
                raise ValueError("unsupported disjunction in caveat")
            return key, op.strip(), value
    raise ValueError("malformed caveat")


def _check_first_party(key, op, value, request, now):
    if key == "action":
        if op != "=" or value != request.get("action"):
            raise ValueError("action mismatch")
    elif key == "tenant":
        if op != "=" or value != request.get("tenant"):
            raise ValueError("tenant mismatch")
    elif key == "time":
        if op != "<":
            raise ValueError("unsupported time caveat")
        try:
            expiry = datetime.strptime(value, _TIME_FORMAT).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            raise ValueError("malformed time caveat") from None
        if now >= expiry:
            raise ValueError("token expired")
    else:
        raise ValueError("unknown caveat")


def _check_third_party(vid, request, verify_signature):
    discharges = request.get("discharges") or {}
    discharge = discharges.get(vid)
    if not isinstance(discharge, dict):
        raise ValueError("missing discharge for third-party caveat")
    identifier = discharge.get("identifier")
    if not identifier:
        raise ValueError("discharge has empty identifier")
    caveats = discharge.get("caveats") or []
    if not verify_signature(_chain_value(identifier, caveats)):
        raise ValueError("bad discharge signature")


def verify_macaroon(token, request, now, seen_nonce, verify_signature):
    identifier = token.get("identifier")
    if not identifier:
        raise ValueError("empty identifier")
    caveats = token.get("caveats") or []
    nonce = token.get("nonce")
    if not nonce or nonce in seen_nonce:
        raise ValueError("nonce missing or replayed")
    if not verify_signature(_chain_value(identifier, caveats)):
        raise ValueError("bad signature")
    for caveat in caveats:
        if not isinstance(caveat, dict):
            raise ValueError("malformed caveat")
        key, op, value = _parse_caveat(caveat.get("cid"))
        vid = caveat.get("vid")
        if vid:
            _check_third_party(vid, request, verify_signature)
        else:
            _check_first_party(key, op, value, request, now)
    seen_nonce.add(nonce)
    return {"identifier": identifier, "caveats": [c["cid"] for c in caveats]}
