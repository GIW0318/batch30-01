import math


BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
LOGOUT_TOKEN_TYPE = "logout+jwt"
MAX_TOKEN_AGE = 300


def _is_timestamp(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def validate_logout_token(token, issuer, client_id, verify, now, seen_jti):
    if not isinstance(token, dict):
        raise ValueError("logout token must be an object")

    header = token.get("header")
    claims = token.get("claims")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("logout token header and claims must be objects")
    if "signature" not in token or token["signature"] is None:
        raise ValueError("logout token is not signed")

    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or not algorithm:
        raise ValueError("logout token algorithm is missing")
    if algorithm.lower() == "none":
        raise ValueError("unsigned logout token is not allowed")

    token_type = header.get("typ")
    if not isinstance(token_type, str) or token_type.lower() != LOGOUT_TOKEN_TYPE:
        raise ValueError("invalid logout token type")

    if not isinstance(issuer, str) or not issuer:
        raise ValueError("issuer is not configured")
    if not isinstance(client_id, str) or not client_id:
        raise ValueError("client_id is not configured")
    if not callable(verify):
        raise ValueError("signature verifier is not configured")

    try:
        signature_valid = verify(header, claims, token["signature"])
    except Exception as exc:
        raise ValueError("logout token signature verification failed") from exc
    if not signature_valid:
        raise ValueError("logout token signature verification failed")

    token_issuer = claims.get("iss")
    if not isinstance(token_issuer, str) or token_issuer != issuer:
        raise ValueError("issuer does not match")

    audience = claims.get("aud")
    if isinstance(audience, str):
        audiences = [audience]
    elif isinstance(audience, list):
        audiences = audience
    else:
        raise ValueError("invalid audience")
    if not audiences or any(
        not isinstance(value, str) or not value for value in audiences
    ):
        raise ValueError("invalid audience")
    if client_id not in audiences:
        raise ValueError("audience does not match")

    has_sub = "sub" in claims
    has_sid = "sid" in claims
    if not has_sub and not has_sid:
        raise ValueError("logout token requires sub or sid")
    if has_sub:
        sub = claims["sub"]
        if not isinstance(sub, str) or not sub:
            raise ValueError("invalid sub")
    if has_sid:
        sid = claims["sid"]
        if not isinstance(sid, str) or not sid:
            raise ValueError("invalid sid")

    events = claims.get("events")
    if (
        not isinstance(events, dict)
        or BACKCHANNEL_LOGOUT_EVENT not in events
        or not isinstance(events[BACKCHANNEL_LOGOUT_EVENT], dict)
    ):
        raise ValueError("backchannel-logout event is missing")

    if "nonce" in claims:
        raise ValueError("logout token must not contain nonce")

    if not _is_timestamp(now):
        raise ValueError("invalid current time")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if not _is_timestamp(issued_at) or not _is_timestamp(expires_at):
        raise ValueError("invalid iat or exp")
    if issued_at > now or now - issued_at > MAX_TOKEN_AGE:
        raise ValueError("logout token is stale or issued in the future")
    if expires_at <= issued_at or expires_at <= now:
        raise ValueError("logout token is expired")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise ValueError("invalid jti")
    if jti in seen_jti:
        raise ValueError("logout token has already been used")
    seen_jti.add(jti)

    return claims
