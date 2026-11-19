import base64
import hashlib
import hmac
import json
import numbers
from urllib.parse import urlsplit


_STRONG_ALGORITHMS = frozenset(
    {
        "ES256",
        "ES384",
        "ES512",
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
    }
)
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_THUMBPRINT_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "RSA": ("e", "kty", "n"),
    "OKP": ("crv", "kty", "x"),
}
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_IAT_MAX_AGE = 300
_IAT_MAX_FUTURE = 60


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _thumbprint(jwk):
    members = _THUMBPRINT_MEMBERS.get(jwk.get("kty"))
    if members is None:
        raise ValueError("unsupported JWK key type")

    canonical = {}
    for member in members:
        value = jwk.get(member)
        if not isinstance(value, str) or not value:
            raise ValueError("invalid JWK")
        canonical[member] = value

    encoded = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return _b64url(hashlib.sha256(encoded).digest())


def _normalize_htu(value, allow_fragment=False):
    if not isinstance(value, str) or not value:
        raise ValueError("invalid htu")

    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid htu") from exc

    if not parts.scheme or not parts.hostname:
        raise ValueError("invalid htu")
    if parts.fragment and not allow_fragment:
        raise ValueError("htu must not contain a fragment")

    scheme = parts.scheme.lower()
    hostname = parts.hostname.lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    if port == _DEFAULT_PORTS.get(scheme):
        port = None

    return (
        scheme,
        parts.username,
        parts.password,
        hostname,
        port,
        parts.path or "/",
        parts.query,
    )


def _token_hash(access_token):
    if not isinstance(access_token, str):
        raise ValueError("invalid access token")
    return _b64url(hashlib.sha256(access_token.encode("utf-8")).digest())


def _constant_time_equal(left, right):
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _validate_iat(iat, now):
    if (
        isinstance(iat, bool)
        or not isinstance(iat, numbers.Real)
        or isinstance(now, bool)
        or not isinstance(now, numbers.Real)
    ):
        raise ValueError("invalid iat")
    if iat < now - _IAT_MAX_AGE or iat > now + _IAT_MAX_FUTURE:
        raise ValueError("iat outside the allowed time window")


def verify_proof(proof, method, url, access_token, expected_jkt, nonce, now, seen_jti, verify):
    if not isinstance(proof, dict):
        raise ValueError("invalid DPoP proof")

    header = proof.get("header")
    claims = proof.get("claims")
    signature = proof.get("signature")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("invalid DPoP proof")
    if not isinstance(signature, str) or not signature:
        raise ValueError("missing DPoP signature")

    if header.get("typ") != "dpop+jwt":
        raise ValueError("invalid DPoP typ")

    alg = header.get("alg")
    if not isinstance(alg, str) or alg == "none" or alg not in _STRONG_ALGORITHMS:
        raise ValueError("unsupported DPoP algorithm")

    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise ValueError("missing DPoP JWK")
    if any(member in jwk for member in _PRIVATE_JWK_MEMBERS):
        raise ValueError("DPoP JWK must not contain private key material")

    if not isinstance(expected_jkt, str) or not expected_jkt:
        raise ValueError("missing expected jkt")
    if not _constant_time_equal(_thumbprint(jwk), expected_jkt):
        raise ValueError("DPoP key does not match the access token binding")

    htm = claims.get("htm")
    if not isinstance(method, str) or method != method.upper():
        raise ValueError("invalid HTTP method")
    if htm != method:
        raise ValueError("DPoP htm does not match the request method")

    if _normalize_htu(claims.get("htu")) != _normalize_htu(url, allow_fragment=True):
        raise ValueError("DPoP htu does not match the request URI")

    expected_ath = _token_hash(access_token)
    ath = claims.get("ath")
    if not isinstance(ath, str) or not _constant_time_equal(ath, expected_ath):
        raise ValueError("DPoP ath does not match the access token")

    _validate_iat(claims.get("iat"), now)

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise ValueError("invalid DPoP jti")
    if seen_jti is None:
        raise ValueError("missing jti replay cache")
    if jti in seen_jti:
        raise ValueError("DPoP proof has already been used")

    expected_nonce = "" if nonce is None else nonce
    proof_nonce = claims.get("nonce", "")
    if not isinstance(expected_nonce, str) or not isinstance(proof_nonce, str):
        raise ValueError("invalid DPoP nonce")
    if not _constant_time_equal(proof_nonce, expected_nonce):
        raise ValueError("DPoP nonce does not match")

    try:
        signature_valid = verify(proof, jwk)
    except Exception as exc:
        raise ValueError("DPoP signature verification failed") from exc
    if signature_valid is not True:
        raise ValueError("DPoP signature verification failed")

    seen_jti.add(jti)
    return claims
