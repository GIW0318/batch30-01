import base64
import hashlib
import json

import pytest

import dpop_verify as dv

NOW = 1_800_000_000
JWK = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
TOKEN = "access-token-1"
URL = "https://api.example.com/resource"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jkt(jwk):
    canonical = json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode()
    return b64(hashlib.sha256(canonical).digest())


def ath(token):
    return b64(hashlib.sha256(token.encode()).digest())


def proof(**overrides):
    claims = {
        "htu": URL,
        "htm": "GET",
        "iat": NOW - 1,
        "jti": "jti-1",
        "ath": ath(TOKEN),
    }
    claims.update(overrides)
    return {"header": {"typ": "dpop+jwt", "alg": "ES256", "jwk": JWK}, "claims": claims, "signature": "sig"}


def verify_ok(p, jwk):
    return True


def test_valid_proof_returns_claims():
    claims = proof()["claims"]
    assert dv.verify_proof(proof(), "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), verify_ok) == claims


def test_wrong_typ_is_rejected():
    p = proof()
    p["header"]["typ"] = "JWT"
    with pytest.raises(ValueError):
        dv.verify_proof(p, "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), verify_ok)


def test_alg_none_is_rejected():
    p = proof()
    p["header"]["alg"] = "none"
    with pytest.raises(ValueError):
        dv.verify_proof(p, "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), verify_ok)


def test_missing_jwk_is_rejected():
    p = proof()
    p["header"].pop("jwk")
    with pytest.raises(ValueError):
        dv.verify_proof(p, "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), verify_ok)


def test_jkt_mismatch_is_rejected():
    with pytest.raises(ValueError):
        dv.verify_proof(proof(), "GET", URL, TOKEN, "wrong-jkt", "", NOW, set(), verify_ok)


def test_htm_mismatch_is_rejected():
    with pytest.raises(ValueError):
        dv.verify_proof(proof(htm="POST"), "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), verify_ok)


def test_htu_query_mismatch_is_rejected():
    with pytest.raises(ValueError):
        dv.verify_proof(proof(htu=URL + "?x=1"), "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), verify_ok)


def test_wrong_ath_is_rejected():
    with pytest.raises(ValueError):
        dv.verify_proof(proof(ath="wrong"), "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), verify_ok)


def test_replayed_jti_is_rejected():
    with pytest.raises(ValueError):
        dv.verify_proof(proof(), "GET", URL, TOKEN, jkt(JWK), "", NOW, {"jti-1"}, verify_ok)


def test_stale_iat_is_rejected():
    with pytest.raises(ValueError):
        dv.verify_proof(proof(iat=NOW - 3600), "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), verify_ok)


def test_nonce_mismatch_is_rejected():
    with pytest.raises(ValueError):
        dv.verify_proof(proof(nonce="old"), "GET", URL, TOKEN, jkt(JWK), "new", NOW, set(), verify_ok)


def test_signature_failure_is_rejected():
    with pytest.raises(ValueError):
        dv.verify_proof(proof(), "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), lambda p, jwk: False)


def test_private_key_in_jwk_is_rejected():
    p = proof()
    p["header"]["jwk"] = {**JWK, "d": "private"}
    with pytest.raises(ValueError):
        dv.verify_proof(p, "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), verify_ok)


def test_lowercase_method_is_rejected():
    with pytest.raises(ValueError):
        dv.verify_proof(proof(htm="get"), "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), verify_ok)


def test_default_port_is_normalized():
    p = proof(htu="https://api.example.com:443/resource")
    assert dv.verify_proof(p, "GET", URL, TOKEN, jkt(JWK), "", NOW, set(), verify_ok) == p["claims"]
