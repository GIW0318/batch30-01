import pytest

import oidc_logout as ol

NOW = 1_800_000_000
ISSUER = "https://idp.example.com"
CLIENT = "client-1"
EVENT = "http://schemas.openid.net/event/backchannel-logout"


def token(**overrides):
    claims = {
        "iss": ISSUER,
        "aud": CLIENT,
        "iat": NOW - 10,
        "exp": NOW + 60,
        "jti": "jti-1",
        "sid": "sid-1",
        "events": {EVENT: {}},
    }
    claims.update(overrides)
    return {"header": {"alg": "RS256", "typ": "logout+jwt"}, "claims": claims, "signature": "sig"}


def verify_ok(header, claims, signature):
    return True


def test_valid_token_is_returned():
    claims = token()["claims"]
    assert ol.validate_logout_token(token(), ISSUER, CLIENT, verify_ok, NOW, set()) == claims


def test_missing_issuer_is_rejected():
    with pytest.raises(ValueError):
        ol.validate_logout_token(token(iss=None), ISSUER, CLIENT, verify_ok, NOW, set())


def test_wrong_issuer_is_rejected():
    with pytest.raises(ValueError):
        ol.validate_logout_token(token(iss="https://evil.example.com"), ISSUER, CLIENT, verify_ok, NOW, set())


def test_wrong_audience_is_rejected():
    with pytest.raises(ValueError):
        ol.validate_logout_token(token(aud="other"), ISSUER, CLIENT, verify_ok, NOW, set())


def test_missing_sub_and_sid_is_rejected():
    claims = token()["claims"]
    claims.pop("sid")
    with pytest.raises(ValueError):
        ol.validate_logout_token({"header": {"alg": "RS256", "typ": "logout+jwt"}, "claims": claims, "signature": "sig"}, ISSUER, CLIENT, verify_ok, NOW, set())


def test_missing_backchannel_event_is_rejected():
    with pytest.raises(ValueError):
        ol.validate_logout_token(token(events={}), ISSUER, CLIENT, verify_ok, NOW, set())


def test_nonce_is_rejected():
    with pytest.raises(ValueError):
        ol.validate_logout_token(token(nonce="n-1"), ISSUER, CLIENT, verify_ok, NOW, set())


def test_stale_iat_is_rejected():
    with pytest.raises(ValueError):
        ol.validate_logout_token(token(iat=NOW - 3600), ISSUER, CLIENT, verify_ok, NOW, set())


def test_expired_token_is_rejected():
    with pytest.raises(ValueError):
        ol.validate_logout_token(token(exp=NOW - 1), ISSUER, CLIENT, verify_ok, NOW, set())


def test_replayed_jti_is_rejected():
    with pytest.raises(ValueError):
        ol.validate_logout_token(token(), ISSUER, CLIENT, verify_ok, NOW, {"jti-1"})


def test_wrong_typ_is_rejected():
    t = token()
    t["header"]["typ"] = "JWT"
    with pytest.raises(ValueError):
        ol.validate_logout_token(t, ISSUER, CLIENT, verify_ok, NOW, set())


def test_alg_none_is_rejected():
    t = token()
    t["header"]["alg"] = "none"
    with pytest.raises(ValueError):
        ol.validate_logout_token(t, ISSUER, CLIENT, verify_ok, NOW, set())


def test_signature_failure_is_rejected():
    with pytest.raises(ValueError):
        ol.validate_logout_token(token(), ISSUER, CLIENT, lambda h, c, s: False, NOW, set())


def test_empty_sid_is_rejected():
    with pytest.raises(ValueError):
        ol.validate_logout_token(token(sid=""), ISSUER, CLIENT, verify_ok, NOW, set())


def test_audience_array_matches_any_entry():
    claims = token(aud=["other", CLIENT])["claims"]
    assert ol.validate_logout_token(token(aud=["other", CLIENT]), ISSUER, CLIENT, verify_ok, NOW, set()) == claims
