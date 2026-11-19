import pytest

import spiffe_svid as sv

NOW = 1_800_000_000
BUNDLE = {"bundle-1": "public-key"}
SVID = {
    "type": "x509",
    "spiffe_id": "spiffe://example.org/ns/default/sa/api",
    "not_before": NOW - 10,
    "not_after": NOW + 10,
    "serial": "s-1",
    "bundle_id": "bundle-1",
    "signature": "sig",
    "audience": [],
}


def svid(**overrides):
    data = dict(SVID)
    data.update(overrides)
    return data


def verify_ok(value, key):
    return True


def test_valid_x509_svid():
    assert sv.validate_svid(svid(), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok) == {
        "spiffe_id": "spiffe://example.org/ns/default/sa/api",
        "serial": "s-1",
        "type": "x509",
    }


def test_wrong_trust_domain_is_rejected():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(spiffe_id="spiffe://evil.org/ns/default/sa/api"), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok)


def test_path_prefix_is_not_enough():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(spiffe_id="spiffe://example.org/ns/default/sa/api-evil"), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok)


def test_expired_svid_is_rejected():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(not_after=NOW - 1), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok)


def test_not_yet_valid_svid_is_rejected():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(not_before=NOW + 1), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok)


def test_unknown_bundle_id_is_rejected():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(bundle_id="bundle-2"), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok)


def test_signature_failure_is_rejected():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), lambda v, k: False)


def test_replayed_serial_is_rejected():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, {"s-1"}, verify_ok)


def test_valid_jwt_svid_with_audience():
    assert sv.validate_svid(svid(type="jwt", audience=["api", "mesh"]), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok) == {
        "spiffe_id": "spiffe://example.org/ns/default/sa/api",
        "serial": "s-1",
        "type": "jwt",
    }


def test_jwt_audience_mismatch_is_rejected():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(type="jwt", audience=["other"]), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok)


def test_jwt_missing_audience_is_rejected():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(type="jwt", audience=[]), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok)


def test_query_in_spiffe_id_is_rejected():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(spiffe_id="spiffe://example.org/ns/default/sa/api?x=1"), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok)


def test_dotdot_path_is_rejected():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(spiffe_id="spiffe://example.org/ns/default/../sa/api"), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok)


def test_malformed_spiffe_id_is_rejected():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(spiffe_id="not-a-spiffe-id"), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok)


def test_jwt_svid_must_use_jwt_type():
    with pytest.raises(ValueError):
        sv.validate_svid(svid(type="x509", audience=["api"]), "example.org", BUNDLE, ["/ns/default/sa/api"], NOW, set(), verify_ok)
