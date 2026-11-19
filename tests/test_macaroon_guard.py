import pytest

import macaroon_guard as mg

NOW = 1_800_000_000


def token(**overrides):
    data = {
        "identifier": "user=alice",
        "caveats": [{"cid": "action = read"}, {"cid": "tenant = t1"}],
        "signature": "sig",
        "nonce": "n-1",
    }
    data.update(overrides)
    return data


def request(**overrides):
    data = {"action": "read", "tenant": "t1", "discharges": {}}
    data.update(overrides)
    return data


def verify_ok(value):
    return True


def test_valid_macaroon():
    assert mg.verify_macaroon(token(), request(), NOW, set(), verify_ok) == {
        "identifier": "user=alice",
        "caveats": ["action = read", "tenant = t1"],
    }


def test_signature_failure_is_rejected():
    with pytest.raises(ValueError):
        mg.verify_macaroon(token(), request(), NOW, set(), lambda value: False)


def test_action_mismatch_is_rejected():
    with pytest.raises(ValueError):
        mg.verify_macaroon(token(), request(action="write"), NOW, set(), verify_ok)


def test_tenant_mismatch_is_rejected():
    with pytest.raises(ValueError):
        mg.verify_macaroon(token(), request(tenant="t2"), NOW, set(), verify_ok)


def test_unknown_caveat_is_rejected():
    with pytest.raises(ValueError):
        mg.verify_macaroon(token(caveats=[{"cid": "role = admin"}]), request(), NOW, set(), verify_ok)


def test_malformed_caveat_is_rejected():
    with pytest.raises(ValueError):
        mg.verify_macaroon(token(caveats=[{"cid": "action-read"}]), request(), NOW, set(), verify_ok)


def test_expired_time_caveat_is_rejected():
    with pytest.raises(ValueError):
        mg.verify_macaroon(token(caveats=[{"cid": "time < 2020-01-01T00:00:00Z"}]), request(), NOW, set(), verify_ok)


def test_valid_time_caveat_is_accepted():
    assert mg.verify_macaroon(token(caveats=[{"cid": "time < 2030-01-01T00:00:00Z"}]), request(), NOW, set(), verify_ok) == {
        "identifier": "user=alice",
        "caveats": ["time < 2030-01-01T00:00:00Z"],
    }


def test_third_party_caveat_requires_discharge():
    third = token(caveats=[{"cid": "auth = service", "vid": "vid-1"}])
    with pytest.raises(ValueError):
        mg.verify_macaroon(third, request(), NOW, set(), verify_ok)


def test_third_party_caveat_with_discharge_is_accepted():
    third = token(caveats=[{"cid": "auth = service", "vid": "vid-1"}])
    discharges = {"vid-1": {"identifier": "service", "caveats": [], "signature": "d-sig"}}
    assert mg.verify_macaroon(third, request(discharges=discharges), NOW, set(), verify_ok) == {
        "identifier": "user=alice",
        "caveats": ["auth = service"],
    }


def test_replayed_nonce_is_rejected():
    with pytest.raises(ValueError):
        mg.verify_macaroon(token(), request(), NOW, {"n-1"}, verify_ok)


def test_empty_identifier_is_rejected():
    with pytest.raises(ValueError):
        mg.verify_macaroon(token(identifier=""), request(), NOW, set(), verify_ok)


def test_duplicate_caveats_are_stable():
    assert mg.verify_macaroon(token(caveats=[{"cid": "action = read"}, {"cid": "action = read"}]), request(), NOW, set(), verify_ok) == {
        "identifier": "user=alice",
        "caveats": ["action = read", "action = read"],
    }


def test_or_caveat_is_rejected():
    with pytest.raises(ValueError):
        mg.verify_macaroon(token(caveats=[{"cid": "action = read || write"}]), request(), NOW, set(), verify_ok)


def test_caveat_order_does_not_matter():
    reordered = token(caveats=[{"cid": "tenant = t1"}, {"cid": "action = read"}])
    assert mg.verify_macaroon(reordered, request(), NOW, set(), verify_ok) == {
        "identifier": "user=alice",
        "caveats": ["tenant = t1", "action = read"],
    }
