import pytest

import dnssec_verify as dv

NOW = 1_800_000_000
RRSET = {"name": "www.example.com", "type": "A", "class": "IN", "ttl": 300, "records": ["192.0.2.1"]}
DS = {"key_tag": 1234, "algorithm": 8, "digest_type": 2, "digest": "abc"}
ANCHOR = {"key_tag": 1234, "algorithm": 8, "public_key": "key"}


def sig(**overrides):
    data = {
        "key_tag": 1234,
        "signer": "example.com",
        "algorithm": 8,
        "inception": NOW - 10,
        "expiration": NOW + 10,
        "labels": 3,
        "original_ttl": 300,
        "signature": "sig",
        "wildcard": False,
    }
    data.update(overrides)
    return data


def verify_ok(rrset, signature, key):
    return True


def test_valid_rrset():
    assert dv.validate_rrset(RRSET, [sig()], DS, ANCHOR, "example.com", NOW, verify_ok) == {
        "name": "www.example.com",
        "type": "A",
        "records": ["192.0.2.1"],
    }


def test_missing_signature_is_rejected():
    with pytest.raises(ValueError):
        dv.validate_rrset(RRSET, [], DS, ANCHOR, "example.com", NOW, verify_ok)


def test_missing_ds_is_rejected():
    with pytest.raises(ValueError):
        dv.validate_rrset(RRSET, [sig()], None, ANCHOR, "example.com", NOW, verify_ok)


def test_ds_key_tag_mismatch_is_rejected():
    with pytest.raises(ValueError):
        dv.validate_rrset(RRSET, [sig()], dict(DS, key_tag=9), ANCHOR, "example.com", NOW, verify_ok)


def test_ds_algorithm_mismatch_is_rejected():
    with pytest.raises(ValueError):
        dv.validate_rrset(RRSET, [sig()], dict(DS, algorithm=13), ANCHOR, "example.com", NOW, verify_ok)


def test_rrsig_key_tag_mismatch_is_rejected():
    with pytest.raises(ValueError):
        dv.validate_rrset(RRSET, [sig(key_tag=9)], DS, ANCHOR, "example.com", NOW, verify_ok)


def test_rrsig_signer_mismatch_is_rejected():
    with pytest.raises(ValueError):
        dv.validate_rrset(RRSET, [sig(signer="evil.example.com")], DS, ANCHOR, "example.com", NOW, verify_ok)


def test_expired_signature_is_rejected():
    with pytest.raises(ValueError):
        dv.validate_rrset(RRSET, [sig(expiration=NOW - 1)], DS, ANCHOR, "example.com", NOW, verify_ok)


def test_not_yet_valid_signature_is_rejected():
    with pytest.raises(ValueError):
        dv.validate_rrset(RRSET, [sig(inception=NOW + 1)], DS, ANCHOR, "example.com", NOW, verify_ok)


def test_original_ttl_mismatch_is_rejected():
    with pytest.raises(ValueError):
        dv.validate_rrset(RRSET, [sig(original_ttl=600)], DS, ANCHOR, "example.com", NOW, verify_ok)


def test_wildcard_labels_are_checked():
    with pytest.raises(ValueError):
        dv.validate_rrset(RRSET, [sig(labels=2)], DS, ANCHOR, "example.com", NOW, verify_ok)


def test_wildcard_signature_is_accepted():
    wild = sig(labels=2, wildcard=True)
    assert dv.validate_rrset(RRSET, [wild], DS, ANCHOR, "example.com", NOW, verify_ok) == {
        "name": "www.example.com",
        "type": "A",
        "records": ["192.0.2.1"],
    }


def test_one_valid_signature_among_many_is_enough():
    bad = sig(expiration=NOW - 1)
    assert dv.validate_rrset(RRSET, [bad, sig()], DS, ANCHOR, "example.com", NOW, verify_ok) == {
        "name": "www.example.com",
        "type": "A",
        "records": ["192.0.2.1"],
    }


def test_all_signatures_failing_verify_is_rejected():
    with pytest.raises(ValueError):
        dv.validate_rrset(RRSET, [sig(), sig(key_tag=1234)], DS, ANCHOR, "example.com", NOW, lambda r, s, k: False)


def test_non_in_class_is_rejected():
    with pytest.raises(ValueError):
        dv.validate_rrset(dict(RRSET, **{"class": "CH"}), [sig()], DS, ANCHOR, "example.com", NOW, verify_ok)
