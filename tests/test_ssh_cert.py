import pytest

import ssh_cert as sc

NOW = 1_800_000_000
CA = {"ca-1": "public-key"}
CERTS = {"ca-1": "public-key"}


def cert(**overrides):
    data = {
        "cert_type": "user",
        "key_id": "alice@example.com",
        "principals": ["alice"],
        "valid_after": NOW - 60,
        "valid_before": NOW + 60,
        "critical_options": {},
        "extensions": {"permit-pty": ""},
        "ca_key_id": "ca-1",
        "serial": 7,
        "signature": "sig",
    }
    data.update(overrides)
    return data


def verify_ok(cert, ca_key):
    return True


def test_valid_user_certificate():
    assert sc.validate_certificate(cert(), CA, ["alice"], "user", "10.0.0.5", NOW, set(), verify_ok) == {
        "key_id": "alice@example.com",
        "principals": ["alice"],
        "critical_options": {},
        "extensions": {"permit-pty": ""},
    }


def test_certificate_type_mismatch_is_rejected():
    with pytest.raises(ValueError):
        sc.validate_certificate(cert(cert_type="host"), CA, ["alice"], "user", "10.0.0.5", NOW, set(), verify_ok)


def test_principal_not_allowed_is_rejected():
    with pytest.raises(ValueError):
        sc.validate_certificate(cert(principals=["bob"]), CA, ["alice"], "user", "10.0.0.5", NOW, set(), verify_ok)


def test_expired_certificate_is_rejected():
    with pytest.raises(ValueError):
        sc.validate_certificate(cert(valid_before=NOW - 1), CA, ["alice"], "user", "10.0.0.5", NOW, set(), verify_ok)


def test_not_yet_valid_certificate_is_rejected():
    with pytest.raises(ValueError):
        sc.validate_certificate(cert(valid_after=NOW + 1), CA, ["alice"], "user", "10.0.0.5", NOW, set(), verify_ok)


def test_unknown_ca_is_rejected():
    with pytest.raises(ValueError):
        sc.validate_certificate(cert(ca_key_id="ca-2"), CA, ["alice"], "user", "10.0.0.5", NOW, set(), verify_ok)


def test_unknown_critical_option_is_rejected():
    with pytest.raises(ValueError):
        sc.validate_certificate(cert(critical_options={"unknown": "1"}), CA, ["alice"], "user", "10.0.0.5", NOW, set(), verify_ok)


def test_force_command_is_returned():
    assert sc.validate_certificate(cert(critical_options={"force-command": "/bin/true"}), CA, ["alice"], "user", "10.0.0.5", NOW, set(), verify_ok) == {
        "key_id": "alice@example.com",
        "principals": ["alice"],
        "critical_options": {"force-command": "/bin/true"},
        "extensions": {"permit-pty": ""},
    }


def test_source_address_mismatch_is_rejected():
    with pytest.raises(ValueError):
        sc.validate_certificate(cert(critical_options={"source-address": "10.0.0.0/8"}), CA, ["alice"], "user", "192.168.1.1", NOW, set(), verify_ok)


def test_signature_failure_is_rejected():
    with pytest.raises(ValueError):
        sc.validate_certificate(cert(), CA, ["alice"], "user", "10.0.0.5", NOW, set(), lambda c, k: False)


def test_revoked_serial_is_rejected():
    with pytest.raises(ValueError):
        sc.validate_certificate(cert(), CA, ["alice"], "user", "10.0.0.5", NOW, {7}, verify_ok)


def test_host_wildcard_principal_is_allowed():
    assert sc.validate_certificate(cert(cert_type="host", principals=["*.example.com"]), CA, ["*.example.com"], "host", "10.0.0.5", NOW, set(), verify_ok) == {
        "key_id": "alice@example.com",
        "principals": ["*.example.com"],
        "critical_options": {},
        "extensions": {"permit-pty": ""},
    }


def test_empty_key_id_is_rejected():
    with pytest.raises(ValueError):
        sc.validate_certificate(cert(key_id=""), CA, ["alice"], "user", "10.0.0.5", NOW, set(), verify_ok)


def test_invalid_time_range_is_rejected():
    with pytest.raises(ValueError):
        sc.validate_certificate(cert(valid_after=NOW + 10, valid_before=NOW + 1), CA, ["alice"], "user", "10.0.0.5", NOW, set(), verify_ok)


def test_extensions_are_returned():
    assert sc.validate_certificate(cert(extensions={"permit-pty": "", "permit-agent-forwarding": ""}), CA, ["alice"], "user", "10.0.0.5", NOW, set(), verify_ok) == {
        "key_id": "alice@example.com",
        "principals": ["alice"],
        "critical_options": {},
        "extensions": {"permit-pty": "", "permit-agent-forwarding": ""},
    }
