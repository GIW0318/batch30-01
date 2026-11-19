def validate_certificate(cert, ca_keys, allowed_principals, expected_type, client_ip, now, revoked_serials, verify):
    return {}
import fnmatch
import ipaddress


KNOWN_CRITICAL_OPTIONS = frozenset(("force-command", "source-address"))


def validate_certificate(
    cert,
    ca_keys,
    allowed_principals,
    expected_type,
    client_ip,
    now,
    revoked_serials,
    verify,
):
    key_id = cert.get("key_id")
    if not key_id or not isinstance(key_id, str):
        raise ValueError("certificate key_id must be a non-empty string")

    cert_type = cert.get("cert_type")
    if cert_type != expected_type:
        raise ValueError(
            "certificate type %r does not match expected type %r"
            % (cert_type, expected_type)
        )

    ca_key_id = cert.get("ca_key_id")
    if ca_key_id not in ca_keys:
        raise ValueError("certificate signed by unknown CA %r" % (ca_key_id,))
    ca_key = ca_keys[ca_key_id]

    if not verify(cert, ca_key):
        raise ValueError("certificate signature verification failed")

    serial = cert.get("serial")
    if serial in revoked_serials:
        raise ValueError("certificate serial %s is revoked" % (serial,))

    valid_after = cert.get("valid_after")
    valid_before = cert.get("valid_before")
    if valid_before < valid_after:
        raise ValueError("certificate validity window is inverted")
    if now < valid_after or now > valid_before:
        raise ValueError("certificate is outside its validity window")

    critical_options = cert.get("critical_options", {}) or {}
    unknown = set(critical_options) - KNOWN_CRITICAL_OPTIONS
    if unknown:
        raise ValueError("certificate contains unknown critical options: %s" % sorted(unknown))

    if "source-address" in critical_options:
        _check_source_address(critical_options["source-address"], client_ip)

    principals = cert.get("principals", []) or []
    if not _principal_allowed(cert_type, principals, allowed_principals):
        raise ValueError("certificate principals %s are not in the allowed list" % principals)

    return {
        "key_id": key_id,
        "principals": principals,
        "critical_options": critical_options,
        "extensions": cert.get("extensions", {}) or {},
    }


def _check_source_address(source_address, client_ip):
    if not client_ip:
        raise ValueError("certificate restricts source addresses but no client IP is present")
    try:
        client = ipaddress.ip_address(client_ip)
    except ValueError:
        raise ValueError("invalid client IP address %r" % (client_ip,))

    permitted = False
    for entry in str(source_address).split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise ValueError("invalid source-address entry %r" % (entry,))
        if client in network:
            permitted = True
            break
    if not permitted:
        raise ValueError("client IP %s is not permitted by source-address %r" % (client_ip, source_address))


def _principal_allowed(cert_type, principals, allowed_principals):
    allowed = list(allowed_principals or [])
    for principal in principals:
        for allowed_principal in allowed:
            if principal == allowed_principal:
                return True
            if cert_type == "host" and (
                fnmatch.fnmatchcase(principal, allowed_principal)
                or fnmatch.fnmatchcase(allowed_principal, principal)
            ):
                return True
    return False
