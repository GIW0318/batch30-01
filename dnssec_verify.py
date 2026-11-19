def _require_field(mapping, key, expected_type, label):
    if not isinstance(mapping, dict) or key not in mapping or not isinstance(
        mapping[key], expected_type
    ):
        raise ValueError(f"{label} has a missing or invalid field: {key}")
    return mapping[key]


def _label_count(name):
    if not isinstance(name, str):
        raise ValueError("RRset owner name must be a string")
    trimmed = name[:-1] if name.endswith(".") else name
    return 0 if trimmed == "" else len(trimmed.split("."))


def _check_ds_against_anchor(ds, trust_anchor):
    if not isinstance(ds, dict):
        raise ValueError("DS record is required and must be a mapping")
    if not isinstance(trust_anchor, dict):
        raise ValueError("trust anchor is required and must be a mapping")
    ds_key_tag = _require_field(ds, "key_tag", int, "DS")
    ds_algorithm = _require_field(ds, "algorithm", int, "DS")
    anchor_key_tag = _require_field(trust_anchor, "key_tag", int, "trust anchor")
    anchor_algorithm = _require_field(trust_anchor, "algorithm", int, "trust anchor")
    if ds_key_tag != anchor_key_tag:
        raise ValueError("DS key tag does not match the trust anchor")
    if ds_algorithm != anchor_algorithm:
        raise ValueError("DS algorithm does not match the trust anchor")


def _check_signature(signature, rrset, ds, trust_anchor, zone, now, verify):
    if not isinstance(signature, dict):
        raise ValueError("RRSIG record must be a mapping")
    key_tag = _require_field(signature, "key_tag", int, "RRSIG")
    algorithm = _require_field(signature, "algorithm", int, "RRSIG")
    signer = _require_field(signature, "signer", str, "RRSIG")
    inception = _require_field(signature, "inception", int, "RRSIG")
    expiration = _require_field(signature, "expiration", int, "RRSIG")
    labels = _require_field(signature, "labels", int, "RRSIG")
    original_ttl = _require_field(signature, "original_ttl", int, "RRSIG")
    wildcard = _require_field(signature, "wildcard", bool, "RRSIG")
    _require_field(signature, "signature", str, "RRSIG")

    if key_tag != ds["key_tag"]:
        raise ValueError("RRSIG key tag does not match the DS key tag")
    if algorithm != ds["algorithm"]:
        raise ValueError("RRSIG algorithm does not match the DS algorithm")
    if signer != zone:
        raise ValueError("RRSIG signer name does not match the zone")
    if now < inception or now > expiration:
        raise ValueError("RRSIG is outside of its validity window")
    if original_ttl != rrset["ttl"]:
        raise ValueError("RRSIG original TTL does not match the RRset TTL")

    name_labels = _label_count(rrset["name"])
    if wildcard:
        if labels >= name_labels:
            raise ValueError("wildcard RRSIG labels do not prove a wildcard expansion")
    elif labels != name_labels:
        raise ValueError("RRSIG labels do not match the RRset owner name")

    if not verify(rrset, signature, trust_anchor.get("public_key")):
        raise ValueError("cryptographic verification of the RRSIG failed")


def validate_rrset(rrset, signatures, ds, trust_anchor, zone, now, verify):
    if not isinstance(rrset, dict):
        raise ValueError("RRset must be a mapping")
    if rrset.get("class") != "IN":
        raise ValueError("only RRsets with class IN are accepted")
    if not isinstance(signatures, list) or not signatures:
        raise ValueError("RRset must be covered by at least one RRSIG")
    if ds is None:
        raise ValueError("DS record is required")
    _check_ds_against_anchor(ds, trust_anchor)

    _require_field(rrset, "name", str, "RRset")
    _require_field(rrset, "type", str, "RRset")
    _require_field(rrset, "ttl", int, "RRset")
    records = _require_field(rrset, "records", list, "RRset")

    last_error = None
    for signature in signatures:
        try:
            _check_signature(signature, rrset, ds, trust_anchor, zone, now, verify)
        except ValueError as exc:
            last_error = exc
            continue
        return {"name": rrset["name"], "type": rrset["type"], "records": records}
    raise ValueError("no valid RRSIG covers the RRset") from last_error
