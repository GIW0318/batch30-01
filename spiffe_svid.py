import re

_SCHEME = "spiffe://"
_TRUST_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$"
)


def _parse_spiffe_id(spiffe_id):
    if not isinstance(spiffe_id, str) or not spiffe_id.startswith(_SCHEME):
        raise ValueError("malformed SPIFFE ID: missing the spiffe:// scheme")

    remainder = spiffe_id[len(_SCHEME):]
    if "?" in remainder or "#" in remainder:
        raise ValueError("malformed SPIFFE ID: query and fragment are not allowed")

    host, separator, tail = remainder.partition("/")
    path = "/" + tail if separator else ""
    if not host or "@" in host or not _TRUST_DOMAIN_RE.match(host):
        raise ValueError("malformed SPIFFE ID: invalid trust domain")

    for segment in path.split("/")[1:]:
        if segment in ("", ".", ".."):
            raise ValueError("malformed SPIFFE ID: invalid path segment")

    return host, path


def _path_matches(path, allowed_paths):
    segments = path.split("/")
    return any(segments == allowed.split("/") for allowed in allowed_paths)


def validate_svid(svid, trust_domain, bundle, allowed_paths, now, seen_serial, verify):
    host, path = _parse_spiffe_id(svid.get("spiffe_id", ""))

    if host != trust_domain:
        raise ValueError("SVID trust domain does not match the expected trust domain")
    if not _path_matches(path, allowed_paths):
        raise ValueError("SVID path is not included in the allow list")

    svid_type = svid.get("type")
    audience = svid.get("audience") or []
    if svid_type == "x509":
        if audience:
            raise ValueError("X509-SVID must not carry a JWT audience")
    elif svid_type == "jwt":
        expected_audience = path.split("/")[-1]
        if not audience or expected_audience not in audience:
            raise ValueError("JWT-SVID audience is missing or does not match")
    else:
        raise ValueError("unknown SVID type: %r" % (svid_type,))

    not_before = svid.get("not_before")
    not_after = svid.get("not_after")
    if not_before is None or not_after is None or now < not_before or now > not_after:
        raise ValueError("SVID is outside of its validity window")

    bundle_id = svid.get("bundle_id")
    if bundle_id not in bundle:
        raise ValueError("SVID references an unknown bundle id")

    serial = svid.get("serial")
    if serial in seen_serial:
        raise ValueError("SVID serial has already been seen (replay detected)")

    if not verify(svid.get("signature"), bundle[bundle_id]):
        raise ValueError("SVID signature verification failed")

    seen_serial.add(serial)
    return {
        "spiffe_id": svid["spiffe_id"],
        "serial": serial,
        "type": svid_type,
    }
