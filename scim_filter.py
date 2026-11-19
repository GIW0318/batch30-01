import copy
import re


_MAX_PAGE_SIZE = 200

_COMPARISON_OPERATORS = frozenset(
    {"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le", "pr"}
)

_BASE_ATTRIBUTES = {
    "id": "id",
    "externalid": "externalId",
    "username": "userName",
    "name": "name",
    "displayname": "displayName",
    "nickname": "nickName",
    "profileurl": "profileUrl",
    "title": "title",
    "usertype": "userType",
    "preferredlanguage": "preferredLanguage",
    "locale": "locale",
    "timezone": "timezone",
    "active": "active",
    "emails": "emails",
    "phonenumbers": "phoneNumbers",
    "ims": "ims",
    "photos": "photos",
    "addresses": "addresses",
    "groups": "groups",
    "x509certificates": "x509Certificates",
    "meta": "meta",
}

_SUB_ATTRIBUTES = {
    "name": {
        "formatted": "formatted",
        "familyname": "familyName",
        "givenname": "givenName",
        "middlename": "middleName",
        "honorificprefix": "honorificPrefix",
        "honorificsuffix": "honorificSuffix",
    },
    "emails": {
        "value": "value",
        "type": "type",
        "primary": "primary",
        "display": "display",
    },
    "phonenumbers": {
        "value": "value",
        "type": "type",
        "primary": "primary",
        "display": "display",
    },
    "ims": {
        "value": "value",
        "type": "type",
        "primary": "primary",
        "display": "display",
    },
    "photos": {
        "value": "value",
        "type": "type",
        "primary": "primary",
        "display": "display",
    },
    "addresses": {
        "type": "type",
        "formatted": "formatted",
        "streetaddress": "streetAddress",
        "locality": "locality",
        "region": "region",
        "postalcode": "postalCode",
        "country": "country",
        "primary": "primary",
    },
    "groups": {
        "value": "value",
        "display": "display",
        "type": "type",
        "$ref": "$ref",
        "members": "members",
    },
    "x509certificates": {
        "value": "value",
    },
    "meta": {
        "resourcetype": "resourceType",
        "created": "created",
        "lastmodified": "lastModified",
        "location": "location",
        "version": "version",
    },
}

_FILTER_ATTRIBUTES = frozenset(_BASE_ATTRIBUTES.values())
_PATCH_ATTRIBUTES = _FILTER_ATTRIBUTES - {"id", "groups", "meta"}

_ATTRIBUTE_PART_RE = re.compile(r"^\$?[A-Za-z][A-Za-z0-9]*$")
_NUMBER_RE = re.compile(
    r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$"
)

_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


def _canonical_attribute(raw, allowed):
    if not isinstance(raw, str) or not raw:
        raise ValueError("invalid attribute path")

    parts = raw.split(".")
    if len(parts) > 2 or any(
        not _ATTRIBUTE_PART_RE.fullmatch(part) for part in parts
    ):
        raise ValueError("invalid attribute path")

    base = _BASE_ATTRIBUTES.get(parts[0].casefold())
    if base is None or base not in allowed:
        raise ValueError("attribute is not allowed")
    if len(parts) == 1:
        return base

    sub_attributes = _SUB_ATTRIBUTES.get(base, {})
    sub_attribute = sub_attributes.get(parts[1].casefold())
    if sub_attribute is None:
        raise ValueError("attribute is not allowed")
    return "{}.{}".format(base, sub_attribute)


def _string_closes_at(text, index):
    length = len(text)
    while index < length and text[index].isspace():
        index += 1
    if index >= length or text[index] in ")]":
        return True

    start = index
    while index < length and (
        text[index].isalnum() or text[index] in "_-"
    ):
        index += 1
    return text[start:index].casefold() in {"and", "or"}


def _read_string(text, start):
    chars = []
    index = start + 1
    length = len(text)

    while index < length:
        char = text[index]
        if char == "\\":
            if index + 1 >= length:
                raise ValueError("unterminated escape")
            escaped = text[index + 1]
            if escaped == "u":
                digits = text[index + 2:index + 6]
                if len(digits) != 4 or not all(
                    digit in "0123456789abcdefABCDEF" for digit in digits
                ):
                    raise ValueError("invalid unicode escape")
                chars.append(chr(int(digits, 16)))
                index += 6
                continue
            if escaped not in _ESCAPES:
                raise ValueError("invalid escape")
            chars.append(_ESCAPES[escaped])
            index += 2
            continue

        if char == '"' and _string_closes_at(text, index + 1):
            return "".join(chars), index + 1

        chars.append(char)
        index += 1

    raise ValueError("unbalanced quote")


def _tokenize(text):
    tokens = []
    index = 0
    length = len(text)

    while index < length:
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == "(":
            tokens.append(("LPAREN", char))
            index += 1
            continue
        if char == ")":
            tokens.append(("RPAREN", char))
            index += 1
            continue
        if char == '"':
            value, index = _read_string(text, index)
            tokens.append(("STRING", value))
            continue
        if char in "[]":
            raise ValueError("unsupported filter syntax")

        start = index
        while (
            index < length
            and not text[index].isspace()
            and text[index] not in '()[]"'
        ):
            index += 1
        if start == index:
            raise ValueError("invalid token")
        tokens.append(("WORD", text[start:index]))

    tokens.append(("END", None))
    return tokens


class _FilterParser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.index = 0

    def _peek(self):
        return self.tokens[self.index]

    def _peek_word(self):
        kind, value = self._peek()
        return value.casefold() if kind == "WORD" else None

    def _advance(self):
        token = self.tokens[self.index]
        self.index += 1
        return token

    def _expect(self, kind):
        token = self._peek()
        if token[0] != kind:
            raise ValueError("invalid filter syntax")
        return self._advance()

    def parse(self):
        if self._peek()[0] == "END":
            raise ValueError("empty filter")
        node = self._parse_or()
        if self._peek()[0] != "END":
            raise ValueError("unexpected trailing input")
        return node

    def _parse_or(self):
        node = self._parse_and()
        while self._peek_word() == "or":
            self._advance()
            node = {
                "op": "or",
                "left": node,
                "right": self._parse_and(),
            }
        return node

    def _parse_and(self):
        node = self._parse_not()
        while self._peek_word() == "and":
            self._advance()
            node = {
                "op": "and",
                "left": node,
                "right": self._parse_not(),
            }
        return node

    def _parse_not(self):
        if self._peek_word() != "not":
            return self._parse_primary()

        self._advance()
        self._expect("LPAREN")
        child = self._parse_or()
        self._expect("RPAREN")
        return {"op": "not", "child": child}

    def _parse_primary(self):
        if self._peek()[0] == "LPAREN":
            self._advance()
            node = self._parse_or()
            self._expect("RPAREN")
            return node
        return self._parse_attribute_expression()

    def _parse_attribute_expression(self):
        _, raw_attribute = self._expect("WORD")
        attribute = _canonical_attribute(raw_attribute, _FILTER_ATTRIBUTES)

        _, raw_operator = self._expect("WORD")
        operator = raw_operator.casefold()
        if operator not in _COMPARISON_OPERATORS:
            raise ValueError("operator is not allowed")
        if operator == "pr":
            return {"op": operator, "attr": attribute}

        kind, raw_value = self._advance()
        if kind == "STRING":
            value = raw_value
        elif kind == "WORD":
            lowered = raw_value.casefold()
            if lowered == "true":
                value = True
            elif lowered == "false":
                value = False
            elif lowered == "null":
                value = None
            elif _NUMBER_RE.fullmatch(raw_value):
                if any(char in raw_value for char in ".eE"):
                    value = float(raw_value)
                else:
                    value = int(raw_value)
            else:
                raise ValueError("invalid comparison value")
        else:
            raise ValueError("missing comparison value")

        return {"op": operator, "attr": attribute, "value": value}


def _validate_tenant(tenant):
    if not isinstance(tenant, str) or not tenant.strip():
        raise ValueError("tenant is required")


def compile_filter(text, tenant):
    _validate_tenant(tenant)
    if not isinstance(text, str) or not text.strip():
        raise ValueError("filter is required")

    parser = _FilterParser(_tokenize(text))
    try:
        ast = parser.parse()
    except RecursionError as exc:
        raise ValueError("filter is nested too deeply") from exc
    return {"tenant": tenant, "ast": ast}


def _positive_integer(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("{} must be a positive integer".format(name))
    return value


def normalize_page(start_index, count):
    start_index = _positive_integer(start_index, "startIndex")
    count = _positive_integer(count, "count")
    if count > _MAX_PAGE_SIZE:
        raise ValueError("count exceeds the maximum page size")
    return {"startIndex": start_index, "count": count}


def _normalize_user_keys(user):
    for key in list(user):
        if not isinstance(key, str):
            continue
        canonical = _BASE_ATTRIBUTES.get(key.casefold())
        if canonical is None or canonical == key:
            continue
        if canonical in user and user[canonical] != user[key]:
            raise ValueError("conflicting attribute names")
        if canonical not in user:
            user[canonical] = user[key]
        del user[key]


def _enforce_tenant(user, tenant):
    tenant_keys = [
        key
        for key in user
        if isinstance(key, str) and key.casefold() == "tenantid"
    ]
    if tenant_keys:
        if any(user[key] != tenant for key in tenant_keys):
            raise ValueError("user belongs to another tenant")
        for key in tenant_keys:
            if key != "tenantId":
                del user[key]
    user["tenantId"] = tenant


def _set_path(target, parts, value):
    current = target
    for part in parts[:-1]:
        child = current.get(part)
        if child is None:
            child = {}
            current[part] = child
        if not isinstance(child, dict):
            raise ValueError("path does not identify an object")
        current = child
    current[parts[-1]] = value


def _remove_path(target, parts):
    current = target
    for part in parts[:-1]:
        child = current.get(part)
        if child is None:
            return
        if not isinstance(child, dict):
            raise ValueError("path does not identify an object")
        current = child
    current.pop(parts[-1], None)


def _reject_foreign_group_members(user, tenant):
    groups = user.get("groups")
    if not isinstance(groups, list):
        return
    for group in groups:
        if not isinstance(group, dict):
            continue
        members = group.get("members")
        if not isinstance(members, list):
            continue
        for member in members:
            if (
                isinstance(member, dict)
                and "tenantId" in member
                and member["tenantId"] != tenant
            ):
                raise ValueError("group contains a member from another tenant")


def apply_patch(user, operations, tenant):
    _validate_tenant(tenant)
    if not isinstance(user, dict):
        raise ValueError("user must be an object")
    if not isinstance(operations, (list, tuple)):
        raise ValueError("operations must be a list")

    patched = copy.deepcopy(user)
    _enforce_tenant(patched, tenant)
    _normalize_user_keys(patched)

    for operation in operations:
        if not isinstance(operation, dict):
            raise ValueError("operation must be an object")

        raw_op = operation.get("op")
        if not isinstance(raw_op, str):
            raise ValueError("operation name is required")
        op = raw_op.casefold()
        if op not in {"add", "replace", "remove"}:
            raise ValueError("operation is not allowed")

        path = _canonical_attribute(operation.get("path"), _PATCH_ATTRIBUTES)
        parts = path.split(".")

        if op == "remove":
            _remove_path(patched, parts)
            continue

        if "value" not in operation:
            raise ValueError("operation value is required")
        _set_path(patched, parts, copy.deepcopy(operation["value"]))

    _enforce_tenant(patched, tenant)
    _reject_foreign_group_members(patched, tenant)
    return patched


def normalize_sort(sort_by, sort_order="ascending"):
    if sort_by is None:
        raise ValueError("sort attribute is required")
    attribute = _canonical_attribute(
        sort_by, _FILTER_ATTRIBUTES - {"id", "meta"}
    )
    if not isinstance(sort_order, str):
        raise ValueError("sort order is invalid")
    order = sort_order.casefold()
    if order not in {"ascending", "descending"}:
        raise ValueError("sort order is invalid")
    return {"sortBy": attribute, "sortOrder": order}


validate_sort = normalize_sort
