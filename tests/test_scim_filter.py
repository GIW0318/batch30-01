import pytest

import scim_filter as sf


def test_compile_simple_eq():
    assert sf.compile_filter('userName eq "alice"', "t1") == {
        "tenant": "t1",
        "ast": {"op": "eq", "attr": "userName", "value": "alice"},
    }


def test_compile_or():
    assert sf.compile_filter('userName eq "a" or userName eq "b"', "t1") == {
        "tenant": "t1",
        "ast": {
            "op": "or",
            "left": {"op": "eq", "attr": "userName", "value": "a"},
            "right": {"op": "eq", "attr": "userName", "value": "b"},
        },
    }


def test_compile_and_with_parentheses():
    assert sf.compile_filter('(userName eq "a" or userName eq "b") and active eq true', "t1") == {
        "tenant": "t1",
        "ast": {
            "op": "and",
            "left": {
                "op": "or",
                "left": {"op": "eq", "attr": "userName", "value": "a"},
                "right": {"op": "eq", "attr": "userName", "value": "b"},
            },
            "right": {"op": "eq", "attr": "active", "value": True},
        },
    }


def test_compile_escaped_quote():
    assert sf.compile_filter('displayName eq "Li \"Bo\""', "t1") == {
        "tenant": "t1",
        "ast": {"op": "eq", "attr": "displayName", "value": 'Li "Bo"'},
    }


def test_compile_contains():
    assert sf.compile_filter('displayName co "li"', "t1") == {
        "tenant": "t1",
        "ast": {"op": "co", "attr": "displayName", "value": "li"},
    }


def test_compile_not():
    assert sf.compile_filter('not (active eq true)', "t1") == {
        "tenant": "t1",
        "ast": {"op": "not", "child": {"op": "eq", "attr": "active", "value": True}},
    }


def test_empty_filter_rejected():
    with pytest.raises(ValueError):
        sf.compile_filter("   ", "t1")


def test_unbalanced_quote_rejected():
    with pytest.raises(ValueError):
        sf.compile_filter('userName eq "alice', "t1")


def test_password_attribute_rejected():
    with pytest.raises(ValueError):
        sf.compile_filter('password eq "x"', "t1")


def test_tenant_attribute_cannot_be_filtered():
    with pytest.raises(ValueError):
        sf.compile_filter('tenantId eq "t2"', "t1")


def test_page_normalization():
    assert sf.normalize_page(5, 20) == {"startIndex": 5, "count": 20}


def test_page_start_zero_rejected():
    with pytest.raises(ValueError):
        sf.normalize_page(0, 20)


def test_page_count_too_large_rejected():
    with pytest.raises(ValueError):
        sf.normalize_page(1, 201)


def test_patch_updates_allowed_field_and_keeps_tenant():
    user = {"userName": "alice", "displayName": "Alice", "active": True, "tenantId": "t1"}
    assert sf.apply_patch(user, [{"op": "replace", "path": "displayName", "value": "Alice Li"}], "t1") == {
        "userName": "alice",
        "displayName": "Alice Li",
        "active": True,
        "tenantId": "t1",
    }


def test_patch_cannot_change_tenant():
    user = {"userName": "alice", "displayName": "Alice", "active": True, "tenantId": "t1"}
    with pytest.raises(ValueError):
        sf.apply_patch(user, [{"op": "replace", "path": "tenantId", "value": "t2"}], "t1")
