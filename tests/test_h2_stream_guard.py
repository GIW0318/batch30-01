import pytest

import h2_stream_guard as h2

BASE = [(":method", "GET"), (":path", "/"), (":scheme", "https"), (":authority", "app.example.com")]


def guard(**kwargs):
    return h2.StreamGuard(**kwargs)


def test_first_client_stream_is_accepted():
    g = guard()
    g.on_headers(1, BASE)
    assert g.state() == {"goaway": False, "active": 1, "closed": 0, "max_streams": 100}


def test_even_stream_id_is_rejected():
    g = guard()
    with pytest.raises(ValueError):
        g.on_headers(2, BASE)


def test_stream_id_must_increase():
    g = guard()
    g.on_headers(3, BASE)
    with pytest.raises(ValueError):
        g.on_headers(1, BASE)


def test_max_concurrent_streams():
    g = guard(max_streams=1)
    g.on_headers(1, BASE)
    with pytest.raises(ValueError):
        g.on_headers(3, BASE)


def test_closed_stream_frees_a_slot():
    g = guard(max_streams=1)
    g.on_headers(1, BASE)
    g.on_rst(1)
    g.on_headers(3, BASE)
    assert g.state() == {"goaway": False, "active": 1, "closed": 1, "max_streams": 1}


def test_rst_on_idle_stream_is_rejected():
    g = guard()
    with pytest.raises(ValueError):
        g.on_rst(1)


def test_rst_flood_is_rejected():
    g = guard()
    g.on_headers(1, BASE)
    g.on_rst(1)
    with pytest.raises(ValueError):
        g.on_rst(1)


def test_header_list_size_is_limited():
    g = guard(max_header_bytes=32)
    with pytest.raises(ValueError):
        g.on_headers(1, BASE + [("x-long", "a" * 64)])


def test_duplicate_pseudo_header_sets_goaway():
    g = guard()
    with pytest.raises(ValueError):
        g.on_headers(1, [(":method", "GET"), (":method", "POST"), (":path", "/"), (":scheme", "https"), (":authority", "x")])
    assert g.state() == {"goaway": True, "active": 0, "closed": 0, "max_streams": 100}


def test_pseudo_header_after_regular_header_is_rejected():
    g = guard()
    with pytest.raises(ValueError):
        g.on_headers(1, [(":method", "GET"), ("x-a", "1"), (":path", "/"), (":scheme", "https"), (":authority", "x")])


def test_connection_specific_header_is_rejected():
    g = guard()
    with pytest.raises(ValueError):
        g.on_headers(1, BASE + [("connection", "keep-alive")])


def test_uppercase_header_name_is_rejected():
    g = guard()
    with pytest.raises(ValueError):
        g.on_headers(1, BASE + [("X-Test", "1")])


def test_te_trailers_is_allowed():
    g = guard()
    g.on_headers(1, BASE + [("te", "trailers")])
    assert g.state() == {"goaway": False, "active": 1, "closed": 0, "max_streams": 100}


def test_te_gzip_is_rejected():
    g = guard()
    with pytest.raises(ValueError):
        g.on_headers(1, BASE + [("te", "gzip")])


def test_settings_max_concurrent_takes_effect():
    g = guard()
    g.on_headers(1, BASE)
    g.on_settings({"MAX_CONCURRENT_STREAMS": 1})
    with pytest.raises(ValueError):
        g.on_headers(3, BASE)
