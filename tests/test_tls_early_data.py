import threading

import pytest

import tls_early_data as ted

NOW = 1_800_000_000


def guard(**kwargs):
    return ted.EarlyDataGuard(**kwargs)


def test_issue_ticket_shape():
    ticket = guard().issue_ticket("sid-1", NOW)
    assert isinstance(ticket, dict)
    assert set(ticket) == {"key_id", "ticket_id", "session_id", "issued_at", "max_early_data"}


def test_valid_ticket_is_accepted():
    g = guard()
    ticket = g.issue_ticket("sid-1", NOW)
    assert g.accept_early_data(ticket, "sid-1", 100, NOW + 1) is True


def test_replayed_ticket_is_rejected():
    g = guard()
    ticket = g.issue_ticket("sid-1", NOW)
    g.accept_early_data(ticket, "sid-1", 100, NOW + 1)
    with pytest.raises(ValueError):
        g.accept_early_data(ticket, "sid-1", 100, NOW + 2)


def test_expired_ticket_is_rejected():
    g = guard(max_age=5)
    ticket = g.issue_ticket("sid-1", NOW)
    with pytest.raises(ValueError):
        g.accept_early_data(ticket, "sid-1", 100, NOW + 6)


def test_wrong_session_is_rejected():
    g = guard()
    ticket = g.issue_ticket("sid-1", NOW)
    with pytest.raises(ValueError):
        g.accept_early_data(ticket, "sid-2", 100, NOW + 1)


def test_unknown_key_id_is_rejected():
    g = guard()
    ticket = g.issue_ticket("sid-1", NOW)
    ticket["key_id"] = "unknown"
    with pytest.raises(ValueError):
        g.accept_early_data(ticket, "sid-1", 100, NOW + 1)


def test_size_over_limit_is_rejected():
    g = guard(max_early_data=10)
    ticket = g.issue_ticket("sid-1", NOW)
    with pytest.raises(ValueError):
        g.accept_early_data(ticket, "sid-1", 11, NOW + 1)


def test_negative_size_is_rejected():
    g = guard()
    ticket = g.issue_ticket("sid-1", NOW)
    with pytest.raises(ValueError):
        g.accept_early_data(ticket, "sid-1", -1, NOW + 1)


def test_malformed_ticket_is_rejected():
    g = guard()
    with pytest.raises(ValueError):
        g.accept_early_data({"ticket_id": "x"}, "sid-1", 1, NOW)


def test_zero_max_early_data_rejects():
    g = guard(max_early_data=0)
    ticket = g.issue_ticket("sid-1", NOW)
    with pytest.raises(ValueError):
        g.accept_early_data(ticket, "sid-1", 1, NOW + 1)


def test_future_ticket_is_rejected():
    g = guard()
    ticket = g.issue_ticket("sid-1", NOW + 10)
    with pytest.raises(ValueError):
        g.accept_early_data(ticket, "sid-1", 1, NOW)


def test_concurrent_accept_only_one_succeeds():
    g = guard()
    ticket = g.issue_ticket("sid-1", NOW)
    results = []

    def worker():
        try:
            results.append(g.accept_early_data(ticket, "sid-1", 1, NOW + 1) is True)
        except ValueError:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_state_counts():
    g = guard()
    ticket = g.issue_ticket("sid-1", NOW)
    g.accept_early_data(ticket, "sid-1", 1, NOW + 1)
    assert g.state() == {"issued": 1, "accepted": 1, "rejected": 0}


def test_ticket_from_other_guard_is_rejected():
    g1 = guard()
    g2 = guard()
    ticket = g1.issue_ticket("sid-1", NOW)
    with pytest.raises(ValueError):
        g2.accept_early_data(ticket, "sid-1", 1, NOW + 1)


def test_consumed_ticket_is_rejected():
    g = guard()
    ticket = g.issue_ticket("sid-1", NOW)
    g.accept_early_data(ticket, "sid-1", 1, NOW + 1)
    with pytest.raises(ValueError):
        g.accept_early_data(ticket, "sid-1", 1, NOW + 1)
