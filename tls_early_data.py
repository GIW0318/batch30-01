import math
import threading
import uuid


_TICKET_FIELDS = frozenset(
    {"key_id", "ticket_id", "session_id", "issued_at", "max_early_data"}
)


def _is_number(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value)


def _is_size(value):
    return isinstance(value, int) and not isinstance(value, bool)


class EarlyDataGuard:
    def __init__(self, max_early_data=1024, max_age=10):
        if not _is_size(max_early_data) or max_early_data < 0:
            raise ValueError("max_early_data must be a non-negative integer")
        if not _is_number(max_age) or max_age < 0:
            raise ValueError("max_age must be a non-negative number")

        self.max_early_data = max_early_data
        self.max_age = max_age
        self._key_id = uuid.uuid4().hex
        self._tickets = {}
        self._consumed = set()
        self._issued = 0
        self._accepted = 0
        self._rejected = 0
        self._lock = threading.Lock()

    def issue_ticket(self, session_id, now):
        if not _is_number(now):
            raise ValueError("now must be a finite number")

        with self._lock:
            ticket_id = uuid.uuid4().hex
            while ticket_id in self._tickets:
                ticket_id = uuid.uuid4().hex

            ticket = {
                "key_id": self._key_id,
                "ticket_id": ticket_id,
                "session_id": session_id,
                "issued_at": now,
                "max_early_data": self.max_early_data,
            }
            self._tickets[ticket_id] = {
                "key_id": self._key_id,
                "session_id": session_id,
                "issued_at": now,
                "max_early_data": self.max_early_data,
            }
            self._issued += 1
            return dict(ticket)

    def accept_early_data(self, ticket, session_id, size, now):
        with self._lock:
            try:
                self._consume_ticket(ticket, session_id, size, now)
            except ValueError:
                self._rejected += 1
                raise

            self._accepted += 1
            return True

    def _consume_ticket(self, ticket, session_id, size, now):
        if not isinstance(ticket, dict) or set(ticket) != _TICKET_FIELDS:
            raise ValueError("malformed ticket")

        key_id = ticket["key_id"]
        ticket_id = ticket["ticket_id"]
        ticket_session_id = ticket["session_id"]
        issued_at = ticket["issued_at"]
        max_early_data = ticket["max_early_data"]

        if not isinstance(key_id, str) or not key_id:
            raise ValueError("malformed ticket key_id")
        if not isinstance(ticket_id, str) or not ticket_id:
            raise ValueError("malformed ticket ticket_id")
        if not _is_number(issued_at):
            raise ValueError("malformed ticket issued_at")
        if not _is_size(max_early_data) or max_early_data < 0:
            raise ValueError("malformed ticket max_early_data")
        if not _is_size(size) or size < 0:
            raise ValueError("invalid early data size")
        if not _is_number(now):
            raise ValueError("now must be a finite number")

        if key_id != self._key_id:
            raise ValueError("unknown ticket key_id")

        record = self._tickets.get(ticket_id)
        if record is None:
            raise ValueError("unknown ticket")

        if (
            key_id != record["key_id"]
            or ticket_session_id != record["session_id"]
            or session_id != record["session_id"]
            or issued_at != record["issued_at"]
            or max_early_data != record["max_early_data"]
        ):
            raise ValueError("ticket does not match its session")

        if ticket_id in self._consumed:
            raise ValueError("ticket has already been consumed")

        age = now - issued_at
        if age < 0:
            raise ValueError("ticket is not valid yet")
        if age > self.max_age:
            raise ValueError("ticket has expired")

        if size > record["max_early_data"] or size > self.max_early_data:
            raise ValueError("early data exceeds ticket limit")

        self._consumed.add(ticket_id)

    def state(self):
        with self._lock:
            return {
                "issued": self._issued,
                "accepted": self._accepted,
                "rejected": self._rejected,
            }
