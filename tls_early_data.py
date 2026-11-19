class EarlyDataGuard:
    def __init__(self, max_early_data=1024, max_age=10):
        pass

    def issue_ticket(self, session_id, now):
        return None

    def accept_early_data(self, ticket, session_id, size, now):
        return None

    def state(self):
        return {}
