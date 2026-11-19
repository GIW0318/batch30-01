class StreamGuard:
    def __init__(self, max_streams=100, max_header_bytes=8192):
        pass

    def on_headers(self, stream_id, headers, end_stream=False):
        return None

    def on_rst(self, stream_id):
        return None

    def on_settings(self, settings):
        return None

    def state(self):
        return {}
