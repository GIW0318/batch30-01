HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
})

REQUEST_PSEUDO_HEADERS = frozenset({":method", ":scheme", ":authority", ":path"})


class StreamGuard:
    def __init__(self, max_streams=100, max_header_bytes=8192):
        self._max_streams = max_streams
        self._max_header_bytes = max_header_bytes
        self._highest_stream_id = 0
        self._open_streams = set()
        self._closed_count = 0
        self._goaway = False

    def _protocol_error(self, message):
        self._goaway = True
        raise ValueError(message)

    def on_headers(self, stream_id, headers, end_stream=False, compressed_size=None):
        if self._goaway:
            raise ValueError("connection is in GOAWAY, no new streams")
        if stream_id % 2 == 0:
            self._protocol_error("client-initiated stream id must be odd")
        if stream_id <= self._highest_stream_id:
            self._protocol_error("stream id must strictly increase")
        if len(self._open_streams) >= self._max_streams:
            raise ValueError("max concurrent streams exceeded")

        self._validate_headers(headers)

        if compressed_size is not None and compressed_size > self._max_header_bytes:
            self._protocol_error("compressed header block too large")
        decoded_size = sum(len(name) + len(value) + 32 for name, value in headers)
        if decoded_size > self._max_header_bytes:
            self._protocol_error("decoded header list too large")

        self._highest_stream_id = stream_id
        self._open_streams.add(stream_id)
        return None

    def _validate_headers(self, headers):
        seen_pseudo = set()
        regular_seen = False
        for name, value in headers:
            if name != name.lower():
                self._protocol_error("header name must be lowercase: %r" % name)
            if name.startswith(":"):
                if regular_seen:
                    self._protocol_error("pseudo-header after regular header: %r" % name)
                if name not in REQUEST_PSEUDO_HEADERS:
                    self._protocol_error("unknown pseudo-header: %r" % name)
                if name in seen_pseudo:
                    self._protocol_error("duplicate pseudo-header: %r" % name)
                seen_pseudo.add(name)
                continue
            regular_seen = True
            if name in HOP_BY_HOP_HEADERS:
                self._protocol_error("connection-specific header not allowed: %r" % name)
            if name == "te" and value.strip().lower() != "trailers":
                self._protocol_error("te header only allows 'trailers'")

    def on_rst(self, stream_id):
        if stream_id in self._open_streams:
            self._open_streams.discard(stream_id)
            self._closed_count += 1
            return None
        if stream_id > self._highest_stream_id:
            self._protocol_error("RST_STREAM on idle stream %d" % stream_id)
        self._protocol_error("RST_STREAM on non-open stream %d" % stream_id)

    def on_settings(self, settings):
        if "MAX_CONCURRENT_STREAMS" in settings:
            value = settings["MAX_CONCURRENT_STREAMS"]
            if not isinstance(value, int) or value < 0:
                self._protocol_error("invalid MAX_CONCURRENT_STREAMS")
            self._max_streams = value
        return None

    def state(self):
        return {
            "goaway": self._goaway,
            "active": len(self._open_streams),
            "closed": self._closed_count,
            "max_streams": self._max_streams,
        }
