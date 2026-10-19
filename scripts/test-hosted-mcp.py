#!/usr/bin/env python3
import io
import unittest
from unittest import mock
from hosted_mcp import read_response


class Response(io.BytesIO):
    def __init__(self, raw, content_type="text/event-stream"):
        super().__init__(raw)
        self.content_type = content_type

    def getheader(self, name, default):
        return self.content_type if name == "Content-Type" else default


class ResponseTests(unittest.TestCase):
    def test_empty_priming_event_and_comments_precede_result(self):
        response = Response(b": keepalive\r\n\r\ndata: \r\n\r\nevent: message\r\ndata: {\"id\":1,\"result\":{}}\r\n\r\n")
        self.assertEqual(read_response(response, 1, 1000), {"id": 1, "result": {}})

    def test_multiline_data_and_notifications(self):
        response = Response(b'data: {"method":"notification"}\n\ndata:{"id":1,\ndata: "result":{}}\n\n')
        self.assertEqual(read_response(response, 1, 1000), {"id": 1, "result": {}})

    def test_entire_stream_has_a_byte_bound(self):
        self.assertIsNone(read_response(Response(b": padding\n\n" * 1000), 1, 100))
        self.assertIsNone(read_response(Response(b'data: {"id":1,"result":{}}\n\n'), 1, 10))

    def test_json_response_and_oversized_response(self):
        self.assertEqual(read_response(Response(b'{"id":1}', "application/json"), 1, 100), {"id": 1})
        self.assertIsNone(read_response(Response(b"x" * 101, "application/json"), 1, 100))
        self.assertIsNone(read_response(Response(b'{"id":2}', "application/json"), 1, 100))

    def test_slow_unterminated_line_and_json_body_hit_absolute_deadline(self):
        for content_type in ("text/event-stream", "application/json"):
            clock = [0.0]
            class SlowResponse(Response):
                def read1(self, size):
                    clock[0] += 0.6
                    return super().read1(1)
            with mock.patch("hosted_mcp.time.monotonic", side_effect=lambda: clock[0]):
                response = SlowResponse(b'data: {"id":1', content_type)
                self.assertIsNone(read_response(response, 1, 1000, deadline=2.0))
                self.assertLessEqual(clock[0], 2.5)

    def test_invalid_response_does_not_echo_sensitive_data(self):
        with self.assertRaises(SystemExit) as error:
            read_response(Response(b"data: SECRET-CANARY\n\n"), 1, 100)
        self.assertNotIn("SECRET-CANARY", str(error.exception))


if __name__ == "__main__":
    unittest.main()
