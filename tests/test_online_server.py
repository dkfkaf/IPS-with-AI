"""ZeroMQ 요청 변환, 반복 처리, 서버 자원 정리를 검증한다."""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

import zmq

import ml.online_server as online_server
from ml.online_server import (
    INVALID_FIELD,
    INVALID_JSON,
    RequestError,
    _response_for_payload,
    _serve_requests,
    run,
)


class LoopSocket:
    def __init__(self, *, receive_again=False, send_error=False):
        self.receive_again = receive_again
        self.send_error = send_error
        self.received = 0
        self.responses = []

    def recv(self):
        self.received += 1
        if self.receive_again and self.received == 1:
            raise zmq.Again()
        return b"{}"

    def send_json(self, response):
        if self.send_error:
            raise zmq.ZMQError(zmq.EFSM)
        self.responses.append(response)
        online_server._running = False


class ServerSocket:
    def __init__(self):
        self.options = []
        self.endpoint = None
        self.closed_with = None

    def setsockopt(self, option, value):
        self.options.append((option, value))

    def bind(self, endpoint):
        self.endpoint = endpoint

    def close(self, *, linger):
        self.closed_with = linger


class ServerContext:
    def __init__(self, socket):
        self.created_socket_type = None
        self.server_socket = socket
        self.terminated = False

    def socket(self, socket_type):
        self.created_socket_type = socket_type
        return self.server_socket

    def term(self):
        self.terminated = True


class OnlineServerTest(unittest.TestCase):
    def setUp(self):
        self.previous_running = online_server._running
        online_server._running = True
        self.artifacts = SimpleNamespace(model_version="ae-test-v1")

    def tearDown(self):
        online_server._running = self.previous_running

    def test_invalid_json_returns_protocol_error(self):
        response = _response_for_payload(self.artifacts, b"\xff")

        self.assertEqual(
            response,
            {
                "schema_version": 1,
                "flow_id": "",
                "model_version": "ae-test-v1",
                "ok": False,
                "error_code": INVALID_JSON,
            },
        )

    def test_request_error_preserves_flow_id_and_error_code(self):
        payload = json.dumps({"flow_id": "flow-7"}).encode()
        error = RequestError(INVALID_FIELD, "src_ip 오류")

        with patch("ml.online_server.infer_request", side_effect=error):
            response = _response_for_payload(self.artifacts, payload)

        self.assertEqual(response["flow_id"], "flow-7")
        self.assertEqual(response["error_code"], INVALID_FIELD)
        self.assertFalse(response["ok"])

    def test_unexpected_inference_error_stops_response_processing(self):
        with (
            patch("ml.online_server.infer_request", side_effect=RuntimeError("boom")),
            redirect_stderr(io.StringIO()) as error_output,
        ):
            response = _response_for_payload(self.artifacts, b"{}")

        self.assertIsNone(response)
        self.assertEqual(error_output.getvalue(), "AI 추론 실패: boom\n")

    def test_serve_requests_retries_timeout_and_sends_response(self):
        socket = LoopSocket(receive_again=True)
        expected = {"ok": True}

        with patch("ml.online_server._response_for_payload", return_value=expected):
            result = _serve_requests(socket, self.artifacts)

        self.assertEqual(result, 0)
        self.assertEqual(socket.received, 2)
        self.assertEqual(socket.responses, [expected])

    def test_serve_requests_returns_failure_when_response_cannot_be_sent(self):
        socket = LoopSocket(send_error=True)

        with (
            patch("ml.online_server._response_for_payload", return_value={"ok": True}),
            redirect_stderr(io.StringIO()) as error_output,
        ):
            result = _serve_requests(socket, self.artifacts)

        self.assertEqual(result, 1)
        self.assertTrue(error_output.getvalue().startswith("AI 응답 전송 실패: "))

    def test_run_configures_and_releases_zmq_resources(self):
        socket = ServerSocket()
        context = ServerContext(socket)

        with (
            patch("ml.online_server.os.umask") as umask_mock,
            patch("ml.online_server.load_artifacts", return_value=self.artifacts) as load_mock,
            patch("ml.online_server.zmq.Context", return_value=context),
            patch("ml.online_server.signal.signal") as signal_mock,
            patch("ml.online_server._serve_requests", return_value=0),
            redirect_stdout(io.StringIO()) as output,
        ):
            result = run("ipc:///run/ips/ai.sock", "/secure/artifacts")

        self.assertEqual(result, 0)
        umask_mock.assert_called_once_with(0o077)
        load_mock.assert_called_once_with(
            "/secure/artifacts", require_secure_permissions=True
        )
        self.assertEqual(context.created_socket_type, zmq.REP)
        self.assertEqual(
            socket.options,
            [(zmq.LINGER, 0), (zmq.RCVTIMEO, 250)],
        )
        self.assertEqual(socket.endpoint, "ipc:///run/ips/ai.sock")
        self.assertEqual(socket.closed_with, 0)
        self.assertTrue(context.terminated)
        self.assertEqual(signal_mock.call_count, 2)
        self.assertEqual(json.loads(output.getvalue())["event"], "AI_READY")


if __name__ == "__main__":
    unittest.main()
