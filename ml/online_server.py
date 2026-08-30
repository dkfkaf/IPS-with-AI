"""완료된 Flow 하나씩 받아 오토인코더 이상 점수를 반환하는 REP 서버."""

import argparse
import ipaddress
import json
import math
import os
import signal
import sys

import numpy as np
import torch
import zmq

from ml.artifacts import LoadedArtifacts, load_artifacts
from ml.features import FEATURES

INVALID_JSON = "INVALID_JSON"
INVALID_FIELD = "INVALID_FIELD"
SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
FEATURE_SCHEMA_MISMATCH = "FEATURE_SCHEMA_MISMATCH"
FEATURE_COUNT_MISMATCH = "FEATURE_COUNT_MISMATCH"
NONFINITE_FEATURE = "NONFINITE_FEATURE"

_running = True


class RequestError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _require_integer(request: dict, key: str, minimum: int, maximum: int) -> int:
    value = request.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise RequestError(INVALID_FIELD, f"{key} 정수 필드 오류")
    if value < minimum or value > maximum:
        raise RequestError(INVALID_FIELD, f"{key} 범위 오류")
    return value


def _require_ipv4(request: dict, key: str) -> None:
    value = request.get(key)
    if not isinstance(value, str):
        raise RequestError(INVALID_FIELD, f"{key} 문자열 필드 오류")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise RequestError(INVALID_FIELD, f"{key} IPv4 오류") from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise RequestError(INVALID_FIELD, f"{key} IPv4 오류")


def _validate_request(
    request: object, artifacts: LoadedArtifacts
) -> tuple[str, np.ndarray]:
    if not isinstance(request, dict):
        raise RequestError(INVALID_FIELD, "요청이 JSON object가 아님")
    flow_id = request.get("flow_id")
    if not isinstance(flow_id, str) or not flow_id:
        raise RequestError(INVALID_FIELD, "flow_id 오류")
    if request.get("schema_version") != 1 or isinstance(
        request.get("schema_version"), bool
    ):
        raise RequestError(SCHEMA_MISMATCH, "schema_version 오류")
    feature_schema_version = request.get("feature_schema_version")
    if feature_schema_version != artifacts.feature_schema_version or isinstance(
        feature_schema_version, bool
    ):
        raise RequestError(
            FEATURE_SCHEMA_MISMATCH, "feature_schema_version 오류"
        )

    _require_ipv4(request, "src_ip")
    _require_ipv4(request, "dst_ip")
    _require_integer(request, "src_port", 0, 65535)
    _require_integer(request, "dst_port", 0, 65535)
    _require_integer(request, "protocol", 0, 255)
    first_seen_ms = _require_integer(request, "first_seen_ms", 0, 2**63 - 1)
    last_seen_ms = _require_integer(request, "last_seen_ms", 0, 2**63 - 1)
    if first_seen_ms > last_seen_ms:
        raise RequestError(INVALID_FIELD, "Flow 시간 순서 오류")
    if request.get("end_reason") not in {"tcp_fin", "tcp_reset", "timeout"}:
        raise RequestError(INVALID_FIELD, "end_reason 오류")

    feature_values = request.get("features")
    if not isinstance(feature_values, list) or len(feature_values) != len(FEATURES):
        raise RequestError(FEATURE_COUNT_MISMATCH, "특징 개수 오류")
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float))
        for value in feature_values
    ):
        raise RequestError(INVALID_FIELD, "특징 타입 오류")
    try:
        features = np.asarray(feature_values, dtype=np.float64)
    except OverflowError as error:
        raise RequestError(NONFINITE_FEATURE, "특징 숫자 범위 오류") from error
    if not np.isfinite(features).all():
        raise RequestError(NONFINITE_FEATURE, "특징에 NaN 또는 Inf 포함")
    return flow_id, features


def infer_request(artifacts: LoadedArtifacts, request: object) -> dict[str, object]:
    flow_id, features = _validate_request(request, artifacts)
    scaled = (features - artifacts.mean) / artifacts.scale
    with torch.no_grad():
        input_tensor = torch.tensor(scaled[None, :], dtype=torch.float32)
        reconstructed = artifacts.model(input_tensor)
        score = float(((reconstructed - input_tensor) ** 2).mean().item())
    if not math.isfinite(score):
        raise RuntimeError("모델 복원오차가 유한하지 않음")
    return {
        "schema_version": 1,
        "flow_id": flow_id,
        "model_version": artifacts.model_version,
        "ok": True,
        "anomaly": score > artifacts.threshold,
        "score": score,
        "threshold": artifacts.threshold,
    }


def _error_response(
    artifacts: LoadedArtifacts, request: object, error: RequestError
) -> dict[str, object]:
    flow_id = request.get("flow_id", "") if isinstance(request, dict) else ""
    return {
        "schema_version": 1,
        "flow_id": flow_id if isinstance(flow_id, str) else "",
        "model_version": artifacts.model_version,
        "ok": False,
        "error_code": error.code,
    }


def _stop(_signum, _frame) -> None:
    global _running
    _running = False


def run(endpoint: str, artifact_dir: str) -> int:
    global _running
    _running = True
    os.umask(0o077)
    artifacts = load_artifacts(artifact_dir, require_secure_permissions=True)
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.setsockopt(zmq.LINGER, 0)
    socket.setsockopt(zmq.RCVTIMEO, 250)
    socket.bind(endpoint)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    print(
        json.dumps(
            {
                "event": "AI_READY",
                "schema_version": 1,
                "model_version": artifacts.model_version,
            }
        ),
        flush=True,
    )

    try:
        while _running:
            try:
                payload = socket.recv()
            except zmq.Again:
                continue
            request = None
            try:
                request = json.loads(payload.decode("utf-8", errors="strict"))
                response = infer_request(artifacts, request)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                response = _error_response(
                    artifacts, request, RequestError(INVALID_JSON, str(error))
                )
            except RequestError as error:
                response = _error_response(artifacts, request, error)
            except Exception as error:
                print(f"AI 추론 실패: {error}", file=sys.stderr, flush=True)
                return 1
            try:
                socket.send_json(response)
            except zmq.ZMQError as error:
                print(f"AI 응답 전송 실패: {error}", file=sys.stderr, flush=True)
                return 1
    finally:
        socket.close(linger=0)
        context.term()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--artifact-dir", required=True)
    args = parser.parse_args()
    return run(args.endpoint, args.artifact_dir)


if __name__ == "__main__":
    raise SystemExit(main())
