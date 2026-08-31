"""온라인 AI 요청 계약과 이상 판정을 검증한다."""

import unittest

import numpy as np
import torch

from ml.artifacts import LoadedArtifacts
from ml.features import FEATURES, FEATURE_SCHEMA_VERSION
from ml.online_server import (
    FEATURE_COUNT_MISMATCH,
    FEATURE_SCHEMA_MISMATCH,
    INVALID_FIELD,
    NONFINITE_FEATURE,
    SCHEMA_MISMATCH,
    RequestError,
    infer_request,
)


class ZeroModel(torch.nn.Module):
    def forward(self, value):
        return torch.zeros_like(value)


class NanModel(torch.nn.Module):
    def forward(self, value):
        return torch.full_like(value, float("nan"))


def make_artifacts(model: torch.nn.Module, threshold: float) -> LoadedArtifacts:
    return LoadedArtifacts(
        model=model,
        mean=np.zeros(len(FEATURES), dtype=np.float64),
        scale=np.ones(len(FEATURES), dtype=np.float64),
        threshold=threshold,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        model_version="ae-test-v1",
    )


def make_request() -> dict[str, object]:
    return {
        "schema_version": 1,
        "flow_id": "sensor-1",
        "src_ip": "192.0.2.10",
        "src_port": 45678,
        "dst_ip": "198.51.100.20",
        "dst_port": 443,
        "protocol": 6,
        "first_seen_ms": 1000,
        "last_seen_ms": 2500,
        "end_reason": "timeout",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "features": [0.0] * len(FEATURES),
    }


class OnlineInferenceTest(unittest.TestCase):
    def assert_request_error(self, request, expected_code, expected_message):
        artifacts = make_artifacts(torch.nn.Identity(), threshold=0.1)
        with self.assertRaises(RequestError) as raised:
            infer_request(artifacts, request)
        self.assertEqual(raised.exception.code, expected_code)
        self.assertEqual(str(raised.exception), expected_message)

    def test_identity_model_returns_normal_decision(self):
        response = infer_request(
            make_artifacts(torch.nn.Identity(), threshold=0.1), make_request()
        )

        self.assertTrue(response["ok"])
        self.assertFalse(response["anomaly"])
        self.assertEqual(response["flow_id"], "sensor-1")
        self.assertEqual(response["model_version"], "ae-test-v1")
        self.assertEqual(response["score"], 0.0)
        self.assertEqual(response["threshold"], 0.1)

    def test_reconstruction_error_above_threshold_returns_anomaly(self):
        request = make_request()
        request["features"] = [2.0] * len(FEATURES)

        response = infer_request(
            make_artifacts(ZeroModel(), threshold=3.5), request
        )

        self.assertTrue(response["ok"])
        self.assertTrue(response["anomaly"])
        self.assertEqual(response["flow_id"], "sensor-1")
        self.assertEqual(response["model_version"], "ae-test-v1")
        self.assertAlmostEqual(response["score"], 4.0)
        self.assertEqual(response["threshold"], 3.5)

    def test_schema_validation_returns_specific_errors(self):
        wrong_schema = make_request()
        wrong_schema["schema_version"] = 2
        wrong_feature_schema = make_request()
        wrong_feature_schema["feature_schema_version"] = 2

        cases = [
            ([], INVALID_FIELD, "요청이 JSON object가 아님"),
            ({}, INVALID_FIELD, "flow_id 오류"),
            (wrong_schema, SCHEMA_MISMATCH, "schema_version 오류"),
            (
                wrong_feature_schema,
                FEATURE_SCHEMA_MISMATCH,
                "feature_schema_version 오류",
            ),
        ]
        for request, code, message in cases:
            with self.subTest(message=message):
                self.assert_request_error(request, code, message)

    def test_flow_metadata_validation_returns_specific_errors(self):
        ipv6 = make_request()
        ipv6["src_ip"] = "2001:db8::1"
        boolean_port = make_request()
        boolean_port["src_port"] = True
        oversized_port = make_request()
        oversized_port["dst_port"] = 65536
        oversized_protocol = make_request()
        oversized_protocol["protocol"] = 256
        reversed_time = make_request()
        reversed_time["first_seen_ms"] = 3000
        invalid_reason = make_request()
        invalid_reason["end_reason"] = "manual"

        cases = [
            (ipv6, "src_ip IPv4 오류"),
            (boolean_port, "src_port 정수 필드 오류"),
            (oversized_port, "dst_port 범위 오류"),
            (oversized_protocol, "protocol 범위 오류"),
            (reversed_time, "Flow 시간 순서 오류"),
            (invalid_reason, "end_reason 오류"),
        ]
        for request, message in cases:
            with self.subTest(message=message):
                self.assert_request_error(request, INVALID_FIELD, message)

    def test_feature_validation_returns_specific_errors(self):
        wrong_count = make_request()
        wrong_count["features"] = [0.0]
        boolean_feature = make_request()
        boolean_feature["features"] = [False] * len(FEATURES)
        nonfinite = make_request()
        nonfinite_features = [0.0] * len(FEATURES)
        nonfinite_features[0] = float("nan")
        nonfinite["features"] = nonfinite_features
        out_of_float_range = make_request()
        out_of_float_range["features"][0] = 10**400

        cases = [
            (wrong_count, FEATURE_COUNT_MISMATCH, "특징 개수 오류"),
            (boolean_feature, INVALID_FIELD, "특징 타입 오류"),
            (nonfinite, NONFINITE_FEATURE, "특징에 NaN 또는 Inf 포함"),
            (out_of_float_range, NONFINITE_FEATURE, "특징 숫자 범위 오류"),
        ]
        for request, code, message in cases:
            with self.subTest(message=message):
                self.assert_request_error(request, code, message)

    def test_nonfinite_model_error_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "모델 복원오차가 유한하지 않음"):
            infer_request(make_artifacts(NanModel(), threshold=0.1), make_request())


if __name__ == "__main__":
    unittest.main()
