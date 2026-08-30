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

    def test_invalid_requests_return_specific_error_codes(self):
        cases = []

        wrong_schema = make_request()
        wrong_schema["schema_version"] = 2
        cases.append(("schema", wrong_schema, SCHEMA_MISMATCH))

        wrong_feature_schema = make_request()
        wrong_feature_schema["feature_schema_version"] = 2
        cases.append(
            ("feature schema", wrong_feature_schema, FEATURE_SCHEMA_MISMATCH)
        )

        ipv6 = make_request()
        ipv6["src_ip"] = "2001:db8::1"
        cases.append(("IPv6", ipv6, INVALID_FIELD))

        boolean_port = make_request()
        boolean_port["src_port"] = True
        cases.append(("boolean port", boolean_port, INVALID_FIELD))

        reversed_time = make_request()
        reversed_time["first_seen_ms"] = 3000
        cases.append(("time order", reversed_time, INVALID_FIELD))

        wrong_count = make_request()
        wrong_count["features"] = [0.0]
        cases.append(("feature count", wrong_count, FEATURE_COUNT_MISMATCH))

        boolean_feature = make_request()
        boolean_feature["features"] = [False] * len(FEATURES)
        cases.append(("boolean feature", boolean_feature, INVALID_FIELD))

        nonfinite = make_request()
        nonfinite_features = [0.0] * len(FEATURES)
        nonfinite_features[0] = float("nan")
        nonfinite["features"] = nonfinite_features
        cases.append(("nonfinite feature", nonfinite, NONFINITE_FEATURE))

        artifacts = make_artifacts(torch.nn.Identity(), threshold=0.1)
        for name, request, expected_code in cases:
            with self.subTest(name=name):
                with self.assertRaises(RequestError) as raised:
                    infer_request(artifacts, request)
                self.assertEqual(raised.exception.code, expected_code)


if __name__ == "__main__":
    unittest.main()
