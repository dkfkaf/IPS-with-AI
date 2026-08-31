"""정상 오탐률과 공격 탐지율 평가 흐름을 검증한다."""

import io
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np

from ml.evaluate import ARTIFACTS, run
from ml.features import BENIGN_LABEL


class EvaluateTest(unittest.TestCase):
    def test_run_returns_rates_and_prints_each_attack_type(self):
        artifacts = SimpleNamespace(
            model=object(),
            mean=np.zeros(2),
            scale=np.ones(2),
            threshold=0.5,
        )
        feature_matrix = np.arange(10, dtype=np.float64).reshape(5, 2)
        labels = np.array([BENIGN_LABEL, BENIGN_LABEL, "PortScan", "DDoS", "DDoS"])
        benign_test = feature_matrix[:2]
        benign_errors = np.array([0.2, 0.8])
        attack_errors = np.array([0.6, 0.2, 0.9])

        with (
            patch("ml.evaluate.load_artifacts", return_value=artifacts) as load_mock,
            patch("ml.evaluate.load_dataset", return_value=(feature_matrix, labels)),
            patch(
                "ml.evaluate.split_benign",
                return_value=(np.empty((0, 2)), np.empty((0, 2)), benign_test),
            ),
            patch(
                "ml.evaluate.normalized_reconstruction_errors",
                side_effect=[benign_errors, attack_errors],
            ),
            redirect_stdout(io.StringIO()) as output,
        ):
            false_positive_rate, detection_rate = run("data/*.csv")

        load_mock.assert_called_once_with(ARTIFACTS)
        self.assertEqual(false_positive_rate, 0.5)
        self.assertAlmostEqual(detection_rate, 2 / 3)
        self.assertIn("오탐률(정상 test) = 0.500", output.getvalue())
        self.assertIn("탐지율(공격 전체) = 0.667", output.getvalue())
        self.assertLess(output.getvalue().index("DDoS"), output.getvalue().index("PortScan"))


if __name__ == "__main__":
    unittest.main()
