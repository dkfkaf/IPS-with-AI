"""평가 그래프 생성 함수가 PNG 산출물을 만드는지 검증한다."""

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import matplotlib
import numpy as np

from ml.features import BENIGN_LABEL
from ml.plot import (
    _plot_detection_by_type,
    _plot_error_distribution,
    _plot_roc,
    run,
)


class PlotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous_font_family = matplotlib.rcParams["font.family"]
        matplotlib.rcParams["font.family"] = "DejaVu Sans"

    @classmethod
    def tearDownClass(cls):
        matplotlib.rcParams["font.family"] = cls.previous_font_family

    def test_error_distribution_writes_png(self):
        benign_errors = np.array([0.1, 0.2, 0.3])
        attack_errors = np.array([0.4, 0.8, 1.2])

        self._assert_plot_written(
            "distribution.png",
            _plot_error_distribution,
            benign_errors,
            attack_errors,
            0.35,
        )

    def test_detection_by_type_writes_png(self):
        attack_errors = np.array([0.2, 0.8, 0.9])
        attack_labels = np.array(["DDoS", "DDoS", "PortScan"])

        self._assert_plot_written(
            "detection.png",
            _plot_detection_by_type,
            attack_errors,
            attack_labels,
            0.5,
        )

    def test_roc_writes_png(self):
        benign_errors = np.array([0.1, 0.2, 0.3])
        attack_errors = np.array([0.4, 0.8, 1.2])

        self._assert_plot_written(
            "roc.png", _plot_roc, benign_errors, attack_errors, 0.35
        )

    def test_run_uses_loaded_artifact_contract(self):
        artifacts = SimpleNamespace(
            model=object(),
            mean=np.zeros(2),
            scale=np.ones(2),
            threshold=0.5,
        )
        feature_matrix = np.arange(8, dtype=np.float64).reshape(4, 2)
        labels = np.array([BENIGN_LABEL, BENIGN_LABEL, "DDoS", "PortScan"])
        benign_test = feature_matrix[:2]

        with (
            patch("ml.plot.load_artifacts", autospec=True, return_value=artifacts),
            patch("ml.plot.load_dataset", return_value=(feature_matrix, labels)),
            patch(
                "ml.plot.split_benign",
                return_value=(np.empty((0, 2)), np.empty((0, 2)), benign_test),
            ),
            patch(
                "ml.plot.normalized_reconstruction_errors",
                side_effect=[np.array([0.8, 0.9]), np.array([0.1, 0.2])],
            ),
            patch("ml.plot._plot_error_distribution") as distribution_mock,
            patch("ml.plot._plot_detection_by_type") as detection_mock,
            patch("ml.plot._plot_roc") as roc_mock,
            redirect_stdout(io.StringIO()),
        ):
            run("data/*.csv")

        distribution_mock.assert_called_once()
        detection_mock.assert_called_once()
        roc_mock.assert_called_once()

    def _assert_plot_written(self, filename, plot_function, *arguments):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / filename

            plot_function(*arguments, path)

            self.assertTrue(path.is_file())
            self.assertGreater(path.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
