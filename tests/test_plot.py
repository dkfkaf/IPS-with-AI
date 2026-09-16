"""평가 그래프 생성 함수가 PNG 산출물을 만드는지 검증한다."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import matplotlib
import numpy as np
import pandas as pd
import torch

from ml.features import BENIGN_LABEL, FEATURE_SCHEMA_VERSION, FEATURES, LABEL_COLUMN
from ml.model import Autoencoder
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
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            model = Autoencoder(len(FEATURES))
            torch.save(model.state_dict(), directory / "autoencoder.pt")
            np.savez(directory / "scaler.npz", mean=np.zeros(27), scale=np.ones(27))
            metadata = {
                "features": FEATURES,
                "n_features": 27,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "model_version": "ae-plot-test",
                "threshold": 0.5,
            }
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            frame = pd.DataFrame(np.arange(324).reshape(12, 27) / 100, columns=FEATURES)
            frame[LABEL_COLUMN] = [BENIGN_LABEL] * 10 + ["DDoS", "PortScan"]
            csv_path = directory / "flows.csv"
            frame.to_csv(csv_path, index=False)
            plots = directory / "plots"

            with (
                patch("ml.plot.ARTIFACTS", str(directory)),
                patch("ml.plot.PLOTS", str(plots)),
                redirect_stdout(io.StringIO()) as output,
            ):
                result = run(str(csv_path))

            self.assertIsNone(result)
            self.assertEqual(output.getvalue(), f"그래프 3장 저장 완료 → {plots}\n")
            self.assertEqual(
                {path.name for path in plots.iterdir()},
                {"error_distribution.png", "detection_by_type.png", "roc.png"},
            )
            for path in plots.iterdir():
                self.assertEqual(path.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")

    def _assert_plot_written(self, filename, plot_function, *arguments):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / filename

            plot_function(*arguments, path)

            self.assertTrue(path.is_file())
            self.assertGreater(path.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
