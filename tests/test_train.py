"""모델 학습, 임계값 계산, artifact 저장 흐름을 검증한다."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import numpy as np
import torch
from sklearn.preprocessing import StandardScaler

from ml.features import FEATURE_SCHEMA_VERSION, FEATURES
from ml.model import Autoencoder
from ml.train import _calculate_threshold, _save_artifacts, run, train_model


class ZeroModel(torch.nn.Module):
    def forward(self, value):
        return torch.zeros_like(value)


class TrainTest(unittest.TestCase):
    def test_train_model_runs_one_epoch_and_preserves_feature_shape(self):
        training_data = np.zeros((4, len(FEATURES)), dtype=np.float64)

        with redirect_stdout(io.StringIO()) as output:
            model = train_model(training_data, epochs=1, batch_size=2, seed=7)

        reconstructed = model(torch.zeros((2, len(FEATURES))))
        self.assertEqual(tuple(reconstructed.shape), (2, len(FEATURES)))
        self.assertIn("epoch 1/1", output.getvalue())

    def test_calculate_threshold_uses_scaled_validation_errors(self):
        scaler = StandardScaler().fit(np.array([[1.0, 2.0], [3.0, 6.0]]))
        validation = np.array([[2.0, 4.0], [3.0, 6.0]])

        threshold = _calculate_threshold(
            ZeroModel(), scaler, validation, percentile=50.0
        )

        self.assertAlmostEqual(threshold, 0.5)

    def test_save_artifacts_writes_complete_online_contract(self):
        training_data = np.vstack(
            [np.zeros(len(FEATURES)), np.ones(len(FEATURES))]
        )
        scaler = StandardScaler().fit(training_data)
        model = Autoencoder(len(FEATURES))

        with tempfile.TemporaryDirectory() as temporary:
            with patch("ml.train.ARTIFACTS", temporary):
                _save_artifacts(model, scaler, 0.25, 99.0, "ae-test-v1")

            directory = Path(temporary)
            self.assertTrue((directory / "autoencoder.pt").is_file())
            with np.load(directory / "scaler.npz") as saved_scaler:
                np.testing.assert_allclose(saved_scaler["mean"], scaler.mean_)
                np.testing.assert_allclose(saved_scaler["scale"], scaler.scale_)
            metadata = json.loads(
                (directory / "metadata.json").read_text(encoding="utf-8")
            )

        self.assertEqual(metadata["feature_schema_version"], FEATURE_SCHEMA_VERSION)
        self.assertEqual(metadata["features"], FEATURES)
        self.assertEqual(metadata["n_features"], len(FEATURES))
        self.assertEqual(metadata["model_version"], "ae-test-v1")
        self.assertEqual(metadata["threshold"], 0.25)
        self.assertEqual(metadata["percentile"], 99.0)

    def test_run_orchestrates_training_threshold_and_save(self):
        feature_matrix = np.zeros((4, len(FEATURES)), dtype=np.float64)
        labels = np.array(["BENIGN"] * 4)
        training = np.vstack(
            [np.zeros(len(FEATURES)), np.ones(len(FEATURES))]
        )
        validation = np.ones((1, len(FEATURES)))
        test = np.ones((1, len(FEATURES)))
        model = Autoencoder(len(FEATURES))

        with (
            patch("ml.train.load_dataset", return_value=(feature_matrix, labels)),
            patch("ml.train.split_benign", return_value=(training, validation, test)),
            patch("ml.train.train_model", return_value=model) as train_mock,
            patch("ml.train._calculate_threshold", return_value=0.75) as threshold_mock,
            patch("ml.train._save_artifacts") as save_mock,
            redirect_stdout(io.StringIO()),
        ):
            returned_model, scaler, threshold = run("data/*.csv", epochs=4, percentile=95.0)

        train_mock.assert_called_once()
        threshold_mock.assert_called_once_with(model, scaler, validation, 95.0)
        saved = save_mock.call_args.args
        self.assertEqual(saved[:4], (model, scaler, 0.75, 95.0))
        self.assertRegex(saved[4], r"^ae-\d{8}T\d{6}Z$")
        self.assertIs(returned_model, model)
        self.assertEqual(threshold, 0.75)


if __name__ == "__main__":
    unittest.main()
