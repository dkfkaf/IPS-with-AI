"""오토인코더 출력 형태와 복원오차 계산 계약을 검증한다."""

import unittest

import numpy as np
import torch

from ml.model import (
    Autoencoder,
    normalized_reconstruction_errors,
    reconstruction_errors,
)


class ZeroModel(torch.nn.Module):
    def forward(self, value):
        return torch.zeros_like(value)


class ModelTest(unittest.TestCase):
    def test_autoencoder_preserves_batch_and_feature_shape(self):
        model = Autoencoder(27)

        reconstructed = model(torch.zeros((3, 27), dtype=torch.float32))

        self.assertEqual(tuple(reconstructed.shape), (3, 27))

    def test_reconstruction_errors_returns_row_mse_and_sets_eval_mode(self):
        model = ZeroModel()
        model.train()
        feature_matrix = np.array([[1.0, 2.0], [3.0, 4.0]])

        errors = reconstruction_errors(model, feature_matrix)

        np.testing.assert_allclose(errors, np.array([2.5, 12.5]))
        self.assertFalse(model.training)

    def test_normalized_reconstruction_errors_uses_training_scaler(self):
        feature_matrix = np.array([[3.0, 6.0]])
        mean = np.array([1.0, 2.0])
        scale = np.array([2.0, 2.0])

        errors = normalized_reconstruction_errors(
            ZeroModel(), mean, scale, feature_matrix
        )

        np.testing.assert_allclose(errors, np.array([2.5]))


if __name__ == "__main__":
    unittest.main()
