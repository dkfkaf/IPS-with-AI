"""CSV 정리, 특징 추출, 정상 데이터 분할 계약을 검증한다."""

import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from ml.features import BENIGN_LABEL, FEATURES, LABEL_COLUMN
from ml.preprocess import extract_features, load_dataset, split_benign


def make_row(value: float, label: str) -> dict[str, object]:
    row = {feature: value for feature in FEATURES}
    row[LABEL_COLUMN] = label
    return row


class PreprocessTest(unittest.TestCase):
    def test_load_dataset_sorts_files_and_strips_column_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            first = pd.DataFrame([make_row(1.0, " BENIGN ")])
            second = pd.DataFrame([make_row(2.0, "DDoS")])
            first.columns = [f" {column} " for column in first.columns]
            second.columns = [f" {column} " for column in second.columns]
            second.to_csv(directory / "b.csv", index=False)
            first.to_csv(directory / "a.csv", index=False)

            feature_matrix, labels = load_dataset(str(directory / "*.csv"))

        np.testing.assert_allclose(feature_matrix[:, 0], np.array([1.0, 2.0]))
        np.testing.assert_array_equal(labels, np.array([BENIGN_LABEL, "DDoS"]))

    def test_extract_features_drops_invalid_rows_without_misaligning_labels(self):
        rows = [
            make_row(1.0, " BENIGN "),
            make_row(2.0, "DDoS"),
            make_row(3.0, "PortScan"),
        ]
        rows[2][FEATURES[0]] = np.inf

        feature_matrix, labels = extract_features(pd.DataFrame(rows))

        self.assertEqual(feature_matrix.shape, (2, len(FEATURES)))
        np.testing.assert_allclose(feature_matrix[:, 0], np.array([1.0, 2.0]))
        np.testing.assert_array_equal(labels, np.array([BENIGN_LABEL, "DDoS"]))

    def test_split_benign_excludes_attacks_and_is_deterministic(self):
        feature_matrix = np.arange(16, dtype=np.float64).reshape(8, 2)
        labels = np.array([BENIGN_LABEL] * 6 + ["DDoS", "PortScan"])

        first_split = split_benign(feature_matrix, labels, seed=7)
        second_split = split_benign(feature_matrix, labels, seed=7)

        self.assertEqual([len(part) for part in first_split], [3, 1, 2])
        for first, second in zip(first_split, second_split):
            np.testing.assert_array_equal(first, second)
        combined = np.concatenate(first_split)
        expected_rows = {tuple(row) for row in feature_matrix[:6]}
        self.assertEqual({tuple(row) for row in combined}, expected_rows)


if __name__ == "__main__":
    unittest.main()
