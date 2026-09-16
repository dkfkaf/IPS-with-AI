"""분할 점검이 누수 신호와 재현성 정보를 실제 CSV에서 계산하는지 검증한다."""

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from ml.audit_dataset import audit_dataset, run
from ml.features import BENIGN_LABEL, FEATURES, LABEL_COLUMN


class AuditDatasetTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.csv_path = self.directory / "flows.csv"

    def write_csv(self, values):
        frame = pd.DataFrame({feature: values for feature in FEATURES})
        frame[LABEL_COLUMN] = [BENIGN_LABEL] * len(values)
        frame.to_csv(self.csv_path, index=False)

    def test_records_reproducible_splits_without_claiming_session_isolation(self):
        self.write_csv(list(range(10)))

        first = audit_dataset(str(self.csv_path))
        second = audit_dataset(str(self.csv_path))

        self.assertEqual(first, second)
        self.assertEqual(first["split"], {"method": "row_random", "seed": 42,
                                          "ratios": [0.6, 0.2, 0.2]})
        self.assertEqual([part["rows"] for part in first["splits"].values()], [6, 2, 2])
        self.assertTrue(all(item["shared_vectors"] == 0 for item in first["feature_overlap"]))
        self.assertEqual(first["group_isolation"], "not_checked")
        self.assertRegex(first["sources"][0]["sha256"], r"^[0-9a-f]{64}$")
        for part in first["splits"].values():
            self.assertRegex(part["indices_sha256"], r"^[0-9a-f]{64}$")

    def test_reports_identical_features_across_all_three_splits(self):
        self.write_csv([1.0] * 10)

        report = audit_dataset(str(self.csv_path))

        self.assertEqual(report["feature_overlap"], [
            {"left": "train", "right": "validation", "shared_vectors": 1},
            {"left": "train", "right": "test", "shared_vectors": 1},
            {"left": "validation", "right": "test", "shared_vectors": 1},
        ])

    def test_normalizes_signed_zero_when_finding_duplicate_features(self):
        self.write_csv([0.0] * 6 + [-0.0] * 4)
        report = audit_dataset(str(self.csv_path))
        self.assertEqual([item["shared_vectors"] for item in report["feature_overlap"]], [1, 1, 1])

    def test_counts_dropped_rows_and_excludes_attacks_from_benign_splits(self):
        frame = pd.DataFrame({feature: list(range(11)) for feature in FEATURES})
        frame[LABEL_COLUMN] = [BENIGN_LABEL] * 10 + ["DDoS"]
        frame.loc[0, FEATURES[0]] = np.nan
        frame.to_csv(self.csv_path, index=False)

        report = audit_dataset(str(self.csv_path))

        self.assertEqual(report["rows"], {"total": 11, "valid": 10, "discarded": 1,
                                         "benign": 9, "attack": 1})
        self.assertEqual(sum(part["rows"] for part in report["splits"].values()), 9)

    def test_input_content_change_changes_source_digest(self):
        self.write_csv(list(range(10)))
        before = audit_dataset(str(self.csv_path))["sources"][0]["sha256"]
        self.write_csv(list(range(1, 11)))
        after = audit_dataset(str(self.csv_path))["sources"][0]["sha256"]
        self.assertNotEqual(before, after)

    def test_missing_csv_fails_without_creating_a_report(self):
        output_path = self.directory / "audit.json"
        with self.assertRaisesRegex(ValueError, "CSV"):
            run(str(self.directory / "*.csv"), str(output_path))
        self.assertFalse(output_path.exists())

    def test_run_writes_report_and_never_overwrites_existing_output(self):
        self.write_csv(list(range(10)))
        output_path = self.directory / "audit.json"
        run(str(self.csv_path), str(output_path))
        saved = output_path.read_bytes()
        self.assertEqual(json.loads(saved)["rows"]["valid"], 10)
        with self.assertRaises(FileExistsError):
            run(str(self.csv_path), str(output_path))
        self.assertEqual(output_path.read_bytes(), saved)


if __name__ == "__main__":
    unittest.main()
