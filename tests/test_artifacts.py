"""학습 artifact 계약과 온라인 권한 검사를 검증한다."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import numpy as np
import torch

from ml.artifacts import load_artifacts
from ml.features import FEATURES, FEATURE_SCHEMA_VERSION
from ml.model import Autoencoder


def write_artifacts(directory: Path, *, scale=None, metadata_updates=None) -> None:
    directory.mkdir()
    torch.save(
        Autoencoder(len(FEATURES)).state_dict(), directory / "autoencoder.pt"
    )
    np.savez(
        directory / "scaler.npz",
        mean=np.zeros(len(FEATURES), dtype=np.float64),
        scale=(
            np.ones(len(FEATURES), dtype=np.float64) if scale is None else scale
        ),
    )
    metadata = {
        "features": FEATURES,
        "n_features": len(FEATURES),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "model_version": "ae-test-v1",
        "threshold": 0.25,
    }
    if metadata_updates:
        metadata.update(metadata_updates)
    (directory / "metadata.json").write_text(
        json.dumps(metadata), encoding="utf-8"
    )


class ArtifactLoaderTest(unittest.TestCase):
    def test_loads_valid_artifact_bundle_in_eval_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "artifacts"
            write_artifacts(directory)

            artifacts = load_artifacts(str(directory))

            self.assertEqual(artifacts.model_version, "ae-test-v1")
            self.assertEqual(artifacts.threshold, 0.25)
            self.assertEqual(artifacts.mean.shape, (len(FEATURES),))
            self.assertEqual(artifacts.scale.shape, (len(FEATURES),))
            self.assertFalse(artifacts.model.training)

    def test_rejects_metadata_with_different_feature_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "artifacts"
            write_artifacts(
                directory, metadata_updates={"features": FEATURES[::-1]}
            )

            with self.assertRaisesRegex(ValueError, "특징 순서"):
                load_artifacts(str(directory))

    def test_rejects_nonpositive_scaler_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "artifacts"
            scale = np.ones(len(FEATURES), dtype=np.float64)
            scale[3] = 0.0
            write_artifacts(directory, scale=scale)

            with self.assertRaisesRegex(ValueError, "0보다 커야"):
                load_artifacts(str(directory))

    @unittest.skipUnless(
        os.name == "posix" and os.geteuid() == 0,
        "root 전용 온라인 artifact 권한 검사는 root Linux에서 실행",
    )
    def test_secure_loader_rejects_symbolic_link_artifact(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            root = Path(temporary)
            directory = root / "artifacts"
            write_artifacts(directory)
            target = root / "model-target.pt"
            (directory / "autoencoder.pt").replace(target)
            (directory / "autoencoder.pt").symlink_to(target)

            with self.assertRaisesRegex(PermissionError, "symbolic link artifact"):
                load_artifacts(str(directory), require_secure_permissions=True)

    @unittest.skipUnless(
        os.name == "posix" and os.geteuid() == 0,
        "root 전용 온라인 artifact 권한 검사는 root Linux에서 실행",
    )
    def test_secure_loader_rejects_group_writable_artifact(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            directory = Path(temporary) / "artifacts"
            write_artifacts(directory)
            metadata = directory / "metadata.json"
            metadata.chmod(metadata.stat().st_mode | stat.S_IWGRP)

            with self.assertRaisesRegex(PermissionError, "group/other 쓰기 가능"):
                load_artifacts(str(directory), require_secure_permissions=True)


if __name__ == "__main__":
    unittest.main()
