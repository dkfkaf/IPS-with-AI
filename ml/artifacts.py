"""학습·평가·온라인 추론이 공유하는 artifact 로더."""

import json
import stat
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import torch

from ml.features import FEATURES, FEATURE_SCHEMA_VERSION
from ml.model import Autoencoder


@dataclass(frozen=True)
class LoadedArtifacts:
    model: Autoencoder
    mean: np.ndarray
    scale: np.ndarray
    threshold: float
    feature_schema_version: int
    model_version: str


def _require_regular_file(path: Path, require_secure_permissions: bool) -> None:
    file_stat = path.stat()
    if not path.is_file():
        raise ValueError(f"artifact가 일반 파일이 아님: {path}")
    if require_secure_permissions and file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PermissionError(f"artifact가 group/other 쓰기 가능: {path}")


def load_artifacts(
    artifact_dir: str, *, require_secure_permissions: bool = False
) -> LoadedArtifacts:
    """고정된 세 artifact를 검증하고 CPU 추론 상태로 읽는다."""
    directory = Path(artifact_dir).resolve(strict=True)
    if not directory.is_dir():
        raise ValueError(f"artifact 경로가 디렉터리가 아님: {directory}")

    model_path = (directory / "autoencoder.pt").resolve(strict=True)
    scaler_path = (directory / "scaler.npz").resolve(strict=True)
    metadata_path = (directory / "metadata.json").resolve(strict=True)
    for path in (model_path, scaler_path, metadata_path):
        _require_regular_file(path, require_secure_permissions)

    with metadata_path.open(encoding="utf-8") as file:
        metadata = json.load(file)
    if not isinstance(metadata, dict):
        raise ValueError("metadata가 JSON object가 아님")
    try:
        if metadata["features"] != FEATURES:
            raise ValueError("metadata 특징 순서 불일치")
        if metadata["n_features"] != len(FEATURES):
            raise ValueError("metadata 특징 개수 불일치")
        if metadata["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
            raise ValueError("metadata 특징 스키마 불일치")
        model_version = metadata["model_version"]
        if not isinstance(model_version, str) or not model_version:
            raise ValueError("metadata 모델 버전 오류")
        threshold = float(metadata["threshold"])
    except KeyError as error:
        raise ValueError(f"metadata 필수 필드 누락: {error.args[0]}") from error
    except (TypeError, OverflowError) as error:
        raise ValueError("metadata 임계값 오류") from error
    if not np.isfinite(threshold) or threshold < 0:
        raise ValueError("metadata 임계값 오류")

    with np.load(scaler_path, allow_pickle=False) as scaler:
        try:
            mean = np.asarray(scaler["mean"], dtype=np.float64)
            scale = np.asarray(scaler["scale"], dtype=np.float64)
        except KeyError as error:
            raise ValueError(f"scaler 필수 배열 누락: {error.args[0]}") from error
    expected_shape = (len(FEATURES),)
    if mean.shape != expected_shape or scale.shape != expected_shape:
        raise ValueError("scaler 배열 크기 불일치")
    if not np.all(np.isfinite(mean)) or not np.all(np.isfinite(scale)):
        raise ValueError("scaler에 유한하지 않은 값이 있음")
    if not np.all(scale > 0):
        raise ValueError("scaler scale은 0보다 커야 함")

    model = Autoencoder(len(FEATURES))
    state_dict = torch.load(model_path, map_location="cpu", weights_only=True)
    model.load_state_dict(state_dict)
    model.eval()
    return LoadedArtifacts(
        model=model,
        mean=mean,
        scale=scale,
        threshold=threshold,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        model_version=model_version,
    )
