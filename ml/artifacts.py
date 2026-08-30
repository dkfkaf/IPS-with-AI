"""학습·평가·온라인 추론이 공유하는 artifact 로더."""

import json
import os
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


def _require_root_owned(path: Path, path_stat: os.stat_result) -> None:
    if path_stat.st_uid != 0:
        raise PermissionError(f"root 소유 경로가 아님: {path}")
    if path_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PermissionError(f"group/other 쓰기 가능 경로: {path}")


def _require_secure_directory_tree(directory: Path) -> None:
    current = Path(directory.anchor)
    for part in directory.parts[1:]:
        current /= part
        path_stat = current.lstat()
        if stat.S_ISLNK(path_stat.st_mode):
            raise PermissionError(f"symbolic link 디렉터리는 허용하지 않음: {current}")
        if not stat.S_ISDIR(path_stat.st_mode):
            raise ValueError(f"artifact 경로가 디렉터리가 아님: {current}")
        _require_root_owned(current, path_stat)


def _require_regular_file(path: Path, require_secure_permissions: bool) -> None:
    file_stat = path.lstat() if require_secure_permissions else path.stat()
    if require_secure_permissions and stat.S_ISLNK(file_stat.st_mode):
        raise PermissionError(f"symbolic link artifact는 허용하지 않음: {path}")
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError(f"artifact가 일반 파일이 아님: {path}")
    if require_secure_permissions:
        _require_root_owned(path, file_stat)


def load_artifacts(
    artifact_dir: str, *, require_secure_permissions: bool = False
) -> LoadedArtifacts:
    """고정된 세 artifact를 검증하고 CPU 추론 상태로 읽는다."""
    configured_directory = Path(os.path.abspath(artifact_dir))
    if require_secure_permissions:
        _require_secure_directory_tree(configured_directory)
    directory = configured_directory.resolve(strict=True)
    if not directory.is_dir():
        raise ValueError(f"artifact 경로가 디렉터리가 아님: {directory}")

    model_path = directory / "autoencoder.pt"
    scaler_path = directory / "scaler.npz"
    metadata_path = directory / "metadata.json"
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
