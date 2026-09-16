"""현재 정상 행 분할의 재현성과 특징 중복을 기록한다. 세션 격리를 인증하지 않는다."""

import argparse
import glob
import hashlib
import json
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd

from ml.features import BENIGN_LABEL, FEATURE_SCHEMA_VERSION, FEATURES
from ml.preprocess import extract_features, load_flows, split_benign_indices


def _file_sha256(path):
    """대용량 CSV를 한 번에 메모리에 복사하지 않고 내용 지문을 계산한다."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _describe_splits(feature_matrix, labels, ratios, seed):
    """실제 분할 행의 지문과 분할 사이에 공유되는 특징 벡터 수를 계산한다."""
    splits = {}
    fingerprints = {}
    parts = split_benign_indices(labels, ratios, seed)
    for name, indices in zip(("train", "validation", "test"), parts):
        splits[name] = {
            "rows": len(indices),
            "indices_sha256": hashlib.sha256(
                np.asarray(indices, dtype="<i8").tobytes()
            ).hexdigest(),
        }
        # -0.0과 0.0은 모델 입력으로 같으므로 바이트 지문에서도 같게 취급한다.
        fingerprints[name] = {
            hashlib.sha256(np.asarray(feature_matrix[index] + 0.0, dtype="<f8").tobytes()).digest()
            for index in indices
        }
    overlap = [
        {"left": left, "right": right,
         "shared_vectors": len(fingerprints[left] & fingerprints[right])}
        for left, right in combinations(fingerprints, 2)
    ]
    return splits, overlap


def audit_dataset(csv_glob):
    """CSV 출처·정리 결과·기존 분할의 점검 보고서를 반환한다. 모델은 변경하지 않는다."""
    paths = [Path(path).resolve() for path in sorted(glob.glob(csv_glob))]
    if not paths:
        raise ValueError("일치하는 CSV 파일이 없음")
    sources = [{"path": str(path), "sha256": _file_sha256(path)} for path in paths]
    frame = load_flows(paths)
    feature_matrix, labels = extract_features(frame)
    for path, source in zip(paths, sources):
        if _file_sha256(path) != source["sha256"]:
            raise ValueError(f"점검 중 CSV 내용 변경: {path}")
    ratios, seed = (0.6, 0.2, 0.2), 42
    splits, overlap = _describe_splits(feature_matrix, labels, ratios, seed)
    benign_count = int(np.count_nonzero(labels == BENIGN_LABEL))
    return {
        "audit_schema_version": 1,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "features": FEATURES,
        "environment": {"numpy": np.__version__, "pandas": pd.__version__},
        "sources": sources,
        "rows": {"total": len(frame), "valid": len(labels), "discarded": len(frame) - len(labels),
                 "benign": benign_count, "attack": len(labels) - benign_count},
        "split": {"method": "row_random", "seed": seed, "ratios": list(ratios)},
        "splits": splits,
        "feature_overlap": overlap,
        "group_isolation": "not_checked",
        "limitations": [
            "같은 특징 지문은 잠재적 누수 신호이며 동일 세션의 확정 증거는 아님",
            "행 분할은 날짜·세션 격리를 보장하지 않으며 중복이 없어도 누수 없음을 증명하지 못함",
            "분할이 비어 있으면 학습·평가에 사용하기 전에 데이터 구성을 확인해야 함",
        ],
    }


def run(csv_glob, output_path):
    """분할 점검 보고서를 새 JSON 파일로 저장한다. 기존 결과는 덮어쓰지 않는다."""
    report = audit_dataset(csv_glob)
    with Path(output_path).open("x", encoding="utf-8") as output:
        json.dump(report, output, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="CSV glob 패턴")
    parser.add_argument("--output", required=True, help="새 JSON 보고서 경로")
    arguments = parser.parse_args()
    run(arguments.data, arguments.output)
