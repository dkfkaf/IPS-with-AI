"""CSV를 읽어 정리하고, 학습에 쓸 특징 배열과 라벨을 뽑는다."""

import glob

import numpy as np
import pandas as pd

from ml.features import BENIGN_LABEL, FEATURES, LABEL_COLUMN


def load_flows(csv_paths):
    """CSV 여러 개를 읽어 하나로 합친다. 컬럼명 앞뒤 공백을 제거한다
    (CICIDS2017은 컬럼명 앞에 공백이 붙어 있다)."""
    frames = [pd.read_csv(path) for path in csv_paths]
    df = pd.concat(frames, ignore_index=True)
    df.columns = df.columns.str.strip()
    return df


def load_dataset(csv_glob):
    """glob 패턴의 CSV들을 로드·정리해 (특징 배열 X, 라벨 배열)을 돌려준다.
    train과 evaluate가 공유하는 진입점 — 로드+정리 절차를 한 곳에 둔다."""
    return extract_features(load_flows(sorted(glob.glob(csv_glob))))


def extract_features(df):
    """FEATURES 열만 골라 숫자 배열 X와 라벨 배열을 돌려준다.
    Inf/NaN이 든 행은 버린다 (정상 데이터가 많아 드롭으로 충분)."""
    labels = df[LABEL_COLUMN].astype(str).str.strip().to_numpy()
    X = df[FEATURES].apply(pd.to_numeric, errors="coerce")  # 숫자 아닌 값 → NaN
    X = X.replace([np.inf, -np.inf], np.nan)
    keep = ~X.isna().any(axis=1)  # NaN 없는 행만 남긴다
    return X[keep].to_numpy(dtype=np.float64), labels[keep]


def split_benign(X, labels, ratios=(0.6, 0.2, 0.2), seed=42):
    """정상(BENIGN)만 train/val/test로 나눠 돌려준다.
    오토인코더는 정상만 학습하므로 정상을 나눠 쓴다. 공격은 호출자가 라벨로 직접 뽑는다
    (평가는 라벨별 탐지율이 필요해 attack을 여기서 미리 떼어줄 이득이 없다)."""
    benign = X[labels == BENIGN_LABEL]
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(benign))
    n_train = int(len(benign) * ratios[0])
    n_val = int(len(benign) * ratios[1])
    train = benign[idx[:n_train]]
    val = benign[idx[n_train : n_train + n_val]]
    test = benign[idx[n_train + n_val :]]
    return train, val, test
