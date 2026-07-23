"""학습된 산출물로 오탐률(정상 test)과 탐지율(공격)을 잰다."""
import argparse
import glob
import json
import os

import numpy as np
import torch

from ml.model import Autoencoder, reconstruction_errors
from ml.preprocess import extract_features, load_flows, split_benign

ARTIFACTS = os.path.join(os.path.dirname(__file__), "artifacts")


def load_artifacts():
    with open(os.path.join(ARTIFACTS, "metadata.json")) as f:
        meta = json.load(f)
    model = Autoencoder(meta["n_features"])
    model.load_state_dict(torch.load(os.path.join(ARTIFACTS, "autoencoder.pt")))
    sc = np.load(os.path.join(ARTIFACTS, "scaler.npz"))
    return model, sc["mean"], sc["scale"], meta["threshold"]


def _rate_above(model, mean, scale, X, threshold):
    """정규화(추론도 학습과 같은 기준으로) 후, 복원오차가 임계값을 넘는 비율."""
    if len(X) == 0:
        return float("nan")
    err = reconstruction_errors(model, (X - mean) / scale)
    return float((err > threshold).mean())


def run(csv_glob):
    model, mean, scale, threshold = load_artifacts()
    df = load_flows(sorted(glob.glob(csv_glob)))
    X, labels = extract_features(df)
    _train, _val, benign_test, attack = split_benign(X, labels)  # 같은 시드 → 같은 분리

    fp = _rate_above(model, mean, scale, benign_test, threshold)  # 정상인데 넘음 = 오탐
    det = _rate_above(model, mean, scale, attack, threshold)      # 공격을 넘김 = 탐지
    print(f"오탐률(정상 test) = {fp:.3f}")
    print(f"탐지율(공격)      = {det:.3f}")
    return fp, det


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="CSV glob 패턴")
    args = ap.parse_args()
    run(args.data)
