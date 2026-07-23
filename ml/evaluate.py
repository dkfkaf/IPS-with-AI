"""학습된 산출물로 오탐률(정상 test)과 탐지율(공격)을 잰다.
공격은 라벨(DDoS·PortScan·Infiltration 등)별로 쪼개 봐야 진짜 그림이 나온다 —
비지도 이상탐지는 볼류메트릭 공격은 잘, 은밀한 공격은 못 잡기 때문이다."""
import argparse
import json
import os

import numpy as np
import torch

from ml.features import BENIGN_LABEL
from ml.model import Autoencoder, reconstruction_errors
from ml.preprocess import load_dataset, split_benign

ARTIFACTS = os.path.join(os.path.dirname(__file__), "artifacts")


def load_artifacts():
    with open(os.path.join(ARTIFACTS, "metadata.json")) as f:
        meta = json.load(f)
    model = Autoencoder(meta["n_features"])
    model.load_state_dict(torch.load(os.path.join(ARTIFACTS, "autoencoder.pt")))
    sc = np.load(os.path.join(ARTIFACTS, "scaler.npz"))
    return model, sc["mean"], sc["scale"], meta["threshold"]


def _errors(model, mean, scale, X):
    """정규화(추론도 학습과 같은 기준으로) 후 행별 복원오차."""
    return reconstruction_errors(model, (X - mean) / scale)


def run(csv_glob):
    model, mean, scale, threshold = load_artifacts()
    X, labels = load_dataset(csv_glob)
    _train, _val, benign_test = split_benign(X, labels)  # benign_test로 오탐률

    # 오탐률: 정상 test 중 임계값을 넘는 비율 (넘으면 정상인데 공격으로 오판 = 오탐)
    fp = float((_errors(model, mean, scale, benign_test) > threshold).mean())
    print(f"오탐률(정상 test) = {fp:.3f}  (n={len(benign_test)})")

    # 공격: 라벨별 탐지율 (복원오차는 한 번만 계산하고 그룹만 나눈다)
    attack_mask = labels != BENIGN_LABEL
    attack_X = X[attack_mask]
    attack_labels = labels[attack_mask]
    attack_err = _errors(model, mean, scale, attack_X)
    det = float((attack_err > threshold).mean())
    print(f"탐지율(공격 전체) = {det:.3f}  (n={len(attack_X)})")
    print("--- 공격 종류별 ---")
    for label in sorted(set(attack_labels)):
        group = attack_err[attack_labels == label]
        rate = float((group > threshold).mean())
        print(f"  {str(label):<30} {rate:.3f}  (n={len(group)})")
    return fp, det


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="CSV glob 패턴")
    args = ap.parse_args()
    run(args.data)
