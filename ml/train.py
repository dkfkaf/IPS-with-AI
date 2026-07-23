"""정상 트래픽으로 오토인코더를 학습하고, 임계값을 정하고, 산출물을 저장한다."""
import argparse
import json
import os

import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler

from ml.features import FEATURES
from ml.model import Autoencoder, reconstruction_errors
from ml.preprocess import load_dataset, split_benign

ARTIFACTS = os.path.join(os.path.dirname(__file__), "artifacts")


def train_model(train_scaled, epochs=30, batch_size=256, lr=1e-3, seed=42):
    """정상 데이터를 '잘 복원'하도록 오토인코더를 학습한다."""
    torch.manual_seed(seed)
    model = Autoencoder(train_scaled.shape[1])
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()
    data = torch.tensor(train_scaled, dtype=torch.float32)
    loader = torch.utils.data.DataLoader(data, batch_size=batch_size, shuffle=True)
    model.train()
    for epoch in range(epochs):
        total = 0.0
        for batch in loader:
            opt.zero_grad()
            loss = loss_fn(model(batch), batch)  # 입력을 얼마나 잘 복원했나
            loss.backward()
            opt.step()
            total += loss.item() * len(batch)
        print(f"epoch {epoch + 1}/{epochs}  loss={total / len(data):.6f}")
    return model


def run(csv_glob, epochs=30, percentile=99.0):
    X, labels = load_dataset(csv_glob)
    train, val, _test = split_benign(X, labels)

    scaler = StandardScaler().fit(train)  # 정규화 기준은 '정상 train'에만 맞춘다 (누수 방지)
    model = train_model(scaler.transform(train), epochs=epochs)

    # 임계값: 정상 val의 복원오차 분포에서 percentile 지점 (정상의 99%가 이 아래)
    val_err = reconstruction_errors(model, scaler.transform(val))
    threshold = float(np.percentile(val_err, percentile))

    os.makedirs(ARTIFACTS, exist_ok=True)
    torch.save(model.state_dict(), os.path.join(ARTIFACTS, "autoencoder.pt"))
    np.savez(os.path.join(ARTIFACTS, "scaler.npz"), mean=scaler.mean_, scale=scaler.scale_)
    with open(os.path.join(ARTIFACTS, "metadata.json"), "w") as f:
        json.dump({"threshold": threshold, "features": FEATURES,
                   "n_features": len(FEATURES), "percentile": percentile}, f, indent=2)
    print(f"저장 완료 → {ARTIFACTS} (임계값={threshold:.6f})")
    return model, scaler, threshold


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="CSV glob 패턴, 예: data/*.csv")
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--percentile", type=float, default=99.0,
                    help="임계값 퍼센타일 (낮출수록 탐지율↑ 오탐률↑)")
    args = ap.parse_args()
    run(args.data, epochs=args.epochs, percentile=args.percentile)
