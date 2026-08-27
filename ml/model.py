"""오토인코더: 입력을 좁은 병목(8)으로 압축했다가 다시 복원한다.
정상만 학습하면 정상은 잘 복원하고, 낯선 공격은 복원이 깨져 오차가 커진다."""

import torch
import torch.nn as nn


class Autoencoder(nn.Module):
    def __init__(self, n_features):
        super().__init__()
        # 인코더: n → 16 → 8 (병목). 좁은 병목이 '정상의 핵심 패턴'만 남기고 잡음을 버린다.
        self.encoder = nn.Sequential(
            nn.Linear(n_features, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
        )
        # 디코더: 8 → 16 → n. 병목에서 원래 크기로 되살린다.
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, n_features),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


def reconstruction_errors(model, X):
    """각 행의 복원 오차(MSE = 입력과 출력 차이의 제곱 평균)를 numpy 배열로 돌려준다.
    이 값이 크면 '정상과 다르다'는 뜻."""
    model.eval()
    with torch.no_grad():
        t = torch.tensor(X, dtype=torch.float32)
        out = model(t)
        err = ((out - t) ** 2).mean(dim=1)  # 행(플로우)별 평균제곱오차
    return err.numpy()
