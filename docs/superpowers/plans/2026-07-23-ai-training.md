# AI 엔진 오프라인 학습 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** CICIDS2017 정상 트래픽으로 오토인코더를 학습시켜, 복원 오차로 이상을 탐지하는 모델과 산출물(모델·정규화 기준·임계값·특징 목록)을 만든다.

**Architecture:** `ml/` 파이썬 패키지. `preprocess`(CSV 정리·특징 선택·분리) → `model`(오토인코더) → `train`(학습·임계값·저장) → `evaluate`(오탐률·탐지율). 파이썬이라 이 Windows 머신에서 바로 돌아간다. **검증은 진짜 CICIDS2017로 한다** — 별도 테스트용 가짜 데이터는 두지 않는다(YAGNI). 데이터가 오기 전까지 각 모듈은 import 확인(문법·오타)만 하고, 기능 검증은 T6에서 실제 데이터로 몰아서 한다.

**Tech Stack:** Python 3, PyTorch(오토인코더), pandas·numpy(전처리), scikit-learn(정규화·분리).

## Global Constraints

- **이 코드는 Windows에서 바로 돌아간다** (C++와 달리). `pip install`·`python -m ml.train`을 이 머신에서 실행할 수 있다.
- **검증 방식**: 자동 테스트 프레임워크·가짜 데이터는 두지 않는다. 각 모듈은 만든 직후 `python -c "import ml.X"`로 문법·import만 확인한다. 진짜 기능 검증은 T6에서 CICIDS2017을 실제로 돌려 loss·오탐률·탐지율을 눈으로 확인한다.
- **코딩 스타일**(docs/coding_style.md): snake_case 함수·변수, PascalCase 클래스, UPPER_SNAKE 상수, "왜" 주석, ruff(한 줄 100자, import 정렬 I, 이름 N). 초보자 학습용이라 설명 주석을 조금 더 붙이되 과하지 않게.
- **특징 계약**: 학습·추론·C++가 공유하는 특징 목록·**순서**는 `ml/features.py` 한 곳에 둔다.
- **정보 누수 금지**: 정규화 기준(평균·퍼짐)은 **정상 train에만** 맞춘다.
- **결정성**: 난수 시드를 고정한다.
- **아직 커밋 안 함**: 프로젝트 전체가 main에서 미커밋. 검증 후 커밋 판단.
- 설계 근거: `docs/design/ai_training.md`.

## File Structure

```
ml/
├── __init__.py           # 패키지 표시 (빈 파일)          [T1 — 작성됨]
├── features.py           # 특징 목록·순서 계약 (상수)      [T1 — 작성됨]
├── requirements.txt      # torch, pandas, numpy, scikit-learn [T1 — 작성됨]
├── preprocess.py         # CSV 로드·정리·특징 선택·정상/공격 분리 [T2]
├── model.py              # 오토인코더 + 복원오차 계산        [T3]
├── train.py              # 학습 루프 + 임계값 결정 + 산출물 저장 [T4]
├── evaluate.py           # 오탐률·탐지율 측정                [T5]
└── artifacts/            # 산출물 저장 (학습 시 생성)        [T4]
```

**공유 계약 (`ml/features.py`, 작성 완료):** 27개 특징 목록·순서. 실제 CSV 헤더를 받으면 철자를 대조해 확정(T6).

---

## Task 1: 패키지 뼈대 + 특징 계약  — **작성 완료**

`ml/__init__.py`, `ml/features.py`(FEATURES 27개·LABEL_COLUMN·BENIGN_LABEL), `ml/requirements.txt`는 이미 작성됨.

- [ ] **확인**: 졸업작품 폴더에서 `pip install -r ml/requirements.txt` 후
  `python -c "import ml.features; print(len(ml.features.FEATURES))"` → `27` 출력.
- [ ] **커밋**:
```bash
git add ml/__init__.py ml/features.py ml/requirements.txt
git commit -m "feat(ml): package skeleton and feature contract

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: 전처리 (preprocess.py)

**Files:** Create `ml/preprocess.py`

**Interfaces:**
- Consumes: `ml/features.py`.
- Produces: `load_flows(csv_paths) -> DataFrame`, `extract_features(df) -> (X: np.ndarray, labels: np.ndarray)`, `split_benign(X, labels, ratios, seed) -> (train, val, test, attack)`.

- [ ] **Step 1: preprocess.py 작성**

```python
"""CSV를 읽어 정리하고, 학습에 쓸 특징 배열과 라벨을 뽑는다."""
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


def extract_features(df):
    """FEATURES 열만 골라 숫자 배열 X와 라벨 배열을 돌려준다.
    Inf/NaN이 든 행은 버린다 (정상 데이터가 많아 드롭으로 충분)."""
    labels = df[LABEL_COLUMN].astype(str).str.strip().to_numpy()
    X = df[FEATURES].apply(pd.to_numeric, errors="coerce")  # 숫자 아닌 값 → NaN
    X = X.replace([np.inf, -np.inf], np.nan)
    keep = ~X.isna().any(axis=1)  # NaN 없는 행만 남긴다
    return X[keep].to_numpy(dtype=np.float64), labels[keep]


def split_benign(X, labels, ratios=(0.6, 0.2, 0.2), seed=42):
    """정상(BENIGN)만 train/val/test로 나누고, 공격은 따로 모아 돌려준다.
    오토인코더는 정상만 학습하므로 정상을 나눠 쓰고, 공격은 평가에만 쓴다."""
    benign = X[labels == BENIGN_LABEL]
    attack = X[labels != BENIGN_LABEL]
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(benign))
    n_train = int(len(benign) * ratios[0])
    n_val = int(len(benign) * ratios[1])
    train = benign[idx[:n_train]]
    val = benign[idx[n_train:n_train + n_val]]
    test = benign[idx[n_train + n_val:]]
    return train, val, test, attack
```

- [ ] **Step 2: import 확인 + 커밋**

Run: `python -c "import ml.preprocess"` (에러 없으면 OK — 기능 검증은 T6)
```bash
git add ml/preprocess.py
git commit -m "feat(ml): preprocessing (load, clean, feature select, benign split)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: 오토인코더 모델 (model.py)

**Files:** Create `ml/model.py`

**Interfaces:**
- Produces: `class Autoencoder(nn.Module)` (`__init__(n_features)`, `forward(x)`), `reconstruction_errors(model, X: np.ndarray) -> np.ndarray` (행별 MSE).

- [ ] **Step 1: model.py 작성**

```python
"""오토인코더: 입력을 좁은 병목(8)으로 압축했다가 다시 복원한다.
정상만 학습하면 정상은 잘 복원하고, 낯선 공격은 복원이 깨져 오차가 커진다."""
import torch
import torch.nn as nn


class Autoencoder(nn.Module):
    def __init__(self, n_features):
        super().__init__()
        # 인코더: n → 16 → 8 (병목). 좁은 병목이 '정상의 핵심 패턴'만 남기고 잡음을 버린다.
        self.encoder = nn.Sequential(
            nn.Linear(n_features, 16), nn.ReLU(),
            nn.Linear(16, 8), nn.ReLU(),
        )
        # 디코더: 8 → 16 → n. 병목에서 원래 크기로 되살린다.
        self.decoder = nn.Sequential(
            nn.Linear(8, 16), nn.ReLU(),
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
```

- [ ] **Step 2: import 확인 + 커밋**

Run: `python -c "import ml.model"` (OK면)
```bash
git add ml/model.py
git commit -m "feat(ml): autoencoder model + per-row reconstruction error

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: 학습 + 임계값 + 산출물 저장 (train.py)

**Files:** Create `ml/train.py`

**Interfaces:**
- Consumes: `preprocess`, `model`, `features`, `sklearn.preprocessing.StandardScaler`.
- Produces: `train_model(train_scaled, epochs, ...) -> Autoencoder`, `run(csv_glob, epochs, percentile) -> (model, scaler, threshold)`. 산출물: `ml/artifacts/autoencoder.pt`, `scaler.npz`, `metadata.json`.

- [ ] **Step 1: train.py 작성**

```python
"""정상 트래픽으로 오토인코더를 학습하고, 임계값을 정하고, 산출물을 저장한다."""
import argparse
import glob
import json
import os

import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler

from ml.features import FEATURES
from ml.model import Autoencoder, reconstruction_errors
from ml.preprocess import extract_features, load_flows, split_benign

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
    df = load_flows(sorted(glob.glob(csv_glob)))
    X, labels = extract_features(df)
    train, val, _test, _attack = split_benign(X, labels)

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
    args = ap.parse_args()
    run(args.data, epochs=args.epochs)
```

- [ ] **Step 2: import 확인 + 커밋**

Run: `python -c "import ml.train"` (OK면)
```bash
git add ml/train.py
git commit -m "feat(ml): training loop, threshold selection, artifact saving

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: 평가 (evaluate.py)

**Files:** Create `ml/evaluate.py`

**Interfaces:**
- Consumes: 산출물, `preprocess`, `model`.
- Produces: `load_artifacts() -> (model, mean, scale, threshold)`, `run(csv_glob) -> (fp_rate, detection_rate)`.

- [ ] **Step 1: evaluate.py 작성**

```python
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
```

- [ ] **Step 2: import 확인 + 커밋**

Run: `python -c "import ml.evaluate"` (OK면)
```bash
git add ml/evaluate.py
git commit -m "feat(ml): evaluation (false-positive and detection rates)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: 진짜 CICIDS2017로 학습·평가 (데이터 준비되면) — **메인 검증**

**Files:** 없음 (실제 데이터로 실행). CICIDS2017 CSV를 예: `data/` 폴더에 둔다.

- [ ] **Step 1: 컬럼 이름 대조**

받은 CSV의 헤더를 확인한다:
```
python -c "import pandas as pd; print([c.strip() for c in pd.read_csv('data/Monday-WorkingHours.pcap_ISCX.csv', nrows=1).columns])"
```
`ml/features.py`의 `FEATURES` 27개와 철자를 대조해, 다른 것이 있으면 `FEATURES`를 실제 헤더에 맞춰 고친다(별도 커밋).

- [ ] **Step 2: 학습 실행**

```
python -m ml.train --data "data/*.csv" --epochs 30
```
Expected: epoch마다 loss가 줄고, `ml/artifacts/`에 산출물 3개 생성, 임계값 출력.

- [ ] **Step 3: 평가 실행**

```
python -m ml.evaluate --data "data/*.csv"
```
Expected: 오탐률·탐지율 출력. 오탐률이 임계값(99퍼센타일)에 맞게 ~1% 근처인지, 탐지율이 유의미한지 확인.

- [ ] **Step 4: 결과 기록 + 조정**

오탐률·탐지율(공격 종류별로도)을 기록한다. 탐지율이 낮으면 임계값 퍼센타일을 낮추거나(예: 95) epoch를 늘려 재실험. 이 수치가 발표의 핵심 결과다.

---

## Self-Review 결과

- **스펙 커버리지**: 설계 4장(특징)→T1, 5장(데이터셋 함정: 컬럼 공백·NaN/Inf)→T2 정리 로직, 6장(파이프라인)→T2~T4, 7장(모델)→T3, 8장(임계값)→T4, 9장(평가)→T5, 10장(산출물)→T4 저장, 11장(파일배치)→전체. 12장(미루는 것)은 계획에 안 넣음(의도적).
- **가짜 데이터 없음**: 사용자 요청대로 테스트용 합성 데이터·pytest를 제거. 검증은 T6에서 실제 CICIDS2017로. 각 모듈은 import 확인만.
- **Placeholder 스캔**: 없음. 모든 스텝에 실제 코드. FEATURES 컬럼 철자만 실제 CSV로 확정(T6 Step1) — 데이터가 없으니 불가피, 명시적 태스크로 뒀음.
- **타입 일관성**: `load_flows(paths)->df`, `extract_features(df)->(X,labels)`, `split_benign->(train,val,test,attack)`, `Autoencoder(n_features)`, `reconstruction_errors(model,X)->np.ndarray`, `run()` 시그니처 일치. 산출물 파일명(autoencoder.pt/scaler.npz/metadata.json)과 로드가 일치.
