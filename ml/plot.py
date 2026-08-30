"""학습된 모델로 발표용 그래프 3장을 그린다 (파일로만 저장, 화면 안 씀).
  1) 복원오차 분포 (정상 vs 공격)  2) 공격 종류별 탐지율  3) ROC 곡선 + AUC
결과: ml/artifacts/plots/*.png.  사용법: python -m ml.plot --data "data/*.csv"
"""

import argparse
import os

import matplotlib
import numpy as np

matplotlib.use("Agg")  # 창 없이 PNG로만 저장 (백그라운드·서버에서도 동작)
import matplotlib.pyplot as plt  # noqa: E402  (use()를 pyplot import 전에 불러야 함)
from sklearn.metrics import roc_auc_score, roc_curve  # noqa: E402

from ml.evaluate import ARTIFACTS, load_artifacts  # noqa: E402
from ml.features import BENIGN_LABEL  # noqa: E402
from ml.model import reconstruction_errors  # noqa: E402
from ml.preprocess import load_dataset, split_benign  # noqa: E402

# 한글 라벨이 깨지지 않게 Windows 기본 한글 폰트 사용
matplotlib.rcParams["font.family"] = "Malgun Gothic"
matplotlib.rcParams["axes.unicode_minus"] = False

PLOTS = os.path.join(ARTIFACTS, "plots")


def _errors(model, mean, scale, feature_matrix):
    """추론도 학습과 같은 기준으로 정규화 후 복원오차."""
    return reconstruction_errors(model, (feature_matrix - mean) / scale)


def _plot_error_distribution(benign_err, attack_err, threshold, path):
    """정상 vs 공격의 복원오차 분포. 정상은 왼쪽(작음), 공격은 오른쪽(큼)으로 갈리고
    임계값 선이 그 사이를 가른다 — 오토인코더 원리를 한 장으로 보여준다."""
    hi = float(np.percentile(attack_err, 99))  # 꼬리값에 눌리지 않게 상한 컷
    bins = np.linspace(0, hi, 80)
    plt.figure(figsize=(8, 5))
    plt.hist(np.clip(benign_err, 0, hi), bins=bins, density=True, alpha=0.6, label="정상")
    plt.hist(np.clip(attack_err, 0, hi), bins=bins, density=True, alpha=0.6, label="공격")
    plt.axvline(threshold, color="red", linestyle="--", label=f"임계값 {threshold:.3f}")
    plt.yscale("log")  # 정상이 압도적으로 많아 로그로 봐야 둘 다 보임
    plt.xlabel("복원 오차")
    plt.ylabel("밀도 (로그)")
    plt.title("복원 오차 분포: 정상 vs 공격")
    plt.legend()
    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close()


def _plot_detection_by_type(attack_err, attack_labels, threshold, path):
    """공격 종류별 탐지율 막대. 볼류메트릭(DoS/DDoS)은 높고 은밀한 것은 낮게 갈린다."""
    types = sorted(set(attack_labels))
    rates = [float((attack_err[attack_labels == t] > threshold).mean()) for t in types]
    plt.figure(figsize=(9, 6))
    y = np.arange(len(types))
    plt.barh(y, rates, color="steelblue")
    plt.yticks(y, [str(t) for t in types])
    plt.xlabel("탐지율")
    plt.xlim(0, 1)
    plt.title("공격 종류별 탐지율")
    for i, r in enumerate(rates):
        plt.text(r + 0.01, i, f"{r:.2f}", va="center")
    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close()


def _plot_roc(benign_err, attack_err, threshold, path):
    """ROC 곡선 + AUC. 복원오차를 점수로 본 이진 판별 성능. 현재 임계값 지점도 표시."""
    y_true = np.concatenate([np.zeros(len(benign_err)), np.ones(len(attack_err))])
    scores = np.concatenate([benign_err, attack_err])
    auc = roc_auc_score(y_true, scores)
    fpr, tpr, _ = roc_curve(y_true, scores)
    cur_fpr = float((benign_err > threshold).mean())
    cur_tpr = float((attack_err > threshold).mean())
    plt.figure(figsize=(6, 6))
    plt.plot(fpr, tpr, label=f"ROC (AUC={auc:.3f})")
    plt.plot([0, 1], [0, 1], "k--", alpha=0.4, label="무작위")
    plt.scatter(
        [cur_fpr],
        [cur_tpr],
        color="red",
        zorder=5,
        label=f"현재 임계값 (오탐 {cur_fpr:.2f}, 탐지 {cur_tpr:.2f})",
    )
    plt.xlabel("오탐률 (False Positive Rate)")
    plt.ylabel("탐지율 (True Positive Rate)")
    plt.title("ROC 곡선")
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(path, dpi=120)
    plt.close()


def run(csv_glob):
    """평가 데이터로 발표용 그래프 세 장을 생성해 artifacts 아래에 저장한다."""
    model, mean, scale, threshold = load_artifacts()
    feature_matrix, labels = load_dataset(csv_glob)
    _train, _val, benign_test = split_benign(feature_matrix, labels)
    attack_mask = labels != BENIGN_LABEL
    attack_errors = _errors(model, mean, scale, feature_matrix[attack_mask])
    benign_errors = _errors(model, mean, scale, benign_test)

    os.makedirs(PLOTS, exist_ok=True)
    _plot_error_distribution(
        benign_errors, attack_errors, threshold, os.path.join(PLOTS, "error_distribution.png")
    )
    _plot_detection_by_type(
        attack_errors,
        labels[attack_mask],
        threshold,
        os.path.join(PLOTS, "detection_by_type.png"),
    )
    _plot_roc(benign_errors, attack_errors, threshold, os.path.join(PLOTS, "roc.png"))
    print(f"그래프 3장 저장 완료 → {PLOTS}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="CSV glob 패턴")
    args = parser.parse_args()
    run(args.data)
