# 기존 코드 안정화 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 기존 ML 오류와 CI 구성을 수정하고, 자동 테스트·데이터 분할 점검 결과와 Linux 미검증 항목을 구분한다.

**Architecture:** 기존 공개 함수와 27개 특징·schema 1·차단 정책은 유지한다. 그래프 생성은 공통
artifact 객체를 사용한다. 분할 점검은 기존 분할과 같은 행 인덱스를 사용하고, 데이터 출처·seed·
분할 지문·동일 특징 중복을 보고한다. 날짜·세션 분할로 몰래 전환하지 않는다.

**Tech Stack:** C++17/CMake/GTest, Python unittest/NumPy/pandas/PyTorch, GitHub Actions.

**Spec:** [핵심 정책 보완 8장](../specs/2026-09-12-core-policy-clarification-design.md),
[확장 설계 단계 0](../specs/2026-09-01-suricata-inspired-expansion-design.md).

## Global Constraints

- 사용자 승인에 따라 현재 폴더의 main에서 직접 수정한다. 별도 작업 폴더는 만들지 않는다.
  구현은 직접 수행하고, 완료 전 읽기 전용 코드 리뷰를 분리한다.
- 새 캡처·DNS·AI 대응 기능은 추가하지 않는다. 외부 라이브러리 의존성은 늘리지 않는다.
- 공개 함수 인자·반환값·기존 오류 메시지는 유지한다. 코드 포맷 일괄 변경을 섞지 않는다.
- Windows에는 Linux 빌드 도구·WSL이 없다. Kali 듀얼 부팅 후 C++·NFQUEUE·root GUI를 검증한다.
- 실제 CICIDS2017 CSV 경로가 제공되기 전에는 데이터 누수 검증 완료로 보고하지 않는다.

## Task 1: 그래프 artifact 계약 복구

**Files:** `ml/plot.py`, `tests/test_plot.py`.

**Interfaces:** `run(csv_glob)` → 기존처럼 PNG 3개 저장·메시지 출력·`None` 반환.
`load_artifacts(ARTIFACTS)` → `LoadedArtifacts`.

- [x] 기존 `test_run_uses_loaded_artifact_contract` 실패를 재현한다.
- [x] 회귀 테스트를 실제 artifact·CSV·PNG 검증으로 보강한다. 파일 경로만 임시 디렉터리로 바꾼다.
  실제 출력 PNG signature `b"\x89PNG\r\n\x1a\n"`, 파일 세 개, 완료 메시지를 확인한다.
- [x] 경로 전달과 객체 접근만 수정한다.

```python
artifacts = load_artifacts(ARTIFACTS)
attack_errors = normalized_reconstruction_errors(
    artifacts.model, artifacts.mean, artifacts.scale, feature_matrix[attack_mask]
)
```

정상 오류 계산도 같은 객체를 사용하고 그래프에 `artifacts.threshold`를 전달한다.

- [x] `.venv/Scripts/python.exe -m unittest discover -s tests -p test_plot.py` 재실행 후
  전체 `test_*.py`를 실행한다. Linux에서는 `.venv/bin/python`을 사용한다.

## Task 2: 기존 데이터 분할 점검

**Files:** `ml/preprocess.py`, `ml/audit_dataset.py`, `tests/test_preprocess.py`,
`tests/test_audit_dataset.py`.

**Interfaces:** 기존 `split_benign(feature_matrix, labels, ratios, seed)` 유지.
추가 `split_benign_indices(labels, ratios=(0.6, 0.2, 0.2), seed=42)`는 원본 행 인덱스 3개 배열을 반환한다.
`audit_dataset(csv_glob)`는 JSON 직렬화 가능한 검증 보고서를 반환한다.

- [x] seed가 고정된 수작업 인덱스 기대값, 공격 제외, 분할 교집합 없음, 전체 정상 행 포함을 검사한다.
- [x] 기존 permutation 로직을 인덱스 함수로 추출하고 기존 분할은 다음처럼 참조한다.

```python
return tuple(feature_matrix[indices] for indices in split_benign_indices(labels, ratios, seed))
```

- [x] 임시 CSV로 재현성·파일 변경 감지·분할 간 동일 특징·유효 행 집계·빈 입력 실패를 검사한다.
- [x] 점검 보고서에는 입력 파일 SHA-256, 특징/schema, seed/ratios, split별 크기·인덱스 SHA-256,
  분할 간 동일 특징 벡터 수와 `group_isolation=not_checked`를 기록한다.
  동일 특징은 잠재적 누수 신호이지 동일 세션의 확정 증거가 아니다.
- [x] CLI `python -m ml.audit_dataset --data 'data/*.csv' --output split_audit.json`은 보고서를
  새 파일에 저장한다. 기존 파일을 덮어쓰지 않는다. 날짜·세션 누수 없음으로 판정하지 않는다.
- [x] 관련 테스트와 전체 Python 테스트를 실행한다. 실제 CSV가 없어 실제 데이터 CLI 검증은 보류한다.

## Task 3: CI 실행 경로·의존성·테스트 복구

**Files:** `.github/my_ci_cd.yml` → `.github/workflows/my_ci_cd.yml`, 필요 시 Python
테스트의 실제 lint 오류 위치만 수정한다.

- [x] 기존 파일의 경로와 CMake 필수 패키지 누락을 확인한다.
- [x] GitHub 인식 위치로 옮기고 Python 전체 테스트를 추가한다.
  Python job: `python -m pip install -r ml/requirements.txt bandit`,
  `python -m ruff check .`, `bandit -r ml -ll`,
  `python -m unittest discover -s tests -p 'test_*.py'`.
- [x] C++ job에 `libnetfilter-queue-dev libgoogle-glog-dev nlohmann-json3-dev libzmq3-dev
  cppzmq-dev qtbase5-dev libgtest-dev pkg-config`와 기존 빌드·분석 도구를 설치한다.
  CTest가 사용할 Python에도 `ml/runtime-requirements.txt`를 설치하고 configure에서 interpreter를 지정한다.
- [x] `cmake --build build`와 `ctest --test-dir build --output-on-failure`를 유지한다.
  root 권한 테스트는 안전한 root 소유 checkout 사본에서 별도로 실행한다.
- [x] YAML 구조 검증과 로컬 Python 검사를 수행한다. GitHub Actions 실제 실행은 미실행으로 남긴다.

## Task 4: 검증 기록과 Kali 실행 안내

**Files:** `README.md`, `docs/validation/2026-09-15-baseline.md`, 해당 설계 문서의 현재 상태 문장.

- [x] Python 버전·패키지 버전·실패 재현·수정 뒤 테스트 수·skip 사유·lint 결과를 기록한다.
- [x] Kali에서 필요한 패키지·venv·CMake·CTest 명령을 제공한다. 자동 테스트에 센서 실행은 필요 없다.
- [x] root 권한 검사는 root 소유 Linux 파일시스템 경로에서, NFQUEUE·Qt·부하 측정은 격리된
  실험 네트워크에서 별도로 수행하도록 구분한다. 일반 네트워크에 공격 트래픽을 보내지 않는다.
- [x] 데이터 부재, Linux 미실행, 실제 CI 미실행을 남겨 완료 범위를 과장하지 않는다.
- [x] `git diff --check`와 변경 범위 검토 후 사용자에게 결과를 전달한다.
