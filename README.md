# AI 기반 인라인 IPS

Rule로 확인된 악성 패킷은 즉시 차단하고, AI 이상 판정은 사용자에게 알린 뒤 **판정 적용 이후 동일 출발지 IP의 수신 패킷**을 TTL 동안 차단하는 **인라인(inline) 침입 방지 시스템(IPS)** 입니다. 사이버보안학과 졸업 작품으로 개발합니다.

AI는 이미 전달된 패킷을 소급 차단하지 않습니다. IP 단위 차단이므로 새 연결뿐 아니라 기존 연결의 이후 수신 패킷도 차단 대상입니다.

기존 룰 기반 보안 장비가 탐지하기 어려운 이상 트래픽을 AI로 판별하고, 단순 탐지(IDS)를 넘어 패킷이 목적지에 도달하기 전에 차단까지 수행하는 것을 목표로 합니다.

## 주요 특징

- **하이브리드 구조** — Rule 검사(C++)가 패킷을 즉시 처리하고, 제출 조건을 만족한 종료·타임아웃 플로우를 AI가 비동기로 분석합니다. 별도의 ‘애매함 점수’로 AI 대상을 고르지는 않습니다.
- **플로우 단위 분석** — 패킷을 5-튜플 기준 플로우로 묶어 통계적 특징으로 판단합니다.
- **오토인코더 기반 이상 탐지** — 정상과 다른 플로우를 찾아 학습하지 않은 공격의 탐지 가능성을 실험합니다.
- **오탐 대책** — 화이트리스트와 차단 TTL(자동 해제)로 오차단 영향을 완화합니다. 무중단을 보장하지는 않습니다.

## 시스템 구성

| 구성 요소 | 언어 | 역할 |
| --- | --- | --- |
| 패킷 처리 모듈 | C++ | NFQUEUE로 패킷 수신, 5-튜플 파싱, 플로우 조립, Rule 검사, 차단 |
| AI 분석 엔진 | Python | 종료 플로우의 이상 판정 반환. C++가 알림과 이후 출발지 IP 수신 차단 적용 |
| 상태·알림 UI | C++ (Qt5) | AI 상태 트레이 아이콘, 이상·오프라인 알림, 누적 통계 표시 |

C++ 센서와 Python AI 엔진은 ZeroMQ로 통신하며, 데이터는 JSON으로 주고받습니다.

## 기술 스택

- **패킷 처리**: C++, libnetfilter_queue (NFQUEUE)
- **통신**: ZeroMQ (cppzmq / pyzmq)
- **직렬화·설정**: nlohmann/json
- **로깅**: glog
- **상태·알림 UI**: Qt5 시스템 트레이
- **AI**: Python, PyTorch (오토인코더), pandas, numpy
- **학습 데이터셋**: CICIDS2017

## 빌드 및 실행

> Ubuntu 22.04 이상의 **root GUI 계정으로 로그인한 터미널**에서 실행합니다. 프로그램은
> `geteuid() == 0`이 아니면 즉시 종료하며, 일반 사용자용 `sudo ./ips` 실행은 지원 범위가 아닙니다.

### 의존성 설치

```bash
apt update
apt install cmake build-essential iptables libnetfilter-queue-dev libgoogle-glog-dev \
  nlohmann-json3-dev libzmq3-dev cppzmq-dev qtbase5-dev libgtest-dev \
  python3-pip python3-venv

install -d -m 0755 -o root -g root /opt/ips-with-ai/python-packages
/usr/bin/python3 -m pip install --target /opt/ips-with-ai/python-packages \
  -r ml/runtime-requirements.txt
chown -R root:root /opt/ips-with-ai
chmod -R go-w /opt/ips-with-ai
```

오프라인 학습 환경은 별도 가상환경에서 `ml/requirements.txt`를 사용합니다. 센서가 자동 실행하는
`/usr/bin/python3`은 user site를 읽지 않고, 위의 root 소유 runtime 경로와 저장소의 `ml/`만
읽습니다. 실행 전 `ml/train.py`로 `ml/artifacts`의 모델·스케일러·metadata를 준비해야 합니다.

### 빌드

저장소 루트에서 실행합니다.
저장소는 `/root` 또는 `/opt`처럼 상위 디렉터리까지 root만 수정할 수 있는 위치에 둡니다.

```bash
cp config.example.json config.json
cmake -S . -B build
cmake --build build --target ips -j2
chown root:root .
chmod go-w .
chown -R root:root ml
chmod -R go-w ml
```

빌드는 cppzmq 4.7 이상을 요구합니다. 센서는 root Python이 읽는 저장소 루트·`ml/`·artifact와
runtime package 경로에서 symbolic link, root 이외 소유자, group/other 쓰기 권한을 거부합니다.

### 자동 테스트

runtime 의존성 설치와 CMake configure가 끝난 Ubuntu 저장소 루트에서 실행합니다.

```bash
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

C++ GTest는 설정·플로우·Rule·AI 프로토콜과 비동기 큐를 검증합니다. Python `unittest`는 요청
검증·이상 판정·artifact 계약을 검증하며, root 전용 권한·symbolic link 검사는 root 실행에서만
활성화됩니다. 학습·평가·그래프까지 포함한 전체 Python 테스트는 오프라인 가상환경에서 실행합니다.

```bash
python3 -m venv .venv
.venv/bin/pip install -r ml/requirements.txt
.venv/bin/python -m unittest discover -s tests -p "test_*.py"
```

현재 `test_plot.PlotTest.test_run_uses_loaded_artifact_contract`는 `plot.run()`의 artifact 로더
계약을 수정하기 전까지 실패하는 릴리스 차단 테스트입니다.

NFQUEUE·재시작·Qt 알림은 별도 통합 검증 범위입니다.

### 실행

```bash
./build/ips
```

프로그램은 Python AI를 자동 실행하고 PID 기반 IPC socket을 만듭니다. 시작 실패나 응답 정지 시
1·2·4초 간격으로 최대 3회 재시작하며, 모두 실패하면 Rule-only 모드로 계속 동작합니다. 트레이는
초록(온라인), 회색(시작·재시작·종료), 노랑(비활성·최종 오프라인) 상태를 표시합니다.

`/usr/sbin/iptables`가 필요합니다. 프로그램은 전용 체인 `IPS_WITH_AI`와
소유권 표시가 붙은 INPUT·OUTPUT jump만 관리합니다. 같은 이름의 체인이 있지만 소유권 표시가
없으면 사용자 체인으로 판단해 수정하지 않고 시작을 중단합니다.

강제 종료 후 NFQUEUE listener가 없어지면 `--queue-bypass`가 새 패킷의 해당 큐 진입을 우회합니다.
센서가 살아 있는 동안의 큐 포화에는 적용되지 않습니다. 현재 코드는 queue-full fail-open
플래그를 설정하지 않아, 커널 NFQUEUE가 가득 차면 기본 DROP 동작을 합니다.
자세한 장애별 범위는 [핵심 정책 보완](docs/superpowers/specs/2026-09-12-core-policy-clarification-design.md)의 6장을 참고하세요.
다음 실행은 남은 관리 체인을 정리한 뒤 새 규칙을 한 번만 등록합니다.

실행 중 자동 등록 상태는 다음 명령으로 확인할 수 있습니다.

```bash
iptables -S INPUT
iptables -S OUTPUT
iptables -S IPS_WITH_AI
```

## 문서

| 문서 | 내용 |
| --- | --- |
| [개념 설계](docs/design/overview.md) | 무엇을, 왜 만드는가 |
| [1단계 설계](docs/design/stage1.md) | 패킷 수신·파싱 |
| [2단계 설계](docs/design/stage2.md) | 플로우·Rule·차단 (대응형 IPS) |
| [플로우 특징 토대](docs/design/flow_features.md) | AI 연동 준비 — 양방향 플로우·특징 원재료 |
| [AI 학습 설계](docs/design/ai_training.md) | CICIDS2017 기반 오토인코더 오프라인 학습 |
| [온라인 추론·차단 설계](docs/design/online_inference.md) | 현재 AI 이벤트, 장애 정책, 이후 수신 패킷 TTL 차단 |
| [핵심 정책 보완](docs/superpowers/specs/2026-09-12-core-policy-clarification-design.md) | 차단 범위·로컬 통신·화이트리스트·캡처 입력의 현재 상태와 확장 권장안 |
| [Suricata 장점 확장 설계](docs/superpowers/specs/2026-09-01-suricata-inspired-expansion-design.md) | DNS·Rule·EVE·재조립·L7·IPv6 단계별 확장 |
| [상용 제품 대비](docs/design/commercial_comparison.md) | 상용 IPS/NGFW와의 기능 차이와 프로젝트 범위 |
| [코드 원리](docs/code_explained.md) | 코드가 왜 이렇게 짜였나 (1·2단계) |
| [코딩 스타일](docs/coding_style.md) | 어떻게 짜는가 |

## 개발 로드맵

체크 표시는 코드 존재 여부이며 Linux VM 통합 검증 완료를 뜻하지 않습니다. DNS·PCAP·확장 Rule·
프로토콜 AI는 설계 단계이고, 현재 기능과 구분합니다. 과거 `docs/superpowers/plans/`의 체크박스도
최신 완료 상태나 현재 작업 지시로 사용하지 않습니다.

- [x] **1단계 코드** — 패킷 수신·파싱 (NFQUEUE → 5-튜플)
- [x] **2단계 코드** — 양방향 플로우 조립, Rule 검사, TTL 차단
- [x] **3단계 코드** — AI 자동 실행, 이상 알림, 동일 출발지 후속 패킷 차단
- [x] 오토인코더 학습·온라인 추론 코드
- [x] Qt5 트레이 상태·알림 UI
- [x] C++·Python 자동 단위/계약 테스트 코드
- [ ] 가상환경 공격 시뮬레이션 검증

## 참고

- 공격 시뮬레이션은 반드시 격리된 가상환경에서만 진행합니다.
- 본 프로젝트는 교육·연구 목적의 졸업 작품입니다.

## 참고 문헌
https://maro5397.tistory.com/105
https://rupijun.tistory.com/entry/IPSIntrusion-Protection-System-%EB%84%A4%ED%8A%B8%EC%9B%8C%ED%81%AC-%EC%B9%A8%EC%9E%85-%EC%8B%A4%EC%8B%9C%EA%B0%84-%EC%B0%A8%EB%8B%A8-%EB%B0%8F-%EC%98%88%EB%B0%A9-%EC%8B%9C%EC%8A%A4%ED%85%9C
https://gilgil.gitlab.io/2019/02/11/1.html
https://gilgil.gitlab.io/2019/02/14/1.html
https://gilgil.gitlab.io/2019/02/15/1.html
https://gilgil.gitlab.io/2019/02/20/1.html
https://www.kci.go.kr/kciportal/ci/sereArticleSearch/ciSereArtiView.kci?sereArticleSearchBean.artiId=ART002794059
