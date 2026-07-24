# AI 기반 인라인 IPS

AI가 악성으로 판단한 네트워크 패킷을 실시간으로 차단하는 **인라인(inline) 침입 방지 시스템(IPS)** 입니다. 사이버보안학과 졸업 작품으로 개발합니다.

기존 룰 기반 보안 장비가 탐지하기 어려운 이상 트래픽을 AI로 판별하고, 단순 탐지(IDS)를 넘어 패킷이 목적지에 도달하기 전에 차단까지 수행하는 것을 목표로 합니다.

## 주요 특징

- **하이브리드 구조** — 빠른 Rule 기반 1차 검사(C++)가 대부분의 트래픽을 인라인 경로에서 즉시 처리하고, 판단이 애매한 플로우만 AI 엔진으로 비동기 전달하여 처리 지연을 최소화합니다.
- **플로우 단위 분석** — 패킷을 5-튜플 기준 플로우로 묶어 통계적 특징으로 판단합니다.
- **오토인코더 기반 이상 탐지** — 정상 트래픽을 학습해 신종 공격(제로데이)까지 탐지합니다.
- **오탐 대책** — 화이트리스트와 차단 TTL(자동 해제)로 정상 서비스 마비를 방지합니다.

## 시스템 구성

| 구성 요소 | 언어 | 역할 |
| --- | --- | --- |
| 패킷 처리 모듈 | C++ | NFQUEUE로 패킷 수신, 5-튜플 파싱, 플로우 조립, Rule 검사, 차단 |
| AI 분석 엔진 | Python | 오토인코더로 이상 트래픽 판정 |
| 관리 대시보드 | C++ (Qt) | 트래픽·차단 현황 실시간 시각화 |

C++ 센서와 Python AI 엔진은 ZeroMQ로 통신하며, 데이터는 JSON으로 주고받습니다.

## 기술 스택

- **패킷 처리**: C++, libnetfilter_queue (NFQUEUE)
- **통신**: ZeroMQ (cppzmq / pyzmq)
- **직렬화·설정**: nlohmann/json
- **로깅**: glog
- **대시보드**: Qt
- **AI**: Python, PyTorch (오토인코더), pandas, numpy
- **학습 데이터셋**: CICIDS2017

## 빌드 및 실행

> 리눅스 환경(Ubuntu)을 기준으로 합니다. NFQUEUE 사용에는 root 권한이 필요합니다.

### 의존성 설치

```bash
# 패킷 처리 관련
sudo apt install libnetfilter-queue-dev libgoogle-glog-dev

# 개발 도구
sudo apt install clang-format cmake build-essential

# Python (AI 엔진)
pip install pyzmq torch pandas numpy ruff
```

### 빌드

```bash
mkdir build && cd build
cmake ..
make
```

### 실행 (1단계 — 수신·파싱·로그)

```bash
# 0) (선택) 파서 단독 테스트 — root 권한 없이 파싱 로직만 검증
./parser_test

# 1) 트래픽을 NFQUEUE 0번 큐로 보내는 iptables 규칙 추가
#    --queue-bypass: ips가 꺼져 있을 때 패킷을 그냥 통과시킴 (자기 접속 차단 사고 방지)
sudo iptables -I INPUT -j NFQUEUE --queue-num 0 --queue-bypass

# 2) IPS 실행 — 통과하는 패킷의 5-튜플이 로그로 출력됨 (Ctrl+C로 종료)
sudo ./ips

# 3) 테스트 후 규칙 제거
sudo iptables -D INPUT -j NFQUEUE --queue-num 0 --queue-bypass
```

> 개발 중에는 `-p tcp --dport 8080` 처럼 특정 트래픽만 큐로 보내면 안전하게 실험할 수 있습니다.

## 문서

| 문서 | 내용 |
| --- | --- |
| [개념 설계](docs/design/overview.md) | 무엇을, 왜 만드는가 |
| [1단계 설계](docs/design/stage1.md) | 패킷 수신·파싱 |
| [2단계 설계](docs/design/stage2.md) | 플로우·Rule·차단 (대응형 IPS) |
| [플로우 특징 토대](docs/design/flow_features.md) | AI 연동 준비 — 양방향 플로우·특징 원재료 |
| [코드 원리](docs/code_explained.md) | 코드가 왜 이렇게 짜였나 (1·2단계) |
| [코딩 스타일](docs/coding_style.md) | 어떻게 짜는가 |

## 개발 로드맵

- [ ] **1단계** — 패킷 수신·파싱 (NFQUEUE → 5-튜플 → 로그)
- [ ] **2단계** — 플로우 조립, Rule 검사, 차단 기능 (대응형 IPS)
- [ ] **3단계** — 인라인 구조 전환, 실시간 차단 (인라인 IPS)
- [ ] AI 분석 엔진 (오토인코더)
- [ ] 관리 대시보드 (Qt)
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
