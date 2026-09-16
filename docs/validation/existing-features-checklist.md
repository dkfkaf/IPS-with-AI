# 기존 기능 검증 실행 안내

작성 기준: 2026-09-16의 소스와 테스트. 이 문서는 **앞으로 실행할 절차**이며 Kali 검증 완료 보고서가 아니다.
이전 Windows 결과는 [안정화 기록](2026-09-15-baseline.md)에 있다.

## 1. 무엇을 어떤 순서로 확인하나

| ID | 확인할 것 | 실행 위치 | 완료 증거 |
| --- | --- | --- | --- |
| V01 | 소스·환경·설정 식별 | Kali 센서 | 커밋, 변경 diff, OS·도구 버전 |
| V02 | C++ 빌드·CTest | Kali 센서 | 모든 등록 테스트 통과 로그 |
| V03 | Python 전체·root 권한·정적 검사 | Kali 센서 | 실패 0, root 테스트 skip 0, Ruff/Bandit 결과 |
| V04 | runtime·artifact·AI 시작 | Kali root GUI | 실제 실행 Python import 성공, ONLINE·모델 버전 |
| V05 | NFQUEUE 등록·정상 통신·정상 종료 | 센서 + 시험 장비 | 규칙 전후 diff, HTTP 성공, 종료 코드 |
| V06 | 포트 스캔·SYN Rule | 센서 + 시험 장비 | Rule 이름, TTL 등록, 실제 HTTP 차단 |
| V07 | TTL·화이트리스트·통신 방향 | 센서 + 시험 장비 | 만료 후 복구, 예외 IP 통과, 로컬 시작 제외 |
| V08 | AI 이상 → 실제 차단·Qt 팝업 | 센서 + 시험 장비 | AI_DECISION, 점수·임계값, 팝업, 후속 요청 차단 |
| V09 | AI 장애·3회 재시작·Rule-only | 센서 + 시험 장비 | 재시작 횟수·timeout·OFFLINE, Rule 동작 |
| V10 | 큐 포화·센서 강제 종료·재실행 | 센서 + 시험 장비 | AI 큐/커널 큐 구분, bypass, 규칙 중복 없음 |
| V11 | 실데이터 분할·학습·평가 | 학습용 venv | CSV 지문, 분할 보고서, 성능·모델 지문 |
| V12 | 학습 특징과 실시간 특징 일치 | 센서 + 분석 환경 | 동일 통신의 27개 특징 비교표 |
| V13 | 처리량·지연·메모리 기준선 | 센서 + 시험 장비 | 조건별 원시 기록·성공률·p50/p95 |
| V14 | GitHub Actions 실제 실행 | GitHub | 동일 변경의 두 job 성공 URL·커밋 |

V01~V03을 먼저 한다. V04~V10은 연동 검증이고, V11~V13은 데이터·성능 검증이다.
V14는 Kali 검증과 별도로 실행할 수 있다. 실패하면 해당 로그를 보존하고 원인을 고친 뒤
그 항목과 영향받는 항목을 다시 실행한다. 자료가 없거나 재현되지 않은 항목은 `미검증`으로 남긴다.

## 2. 실험 준비와 공통 규칙 — V01

### 실행 위치

- **센서:** Kali의 root GUI 로그인 터미널. 예시 저장소 경로는 `/opt/ips-with-ai-src`.
- **시험 장비:** 센서와 격리된 실험망으로 연결한 VM 또는 별도 Linux 장비.
- 예시 주소는 센서 `192.168.56.10`, 시험 장비 `192.168.56.20`이다. 실제 실험 인터페이스의
  주소로 바꾼다. NAT로 출발지 주소가 바뀌면 센서에서 관찰한 주소를 기준으로 기록한다.
- 설치는 인터넷 연결 상태에서 마치고, 패킷 실험은 실험 인터페이스만 사용하는 상태에서 한다.
  이 프로그램은 인터페이스 필터 없이 호스트 INPUT/OUTPUT에 등록된다. 다른 업무망 연결도
  함께 시험 대상이 되지 않도록 한다. FORWARD를 지나는 다른 호스트의 중계 트래픽은 현재 대상이 아니다.

Windows 소스의 **미커밋 변경과 새 파일까지** 복사한다. `git clone`만 하면 로컬 변경은 따라오지
않는다. Windows `.venv`와 `build`는 복사하지 않는다. 기존 대상 폴더에 덮어쓰지 말고 내용을 확인한다.
root 소유 Linux 파일시스템에 새 복사본을 준비하고 `namei -l /opt/ips-with-ai-src/ml`로 상위 경로도 확인한다.

센서의 Bash에서 실행한다. `RUN`은 이 터미널에서 계속 쓰는 결과 폴더다.

```bash
cd /opt/ips-with-ai-src
test "$(id -u)" -eq 0
umask 077
RUN=$(mktemp -d /opt/ips-validation.XXXXXX)
export RUN
printf '%s\n' "$RUN"
set -o pipefail
uname -a | tee "$RUN/kernel.txt"
cat /etc/os-release | tee "$RUN/os.txt"
git rev-parse HEAD | tee "$RUN/commit.txt"
git status --short | tee "$RUN/worktree.txt"
git diff --binary > "$RUN/changes.patch"
git ls-files --others --exclude-standard > "$RUN/untracked.txt"
ip -br address | tee "$RUN/interfaces.txt"
iptables --version | tee "$RUN/iptables-version.txt"
iptables-save > "$RUN/firewall-before.rules"
if [ -e config.json ]; then cp -a config.json "$RUN/config.original.json"; fi
```

`git diff`에 새 파일 내용은 들어가지 않는다. `untracked.txt`에 적힌 소스·테스트·워크플로도
결과 자료와 함께 보관한다. 모든 명령의 오류를 확인하고, 실패한 상태에서 다음 블록을 실행하지 않는다.
다른 터미널에서는 위에서 출력한 실제 경로로 `export RUN=/opt/ips-validation.XXXXXX`를 설정한다.

시험 장비에도 `SENSOR=192.168.56.10`을 설정한다. `ip route get "$SENSOR"`로 실험망 경로인지 확인한다.
각 시나리오마다 센서를 정상 종료하고 다시 시작해 이전 차단·Rule 통계가 다음 시험에 섞이지 않게 한다.
설정은 시작 시 읽는다. 실행 중 `config.json`을 바꿔도 즉시 반영되지 않는다.

## 3. 빌드와 자동 테스트 — V02·V03

센서에서 필요한 패키지를 설치한다.

```bash
apt update
apt install -y build-essential cmake pkg-config iptables \
  libnetfilter-queue-dev libgoogle-glog-dev nlohmann-json3-dev \
  libzmq3-dev cppzmq-dev qtbase5-dev libgtest-dev \
  python3-pip python3-venv clang clang-tidy ninja-build \
  curl tcpdump procps sysstat
python3 -m venv .venv
.venv/bin/python -m pip install 'torch>=2.1' --index-url https://download.pytorch.org/whl/cpu
.venv/bin/python -m pip install -r ml/requirements.txt bandit
.venv/bin/python -m pip freeze > "$RUN/python-packages.txt"
cmake --version | tee "$RUN/cmake-version.txt"
c++ --version | tee "$RUN/compiler-version.txt"
cmake -S . -B build -DPython3_EXECUTABLE="$PWD/.venv/bin/python" 2>&1 | tee "$RUN/configure.log"
cmake --build build -j2 2>&1 | tee "$RUN/build.log"
ctest --test-dir build -N | tee "$RUN/ctest-list.txt"
ctest --test-dir build --output-on-failure 2>&1 | tee "$RUN/ctest.log"
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v 2>&1 | tee "$RUN/python-tests.log"
.venv/bin/python -m unittest tests.test_artifacts -v 2>&1 | tee "$RUN/root-artifacts.log"
.venv/bin/python -m ruff check . 2>&1 | tee "$RUN/ruff.log"
.venv/bin/python -m bandit -r ml -ll 2>&1 | tee "$RUN/bandit.log"
```

**합격 기준:** 각 명령이 종료 코드 0으로 끝나야 한다. `tee`가 있는 명령은 바로 다음에
`echo "${PIPESTATUS[0]}"`를 실행하면 원래 검사 명령의 종료 코드를 확인할 수 있다.

**정상 결과:** CTest 등록 항목은 현재 아래 9개이며, 각 GTest 안에는 여러 테스트가 있다.
`ctest -N`만 실행한 것은 테스트 통과가 아니다. 전체 Python 테스트는 작성 당시 41개이며
Kali root 실행에서는 권한 검사 두 개도 실행되어야 한다. 최신 코드에서 개수가 바뀌면 실제 개수를 기록한다.
CTest의 Python 검사에는 `/opt/ips-with-ai/python-packages`가 검색 경로에 추가된다. 이 경로에
기존 패키지가 있다면 venv와 다른 버전이 로드될 수 있으므로 runtime 버전도 V04에서 기록한다.

| 테스트 | 확인하는 내용 |
| --- | --- |
| `parser_test` | IP/TCP/UDP 패킷 파싱 |
| `block_list_test` | 차단 등록·만료·갱신 |
| `flow_manager_test` | 양방향 통계·시간 창·저장 상한 |
| `config_test` | 설정 타입·범위·화이트리스트 |
| `rule_test` | 포트 수·SYN 수 임계값 |
| `flow_features_test` | 27개 특징 순서·값·종료 사유 |
| `ai_protocol_test` | 요청 직렬화·응답 식별·잘못된 응답 거부 |
| `async_ai_client_test` | 오프라인·큐 상한·재접속·이전 응답 폐기 |
| `online_ai_python_test` | artifact·온라인 판정·서버 계약 |

Clang-Tidy까지 로컬에서 확인하려면 별도 새 빌드 폴더를 사용한다.

```bash
cmake -S . -B "$RUN/build-clang" -G Ninja \
  -DPython3_EXECUTABLE="$PWD/.venv/bin/python" \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_CXX_CLANG_TIDY='clang-tidy;-warnings-as-errors=*'
cmake --build "$RUN/build-clang" -j2 2>&1 | tee "$RUN/clang-tidy.log"
```

**실패 시:** configure 로그의 누락 패키지, cppzmq 4.7 이상 여부, 실제 선택된 Python 경로를
확인한다. root 테스트가 skip이면 `id -u`부터 확인한다. 권한 오류면 저장소 상위 디렉터리와
symlink를 확인한다. 현재 테스트는 두 가지 artifact 권한 거부를 검사하며, 모든 supervisor 경로
검사나 Qt·방화벽 수명주기를 자동으로 검사하는 것은 아니다.

## 4. AI runtime과 모델 준비 — V04

센서는 `.venv/bin/python` 대신 `/usr/bin/python3`를 실행한다. 테스트용 venv 설치만으로는 부족하다.
runtime 설치는 [README의 의존성 설치](../../README.md)를 따른다. 이미 runtime이 있다면
백업·버전 확인 후 변경하고, 다른 Python 버전의 site-packages를 복사하지 않는다.

```bash
PYTHONNOUSERSITE=1 PYTHONPATH="/opt/ips-with-ai/python-packages:$PWD" \
  /usr/bin/python3 -c 'import sys, torch, numpy, zmq; print(sys.executable); print(torch.__version__, numpy.__version__, zmq.__version__)'
```

이 명령부터 성공해야 한다. `ModuleNotFoundError`는 해당 고정 runtime 경로의 설치를 확인한다.
Kali의 시스템 Python 환경을 우회 변경하지 않는다. 학습은 venv를 사용한다.
[Kali의 Python 환경 안내](https://www.kali.org/docs/general-use/python3-external-packages/)

### 연동 검증용 모델 만들기

실제 모델은 정상 통신을 이상으로 판정하지 않을 수 있다. 차단·팝업 전달 경로를 확실히
시험하기 위해 아래 코드는 `$RUN/fixture-artifacts`에 **가중치 0, 임계값 0인 시험 모델**을 만든다.
패킷 수가 양수인 제출 Flow의 복원오차는 양수이므로 이상 응답을 유도한다. 실제 학습 모델을
덮어쓰지 않으며, 이 시험은 탐지 성능 평가에 포함하지 않는다.

```bash
.venv/bin/python - <<'PY'
import json
import os
from pathlib import Path

import numpy as np
import torch

from ml.features import FEATURE_SCHEMA_VERSION, FEATURES
from ml.model import Autoencoder

directory = Path(os.environ['RUN']) / 'fixture-artifacts'
directory.mkdir(mode=0o700)
model = Autoencoder(len(FEATURES))
with torch.no_grad():
    for parameter in model.parameters():
        parameter.zero_()
torch.save(model.state_dict(), directory / 'autoencoder.pt')
np.savez(directory / 'scaler.npz', mean=np.zeros(len(FEATURES)), scale=np.ones(len(FEATURES)))
metadata = dict(feature_schema_version=FEATURE_SCHEMA_VERSION, features=FEATURES,
                n_features=len(FEATURES), model_version='integration-fixture-not-trained', threshold=0.0)
(directory / 'metadata.json').write_text(json.dumps(metadata), encoding='utf-8')
print(directory)
PY
```

재실행 시 같은 디렉터리가 있으면 실패하는 것이 정상이다. 새 RUN을 만들거나 이미 만든 fixture를 사용한다.
root 소유권 검사를 실제 interpreter로 확인한다.

```bash
PYTHONNOUSERSITE=1 PYTHONPATH="/opt/ips-with-ai/python-packages:$PWD" \
  /usr/bin/python3 -c 'import os; from ml.artifacts import load_artifacts; print(load_artifacts(os.environ["RUN"] + "/fixture-artifacts", require_secure_permissions=True).model_version)'
```

## 5. 공통 시험 설정·정상 통신 — V05

센서를 중지한 상태에서 원본 config 백업을 확인하고, 텍스트 편집기로 `config.json`을 다음
시험 설정으로 바꾼다. 초기에는 AI를 끄고 Rule만 확인한다. `artifact_dir`의 경로는 실제 RUN 경로로 바꾼다.
JSON 안의 `$RUN` 문자열은 자동 치환되지 않는다.

```json
{
  "queue_num": 0,
  "block_ttl_seconds": 15,
  "whitelist": [],
  "rules": {
    "window_seconds": 10,
    "port_scan": {"distinct_port_threshold": 5},
    "syn_flood": {"syn_threshold": 8}
  },
  "ai": {
    "enabled": false,
    "artifact_dir": "/opt/ips-validation.XXXXXX/fixture-artifacts",
    "queue_capacity": 1024,
    "startup_timeout_ms": 10000,
    "response_timeout_ms": 2000,
    "max_restarts": 3,
    "restart_reset_seconds": 60
  }
}
```

센서의 별도 터미널에서 빈 시험 디렉터리만 HTTP로 제공한다. 저장소나 모델 폴더를 공개하지 않는다.

```bash
mkdir "$RUN/http-public"
python3 -m http.server 8000 --bind 192.168.56.10 --directory "$RUN/http-public"
```

센서 실행 터미널에서 시작한다. 다음 시험에서는 로그 이름 `v05`를 해당 ID로 바꾼다.

```bash
cp config.json "$RUN/v05-config.json"
./build/ips 2>&1 | tee "$RUN/v05-sensor.log"
```

센서 관찰용 터미널에서:

```bash
pgrep -a -x ips
iptables -S INPUT
iptables -S OUTPUT
iptables -S IPS_WITH_AI
iptables -nvL IPS_WITH_AI
```

시험 장비에서 센서 시작 전·실행 중 각각:

```bash
SENSOR=192.168.56.10
curl --max-time 3 --fail --output /dev/null --write-out '%{http_code}\n' "http://$SENSOR:8000/"
```

**정상 결과:** 둘 다 HTTP 200. INPUT·OUTPUT에 `ips-with-ai-managed` jump가 각각 하나,
`IPS_WITH_AI` 안에 큐 0의 `--queue-bypass`와 `ips-with-ai-owned` 표시가 있다.
규칙 등록 성공 로그와 카운터 증가도 확인한다. 카운터 증가는 큐 진입 증거이며 DROP 증거가 아니다.

트레이의 종료 메뉴 또는 실행 터미널의 Ctrl+C로 종료한다. Bash에서 바로 `echo "${PIPESTATUS[0]}"`로
센서 종료 코드 0을 확인하고, 규칙을 다시 조회한다. 전용 체인과 관리 jump가 없어야 한다.
`IPS_WITH_AI` 조회의 “체인 없음”은 이 시점에서는 정상이다. 다른 규칙은 변경되지 않아야 한다.

**실패 시:** 센서 시작 전에도 curl이 실패하면 HTTP 서버·라우팅·기존 방화벽부터 확인한다.
`nfq_create_queue 실패`면 다른 큐 0 사용 프로세스를 확인한다. “다른 사용자 소유” 메시지면 기존
동명 체인을 임의 삭제하지 말고 소유자를 확인한다. 트레이 미지원 로그가 있으면 패킷 시험과 별도로
Qt 검증은 미통과이며, GUI 세션의 시스템 트레이 지원을 확인한다.

## 6. Rule 차단과 TTL — V06·V07

시험 장비에 `apt install hping3 curl`로 도구를 설치한다. 아래 명령은 실험망의 지정 IP에
수 개의 패킷만 보낸다. `-c`는 개수, `-i u100000`은 패킷 간격 0.1초다.
[Kali hping3 옵션 안내](https://www.kali.org/tools/hping3/)
**각 소시험 전 센서를 재시작한다.** 시험 도중 다른 curl 요청도 Rule 통계에 들어가므로
임계값 확인 패킷 사이에 다른 요청을 섞지 않는다. 두 Rule을 분리하려면 다른 Rule의 임계값을
충분히 높게 설정한다(포트 시험: `syn_threshold=1000`, SYN 시험: `distinct_port_threshold=1000`).

### 포트 스캔

센서 시작 직후 시험 장비 root 터미널에서:

```bash
hping3 -S -p ++8100 -c 5 -i u100000 "$SENSOR"
curl --max-time 3 --fail "http://$SENSOR:8000/"
```

5개 서로 다른 포트가 10초 창 안에 들어오면 포트 스캔 Rule 로그·TTL 등록이 생기고 curl이
실패해야 한다. 닫힌 시험 포트의 RST 자체는 정상이며 탐지 성공 증거로 쓰지 않는다.
경계 아래 조건은 별도 재시작 후 4개만 보내서 차단 로그가 없는지 확인한다.

### SYN 임계값

```bash
hping3 -S -p 8000 -c 8 -i u100000 "$SENSOR"
curl --max-time 3 --fail "http://$SENSOR:8000/"
```

8번째 SYN에서 SYN Rule 로그와 실제 차단을 확인한다. 별도 재시작 후 7개만 보내면
차단되지 않아야 한다. 이 시험은 적은 패킷으로 임계값을 확인하는 것이며 대규모 공격 부하 시험은 아니다.

### TTL 만료

마지막 차단 등록 로그 시각을 기록하고, 추가 hping 전송을 중단한다. 그 시각부터 15초를 넘긴 뒤
curl을 다시 실행해 HTTP 200을 확인한다. 필요하면 1~2초 간격으로 재시도한다. 만료 정리 로그와
실제 통신 복구를 모두 남긴다. 로그 출력 시점은 주기 정리 때문에 실제 만료 판단보다 늦을 수 있다.

### 화이트리스트

센서를 중지하고 `whitelist`에 시험 장비의 실제 출발지 IP를 넣어 재시작한 뒤 위 Rule 시험을
반복한다. HTTP는 계속 성공하고 그 IP의 차단 등록은 없어야 한다. **현재 구현은 해당 IP의 Flow
관찰·AI 제출도 건너뛴다.** 시험 후 원래 whitelist로 복구한다.

## 7. AI 이상 판정·방향·Qt — V08·V07

AI fixture 경로를 설정하고 `ai.enabled=true`, 두 Rule 임계값은 각각 1000으로 설정해 재시작한다.
트레이가 초록색이고 상태 창에 `ONLINE`, `integration-fixture-not-trained`가 표시되어야 한다.
먼저 이 상태를 확인한 후 시험 장비에서 HTTP 요청 한 번을 끝낸다.

**정상 결과의 순서:**

1. 첫 HTTP 요청은 완료된다. AI는 제출된 종료 Flow를 나중에 판단한다.
2. 센서 로그에 `AI_DECISION action=blocked`와 시험 IP·score·threshold·model_version이 나온다.
3. Qt에 `AI 이상 Flow 탐지` 팝업이 표시되고 상태 창의 AI 신규 차단 수가 증가한다.
4. 그 로그 이후 새 HTTP 요청은 실패한다. 15초 TTL 뒤에는 다시 한 번 성공할 수 있다.
   fixture를 계속 사용하면 이 새 Flow 종료 뒤 다시 차단되는 것이 정상이다.

Flow가 FIN 종료 조건을 충족하지 못하면 마지막 패킷 이후 60초 timeout과 순차 정리 뒤 제출될 수 있다.
Rule 차단, whitelist, 로컬 시작, 1패킷 Flow는 AI 제출에서 제외될 수 있으므로 로그 부재를 곧바로
AI 고장으로 단정하지 않는다. `AI_FLOW_READY`는 별도 LoggingFlowConsumer의 메시지이며 현재
AsyncAiClient 실행 경로에서 이 로그가 반드시 나온다고 기대하면 안 된다.

### 기존 연결도 차단되는지 확인

시험 장비에서 아래 연결을 먼저 열고 유지한다. `SENSOR`를 환경 변수로 전달한다.

```bash
SENSOR="$SENSOR" python3 - <<'PY'
import os
import socket

sock = socket.create_connection((os.environ['SENSOR'], 8000), timeout=3)
input('다른 터미널의 HTTP 요청으로 AI 차단 로그를 확인한 뒤 Enter: ')
sock.sendall(b'GET / HTTP/1.0\r\nHost: lab\r\n\r\n')
try:
    print(sock.recv(256))
except socket.timeout:
    print('기존 연결의 후속 요청도 응답 timeout')
finally:
    sock.close()
PY
```

다른 시험 장비 터미널에서 curl을 한 번 실행해 이상 판정을 유도한다. 미리 연 연결은 60초
이내에 시험하고, 차단 로그 직후 TTL 안에 Enter를 누른다. 기존 연결의 요청도 차단되어야 한다.
센서는 IP 단위로 inbound 패킷을 차단하므로 “새 연결만 차단”으로 결과를 적지 않는다.

### 로컬 시작 통신

차단 상태를 초기화하고 시험 장비에서 빈 디렉터리를 HTTP 8001로 제공한다. 센서가 시험 장비의
8001로 curl을 보내고 종료한다. 해당 통신만 발생시켰을 때 AI 큐 등록 수가 증가하지 않아야 한다.
역방향 응답은 OUTPUT에서 시작한 동일 Flow에 속한다. 양방향 통계의 값 자체는
`flow_manager_test`와 V12에서 별도로 확인한다.

### AI 중복 결과

하나의 IP에서 여러 HTTP 요청을 동시에 종료하면 이미 제출된 결과 중 `action=duplicate`가
나올 수 있다. 첫 차단 기준 15초 뒤 복구되는지 확인해 중복이 TTL을 연장하지 않는지 기록한다.
중복 로그가 안 나오면 재현 성공으로 표시하지 않는다. 현재 이 PacketCapture 분기를 확실히
주입하는 통합 하네스는 없으므로 필요하면 후속 테스트 작업으로 남긴다. `block_list_test`의
TTL 갱신 테스트는 BlockList API 자체의 기능이며 AI 중복 방지 검증을 대신하지 않는다.

## 8. AI 장애와 자동 재시작 — V09

아래 신호는 확인한 **AI 자식 PID 하나에만** 보낸다. 센서 관찰 터미널에서 PID를 찾는다.

```bash
pgrep -a -x ips
# 위에서 확인한 센서 PID 숫자를 입력한다.
IPS_PID=12345
pgrep -a -P "$IPS_PID"
```

### 자식 비정상 종료

AI ONLINE 상태에서 표시된 `/usr/bin/python3 -m ml.online_server` PID를 확인하고
`kill -KILL AI_PID숫자`를 실행한다. 센서는 살아 있고, 상태는 재시작 대기를 거쳐 새 Python PID로
ONLINE이 되어야 한다. 상태 창의 `Python 재시작` 수가 증가한다.

### 3회 한도

센서를 중지하고 `ai.artifact_dir`을 존재하지 않는 `$RUN/missing-artifacts`의 **실제 절대 경로**로
설정한 뒤 재시작한다. 초기 시작 외에 1·2·4초 대기 후 3번 재시도하고 최종 OFFLINE이 되어야 한다.
실제 소요 시간에는 프로세스 시작·정리 시간이 더해진다. 노란 트레이·오프라인 알림·재시작 수 3을
확인하고 추가 재시도가 없는지 관찰한다. 이 상태에서도 V06의 Rule 차단이 동작해야 한다.

정상 ONLINE을 60초 유지하면 현재 설정의 재시도 예산은 초기화된다. 따라서 “수명 전체에서
오직 3회만”으로 해석하지 않는다. 한도 시험은 위의 연속 시작 실패로 한다.

### 응답 멈춤

정상 fixture 설정과 높은 Rule 임계값으로 재시작한다. ONLINE의 AI 자식 PID에 `kill -STOP AI_PID숫자`를
보낸 직후 시험 장비에서 HTTP 요청을 완료해 **종료 Flow를 제출**한다. 단순히 유휴 AI를 멈추기만
하면 요청 timeout은 발생하지 않을 수 있다. 상태 창 timeout 증가와 자동 재시작을 확인한다.
2초 응답 제한 외에 프로세스 정리 시간이 걸릴 수 있다. 시험을 취소하면 해당 자식이 아직 같은
프로세스인지 확인한 뒤 `kill -CONT AI_PID숫자`로 되돌린다.

**합격 기준:** AI 장애 중 일반 통신이 AI 응답을 기다리며 정지하지 않고 Rule 경로가 살아 있다.
최종 OFFLINE을 전체 IPS 종료로 기록하지 않는다. UI 상태 전환만 확인하지 말고 HTTP·Rule 결과도 남긴다.

## 9. 큐·강제 종료·복구 — V10

### AI 큐

우선 `async_ai_client_test`의 큐 상한·최신 Flow 폐기 테스트 통과를 확인한다. 통합 시험에서는
`queue_capacity=1`, Rule 임계값은 높게, fixture를 사용한다. AI 자식에 STOP을 보낸 뒤 2초 안에
짧은 HTTP 요청 여러 개를 병렬로 완료한다. 예시는 시험 장비에서 다음과 같다.

```bash
for i in $(seq 1 12); do
  curl --max-time 3 --silent --output /dev/null "http://$SENSOR:8000/" &
done
wait
```

`AI_QUEUE_FULL` 또는 큐 폐기 통계 증가와 HTTP 응답을 확인한다. 이후 timeout·재시작도 예상된다.
아무 Flow도 완료되지 않아 큐 포화가 발생하지 않았으면 `미재현`으로 기록한다. 이때 버린 것은
AI 분석 요청이며 네트워크 패킷 DROP과 구분한다.

### 커널 NFQUEUE

AI를 끄고 `syn_threshold=100000`, `distinct_port_threshold=65536`으로 새 센서를 시작한다.
아래 신호 조작은 SSH가 아닌 센서의 로컬 터미널에서 한다. 별도 센서 터미널에서
`cat /proc/net/netfilter/nfnetlink_queue`를 저장한다. **센서 프로세스 전체**에 STOP을 보내고,
시험 장비에서 `hping3 -S -p 8000 -c 12000 -i u1000 "$SENSOR"`로 유한한 패킷을 보낸다.
소스가 요청하는 큐 길이는 10240이며 설정 실패 시 기본 1024를 사용한다. 실제 송신 속도·
넷링크 버퍼 상한에 따라 큐 포화보다 소켓 전달 실패가 먼저 발생할 수도 있다.
중단 중 큐 상태를 다시 저장한 뒤 즉시 센서에 CONT를 보내고 통신 복구를 확인한다.
사용 커널의 열 정의를 확인해 큐 길이·queue dropped·user dropped의 전후 차이를 기록한다.
카운터 증가가 없으면 포화를 검증한 것이 아니다. 무제한 flood로 대신하지 않는다.

현재 소스는 queue-full fail-open 플래그를 설정하지 않는다. 따라서 listener가 살아 있는 동안
큐가 차면 DROP이 발생할 수 있다. `--queue-bypass`는 listener가 없는 경우의 정책이다.
[Netfilter queue 플래그 문서](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html)

### 센서 강제 종료와 다시 실행

별도 새 센서에서 AI는 끈 상태로 시험한다. PID를 확인하고 `kill -KILL IPS_PID숫자`로 종료한다.
listener가 해제된 뒤 HTTP가 통과하는지 확인한다. SIGKILL은 정상 정리 코드를 실행하지 않으므로
관리 규칙이 남아 있을 수 있다. 센서를 다시 실행해 관리 규칙이 INPUT·OUTPUT 각각 한 번만
등록되고, 정상 종료하면 제거되는지 확인한다. 다른 규칙을 지우는 `iptables -F`는 사용하지 않는다.

AI를 켠 강제 종료까지 확인할 경우 종료 전 자식 PID·socket 경로도 기록한다. orphan Python과
이전 PID의 socket이 남는지 확인하고 잔류 시 결함으로 기록한다. 살아 있는 같은 자식인지 확인한
뒤 해당 PID에만 TERM을 보내 정리한다. 다른 프로세스나 `/tmp` 전체를 지우지 않는다.

## 10. 실제 CICIDS2017 점검·학습·평가 — V11

CSV를 `data/`에 준비하고 glob에 의도한 파일만 포함되는지 확인한다. 빈 데이터나 다른 CSV가
섞여 있으면 진행하지 않는다. 센서를 중지한 상태에서 데이터 점검부터 한다.

```bash
.venv/bin/python -m ml.audit_dataset --data 'data/*.csv' --output "$RUN/split-audit.json"
```

`rows`의 정상·공격·제외 수와 각 split이 비어 있지 않은지 확인한다. `feature_overlap`가 양수면
분할 사이 동일 특징이 존재한다. `group_isolation=not_checked`는 날짜·세션 분리가 미확인이라는
뜻이다. **중복 0도 누수 없음의 증거는 아니다.** 상세 의미는 [안정화 기록 4장](2026-09-15-baseline.md)을 따른다.

파일명·원본 Timestamp·Flow 식별 정보 등으로 날짜/세션 그룹을 정의하고 각 split의 그룹 교집합을
확인해야 최종 평가를 할 수 있다. 현재 audit는 그룹 교집합 보고 기능이 없다. 자료가 없거나
그룹 분할이 필요하면 그 작업을 별도 미완료 항목으로 기록한다. 현행 행 단위 분할을 유지한
다음 실행은 **파이프라인 동작 확인·잠정 성능**으로만 사용한다.

학습은 `ml/artifacts`를 덮어쓴다. 기존 모델이 있으면 먼저 보관한다.

```bash
if [ -d ml/artifacts ]; then cp -a ml/artifacts "$RUN/artifacts.before-training"; fi
.venv/bin/python -m ml.train --data 'data/*.csv' --epochs 30 2>&1 | tee "$RUN/train.log"
.venv/bin/python -m ml.evaluate --data 'data/*.csv' 2>&1 | tee "$RUN/evaluate.log"
.venv/bin/python -m ml.plot --data 'data/*.csv' 2>&1 | tee "$RUN/plot.log"
sha256sum ml/artifacts/autoencoder.pt ml/artifacts/scaler.npz ml/artifacts/metadata.json \
  > "$RUN/artifact-sha256.txt"
```

**정상 결과:** 모델·scaler·metadata가 생성되고 정상 오탐률·공격별 탐지율에 NaN/Inf가 없으며,
`ml/artifacts/plots`의 PNG 3개를 실제 열 수 있다. 학습과 평가에 같은 CSV glob·동일 전처리·seed를
사용했음을 기록한다. 학습 기록, CSV 지문, 모델 지문을 함께 보관한다. 임의의 “정확도 99%”를
합격 기준으로 쓰지 않고, 목표 오탐률·공격별 탐지율을 먼저 정한 뒤 별도 고정 test 자료로 평가한다.
Kali에는 현재 plot 코드가 지정한 `Malgun Gothic`이 없을 수 있다. PNG 생성 성공과 한글 표시
성공을 구분해 확인하고, 글꼴 깨짐은 시각화 환경의 후속 수정 사항으로 기록한다.

실제 모델로 V04·V08을 다시 실행해 로딩·정상 통신·판정 점수·오탐 여부를 기록한다. fixture의
차단 성공률을 실제 모델의 공격 탐지율로 사용하지 않는다.

## 11. 실시간 특징과 학습 특징의 일치 — V12

1. 시험망에서 동일한 짧은 TCP/UDP 통신을 만들고 인터페이스를 지정해 pcap을 보관한다.
   예: `tcpdump -i 실험인터페이스 -s 0 -w "$RUN/features.pcap" host 192.168.56.20`.
   통신 종료 후 Ctrl+C로 저장을 마친다.
2. 사용하는 CICFlowMeter의 버전·설정·timeout을 기록하고 해당 pcap에서 특징을 추출한다.
3. 같은 통신의 C++ `FlowRecord.features`를 확보한다. 현재 앱은 이 배열을 기본 로그나 파일로
   내보내지 않는다. 디버거로 `AsyncAiClient::consume`의 인자를 관찰하거나, 별도 승인한
   테스트용 exporter/하네스를 구현해야 한다. **현재 명령 하나로 완료할 수 없는 항목**이다.
4. `ml/features.py` 순서대로 27행 비교표를 만든다. 특징명, C++ 값, CSV 값, 단위, 절대/상대 차이,
   허용 오차와 근거를 적는다. 방향은 최초 송신자 기준으로 맞춘다.
5. 패킷 수·TCP flag 수는 일치를 확인하고, 시간·표준편차 차이는 timestamp 정밀도와 계산법을
   확인한다. payload 길이와 전체 IP 패킷 길이를 혼동하지 않는다. FIN/RST/60초 timeout으로
   세션이 나뉘는 조건도 맞춘다.

현재 128바이트 캡처 복사 제한이 있으므로 긴 패킷·TCP 옵션 사례도 포함한다. 불일치가 있으면
특징 계약이나 추출기를 수정하고 재학습 필요 여부를 판단한다. 합성 단위 테스트 통과만으로
CICFlowMeter와 완전히 같다고 결론내리지 않는다.

## 12. 성능 기준선 — V13

같은 장비·인터페이스·요청 크기에서 센서 꺼짐 / AI 비활성 / 실제 AI 활성의 세 조건을 비교한다.
성능 시험에서는 원래 설정을 보관하고 Rule 임계값을 시험량에 맞게 조절하되, 변경값을 기록한다.
화이트리스트는 Flow·AI를 생략하므로 AI 비용 측정에 사용하지 않는다. 실제 모델이 차단했다면
그 시각·실패율을 함께 기록한다.

시험 장비에서 조건별 출력 파일 이름을 바꾸며 HTTP 50회 기초 측정을 한다.

```bash
for i in $(seq 1 50); do
  curl --max-time 3 --silent --output /dev/null \
    --write-out '%{http_code},%{time_total}\n' "http://$SENSOR:8000/"
  sleep 0.2
done > latency-sensor-off.csv
```

CSV의 HTTP 200 비율과 성공한 요청 시간의 p50/p95를 계산한다. 조건마다 3회 반복하고 요청 수·
성공 수·timeout 수도 남긴다. 이것은 **HTTP 종단간 지연**이며 NFQUEUE 내부 처리 지연이 아니다.
센서 측 `pidstat -r -u -p IPS_PID숫자 1 30`과 Python 자식의 동일 측정으로 CPU·메모리를 기록한다.

패킷 처리량·커널 DROP은 정해진 송신률/시간의 유한 트래픽과 양측 pcap·큐 카운터를 함께 비교한다.
먼저 저율에서 시작하고 단계별 송신률을 기록한다. 실제 판정 처리 지연 p50/p95를 구하려면
수신~verdict 계측이 추가로 필요하다. 현재 앱에 이 계측과 자동 부하 보고서는 없으므로
그 수치를 HTTP 지연으로 대체하지 말고 미측정으로 적는다.

## 13. GitHub Actions — V14

로컬 YAML 검사와 실제 GitHub 실행은 다르다. 검증할 소스·새 파일·워크플로를 검토해 커밋하고,
원격 반영을 결정한 뒤 push/PR을 진행한다. 이 안내 작성 작업 자체는 커밋·push를 실행하지 않는다.

1. GitHub 저장소의 `Actions`에서 `IPS Engine CI Pipeline`을 연다.
2. main/develop의 push 또는 해당 브랜치 대상 PR로 실행한다. 수동 실행은 기본 브랜치에
   `workflow_dispatch`가 있는 워크플로가 반영된 뒤 `Run workflow`에서 대상 브랜치를 선택한다.
3. `Python Security & Quality`, `C++ Clang-Tidy & CMake Build` 두 job을 확인한다.
4. root 전용 artifact 단계가 실제 실행됐는지, C++ job이 build뿐 아니라 CTest까지 통과했는지 본다.
5. 실행 URL, 커밋 SHA, 두 job 로그를 기록한다. 이전 커밋의 초록 표시를 이번 변경의 성공으로 쓰지 않는다.

버튼이 없으면 워크플로 경로 `.github/workflows/my_ci_cd.yml`, 기본 브랜치 반영, 저장소 쓰기
권한을 확인한다. [GitHub 공식 수동 실행 절차](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)

## 14. 시험 종료·결과 전달

센서를 정상 종료하고 HTTP 시험 서버를 Ctrl+C로 종료한다. 시작 전 설정이 있었다면 백업을
`config.json`으로 되돌린다. 원래 설정 파일이 없었다면 시험 설정을 RUN 안으로 옮겨 보관한다.
실제 모델 사용 전 `ai.artifact_dir`가 fixture를 가리키지 않는지 확인한다. 학습으로 교체한 모델을
계속 사용할지, 보관한 이전 모델로 복구할지도 명시한다.

`iptables-save`로 종료 뒤 규칙을 저장해 시작 전과 비교한다. 센서·자식 PID가 남지 않았는지
확인한다. RUN 자료는 지우지 말고 보관하되 외부 공유 시 IP·pcap·데이터 경로를 확인한다.

아래 표를 복사해 실제 결과를 작성한다. 상세 로그는 RUN 경로로 연결한다.

| 항목 | 상태(통과/실패/미검증) | 관찰 결과·종료 코드 | 증거 파일·실행 URL | 실패 원인·다음 작업 |
| --- | --- | --- | --- | --- |
| V01 환경 | 미검증 | | | |
| V02 C++ | 미검증 | | | |
| V03 Python·권한 | 미검증 | | | |
| V04 runtime·모델 | 미검증 | | | |
| V05 시작·정상 통신·종료 | 미검증 | | | |
| V06 Rule | 미검증 | | | |
| V07 TTL·화이트리스트·방향 | 미검증 | | | |
| V08 AI·Qt | 미검증 | | | |
| V09 장애·재시작 | 미검증 | | | |
| V10 큐·강제 종료 | 미검증 | | | |
| V11 실데이터·성능 | 미검증 | | | |
| V12 특징 일치 | 미검증 | | | |
| V13 처리량·지연 | 미검증 | | | |
| V14 CI | 미검증 | | | |

V07 중복 결과, V12 실시간 특징 수집, V13 내부 지연 계측은 현재 자동화가 부족한 부분이다.
재현하지 못했거나 수집 도구가 없으면 남은 테스트·계측 개발로 기록한다. 완료 보고에는
“자동 테스트 통과”, “실험망 통합 검증”, “실데이터 성능 평가”를 각각 적는다.
