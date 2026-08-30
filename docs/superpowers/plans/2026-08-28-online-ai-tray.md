# Online AI and Qt Tray Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 종료된 원격 Flow를 Python AI가 온라인 판정하고, 이상이면 기존 TTL로 후속 수신 패킷을 차단하면서 Qt5 트레이로 사용자에게 알린다.

**Architecture:** Qt 메인 스레드는 트레이와 Python `QProcess`를, 캡처 스레드는 NFQUEUE·Rule·BlockList를, AI 통신 스레드는 bounded 큐와 ZeroMQ REQ socket을 각각 단독 소유한다. AI 결과는 결과 큐를 거쳐 캡처 스레드가 적용하므로 패킷 verdict는 Python 응답을 기다리지 않는다.

**Tech Stack:** C++17, Qt5 Core/Widgets, libzmq/cppzmq, nlohmann/json, glog, Python 3, pyzmq, PyTorch, NumPy

**Spec:** `docs/superpowers/specs/2026-08-28-online-ai-tray-design.md`

## Global Constraints

- 대상은 Ubuntu VM의 root GUI 로그인 한 세션이며 시작 시 `geteuid() != 0`이면 종료한다.
- Qt5를 사용하고 headless 실행, 일반 사용자 실행, 다중 센서 인스턴스는 지원하지 않는다.
- Python은 shell 없이 `/usr/bin/python3 -m ml.online_server`로 자동 실행한다.
- Python runtime package는 root 소유 `/opt/ips-with-ai/python-packages`에 설치하며 PyTorch 2.1 이상을 사용한다.
- ZeroMQ endpoint는 `ipc:///tmp/ips-with-ai-<sensor-pid>.sock`이며 외부 TCP를 열지 않는다.
- 요청은 한 건을 보내고 응답을 받은 뒤 다음 건을 보내는 순차 REQ/REP 방식이다.
- 입력·결과 큐 기본 상한은 1024, 시작 제한시간은 10000ms, 응답 제한시간은 2000ms다.
- Python 재시작 기본값은 최초 실행 이후 1초·2초·4초 간격의 최대 3회이며 60초 정상 동작 후 횟수를 초기화한다.
- AI 장애·과부하는 Rule 처리와 NFQUEUE verdict를 중단하지 않고 Rule-only로 열화한다.
- Rule과 AI는 최상위 `block_ttl_seconds`를 공유한다.
- 이미 끝난 현재 Flow는 소급 차단하지 않고 동일 출발지의 이후 수신 패킷부터 차단한다.
- 같은 IP는 TTL 동안 트레이 알림 1회만 표시한다.
- C++은 Google 스타일, Python은 `ruff.toml`의 100자 제한과 현재 모듈 구조를 따른다.
- 사용자의 결정에 따라 이번 계획에서는 테스트 파일을 생성·수정·열람·실행하지 않는다.
- Windows 호스트 결과를 Ubuntu NFQUEUE·Qt 통합 성공으로 주장하지 않는다.

## File Map

| 파일 | 책임 |
| --- | --- |
| `src/config/config.h`, `src/config/config.cpp` | AI 설정 기본값·타입·범위 검증 |
| `src/ai/ai_types.h` | AI 상태, 응답, 결정, 알림, 상태 snapshot 데이터 |
| `src/ai/ai_protocol.h`, `src/ai/ai_protocol.cpp` | Flow 요청 JSON 생성과 응답 JSON 검증 |
| `src/ai/async_ai_client.h`, `src/ai/async_ai_client.cpp` | bounded 큐, AI 통신 스레드, ZeroMQ REQ 수명 |
| `src/ai/flow_consumer.h` | Flow 제출과 검증된 AI 결과 drain 인터페이스 |
| `src/capture/packet_capture.h`, `src/capture/packet_capture.cpp` | AI 결과를 화이트리스트·BlockList에 안전하게 반영 |
| `src/app/ai_process_supervisor.h`, `src/app/ai_process_supervisor.cpp` | Python 준비 확인·종료 감지·3회 재시작 |
| `src/ui/tray_controller.h`, `src/ui/tray_controller.cpp` | 트레이 상태 아이콘·이상 알림·상태 창·종료 메뉴 |
| `src/app/application_controller.h`, `src/app/application_controller.cpp` | Qt·캡처·AI 수명 연결과 스레드 간 callback 전달 |
| `src/main.cpp` | root 검사, Qt 이벤트 루프, signal relay |
| `ml/artifacts.py` | artifact 안전 로드와 계약 검증 |
| `ml/online_server.py` | pyzmq REP 서버와 오토인코더 온라인 추론 |
| `ml/features.py`, `ml/train.py`, `ml/evaluate.py` | 특징·모델 버전 저장과 공통 artifact loader 사용 |
| `CMakeLists.txt`, `ml/requirements.txt`, `ml/runtime-requirements.txt` | Qt5·ZeroMQ·학습·온라인 Python 의존성 연결 |
| `config.example.json`, `README.md`, `docs/design/*.md` | 설치·설정·운영·검증 설명 |

## Execution Precondition

현재 작업 트리에는 이 계획의 기반인 양방향 캡처와 AI 특징 코드가 미커밋 상태로 남아 있다.
Task 1 전에 `git status --short`와 `git diff --check`로 그 범위를 다시 확인하고, 온라인 AI 변경과
섞이지 않도록 기존 승인 작업을 별도 checkpoint commit으로 먼저 보존한다. `git add -A`는 사용하지
않고 상태에 표시된 기존 파일만 명시적으로 stage한다. 테스트 파일은 stage하지 않는다.

---

### Task 1: AI 설정과 빌드 의존성

**Files:**
- Modify: `src/config/config.h`
- Modify: `src/config/config.cpp`
- Modify: `CMakeLists.txt`
- Modify: `ml/requirements.txt`
- Create: `ml/runtime-requirements.txt`

**Interfaces:**
- Consumes: 기존 `Config`, `read_nonnegative_integer()`, `parse_config()`
- Produces: `AiConfig`, `Config::ai`, Qt5·libzmq·cppzmq 빌드 의존성

- [ ] **Step 1: `AiConfig` 기본값을 선언한다**

`src/config/config.h`에서 `Config` 앞에 다음 구조체를 추가하고 `Config` 마지막에 `AiConfig ai;`를
추가한다.

```cpp
struct AiConfig {
    bool enabled = true;
    std::string artifact_dir = "ml/artifacts";
    size_t queue_capacity = 1024;
    int startup_timeout_ms = 10000;
    int response_timeout_ms = 2000;
    int max_restarts = 3;
    int restart_reset_seconds = 60;
};
```

- [ ] **Step 2: `ai` object를 기존 fail-fast 방식으로 파싱한다**

`parse_config()`에서 `rules`를 읽는 위치와 같은 수준으로 AI object를 읽는다.

```cpp
const auto ai = j.value("ai", nlohmann::json::object());
const auto queue_capacity =
    read_nonnegative_integer(ai, "queue_capacity", cfg.ai.queue_capacity);
const auto startup_timeout_ms =
    read_nonnegative_integer(ai, "startup_timeout_ms", cfg.ai.startup_timeout_ms);
const auto response_timeout_ms =
    read_nonnegative_integer(ai, "response_timeout_ms", cfg.ai.response_timeout_ms);
const auto max_restarts =
    read_nonnegative_integer(ai, "max_restarts", cfg.ai.max_restarts);
const auto restart_reset_seconds =
    read_nonnegative_integer(ai, "restart_reset_seconds", cfg.ai.restart_reset_seconds);
```

`ai`가 object가 아니거나 `enabled`가 boolean이 아니거나 `artifact_dir`이 string이 아니면
`std::nullopt`를 반환한다. 정수는 아래 범위를 그대로 적용한다.

```cpp
if (!ai.is_object() ||
    (ai.contains("enabled") && !ai.at("enabled").is_boolean()) ||
    (ai.contains("artifact_dir") && !ai.at("artifact_dir").is_string()) ||
    !queue_capacity.has_value() || !startup_timeout_ms.has_value() ||
    !response_timeout_ms.has_value() || !max_restarts.has_value() ||
    !restart_reset_seconds.has_value()) {
    LOG(ERROR) << "config.json AI 필드 타입 오류";
    return std::nullopt;
}

if (*queue_capacity == 0 || *queue_capacity > 65536 ||
    *startup_timeout_ms < 1000 || *startup_timeout_ms > 60000 ||
    *response_timeout_ms < 100 || *response_timeout_ms > 60000 ||
    *max_restarts > 10 || *restart_reset_seconds == 0 ||
    *restart_reset_seconds > 3600) {
    LOG(ERROR) << "config.json AI 값 범위 오류";
    return std::nullopt;
}
```

검증 뒤 값을 목적 타입으로 변환한다. `artifact_dir`이 빈 문자열이면 시작을 중단한다.

```cpp
cfg.ai.enabled = ai.value("enabled", cfg.ai.enabled);
cfg.ai.artifact_dir = ai.value("artifact_dir", cfg.ai.artifact_dir);
if (cfg.ai.artifact_dir.empty()) {
    LOG(ERROR) << "config.json ai.artifact_dir가 비어 있음";
    return std::nullopt;
}
cfg.ai.queue_capacity = static_cast<size_t>(*queue_capacity);
cfg.ai.startup_timeout_ms = static_cast<int>(*startup_timeout_ms);
cfg.ai.response_timeout_ms = static_cast<int>(*response_timeout_ms);
cfg.ai.max_restarts = static_cast<int>(*max_restarts);
cfg.ai.restart_reset_seconds = static_cast<int>(*restart_reset_seconds);
```

- [ ] **Step 3: Qt5와 ZeroMQ를 센서 target에 연결한다**

`CMakeLists.txt`의 기존 pkg-config와 package 검색 옆에 다음을 추가한다.

```cmake
pkg_check_modules(ZMQ REQUIRED IMPORTED_TARGET libzmq)
find_path(CPPZMQ_INCLUDE_DIR zmq.hpp)
if(NOT CPPZMQ_INCLUDE_DIR)
    message(FATAL_ERROR "cppzmq header zmq.hpp not found")
endif()
find_package(Qt5 5.12 REQUIRED COMPONENTS Core Widgets)
```

`ips` target에만 cppzmq include와 라이브러리를 연결한다.

```cmake
target_include_directories(ips PRIVATE ${CPPZMQ_INCLUDE_DIR})
target_link_libraries(ips PRIVATE
    PkgConfig::NFQUEUE
    PkgConfig::GLOG
    PkgConfig::ZMQ
    nlohmann_json::nlohmann_json
    Qt5::Core
    Qt5::Widgets
)
```

- [ ] **Step 4: Python 학습·온라인 의존성을 분리한다**

`ml/runtime-requirements.txt`를 다음 내용으로 만든다.

```text
torch>=2.1
numpy
pyzmq
```

`ml/requirements.txt`는 공통 항목을 중복하지 않고 runtime 파일을 포함한다.

```text
-r runtime-requirements.txt
pandas
scikit-learn
matplotlib
ruff
```

- [ ] **Step 5: 변경 범위를 정적으로 확인한다**

Run:

```bash
git diff --check -- src/config/config.h src/config/config.cpp CMakeLists.txt ml/requirements.txt ml/runtime-requirements.txt
rg -n "AiConfig|queue_capacity|startup_timeout_ms|response_timeout_ms|max_restarts|Qt5|ZMQ|pyzmq|torch>=2.1" src/config CMakeLists.txt ml/*requirements.txt
```

Expected: whitespace 오류가 없고 일곱 AI 설정 및 Qt5/ZeroMQ/pyzmq가 모두 검색된다. 테스트 target은
수정되지 않는다.

- [ ] **Step 6: Task 1을 커밋한다**

```bash
git add src/config/config.h src/config/config.cpp CMakeLists.txt ml/requirements.txt ml/runtime-requirements.txt
git commit -m "build: add online AI runtime configuration"
```

---

### Task 2: 학습 artifact 버전과 안전한 공통 loader

**Files:**
- Create: `ml/artifacts.py`
- Modify: `ml/features.py`
- Modify: `ml/train.py`
- Modify: `ml/evaluate.py`

**Interfaces:**
- Consumes: `ml.model.Autoencoder`, `ml.features.FEATURES`, 기존 세 artifact 파일
- Produces: `FEATURE_SCHEMA_VERSION`, `LoadedArtifacts`, `load_artifacts(artifact_dir, require_secure_permissions=False)`

- [ ] **Step 1: Python 특징 계약 버전을 한 곳에 선언한다**

`ml/features.py`에서 `FEATURES` 앞에 다음 상수를 추가한다.

```python
FEATURE_SCHEMA_VERSION = 1
```

- [ ] **Step 2: 학습 metadata에 특징·모델 버전을 저장한다**

`ml/train.py`에 UTC datetime import를 추가한다.

```python
from datetime import datetime, timezone

from ml.features import FEATURES, FEATURE_SCHEMA_VERSION
```

artifact 저장 직전에 버전을 생성하고 metadata에 넣는다.

```python
model_version = datetime.now(timezone.utc).strftime("ae-%Y%m%dT%H%M%SZ")
```

```python
{
    "feature_schema_version": FEATURE_SCHEMA_VERSION,
    "model_version": model_version,
    "threshold": threshold,
    "features": FEATURES,
    "n_features": len(FEATURES),
    "percentile": percentile,
}
```

- [ ] **Step 3: 공통 artifact 자료형과 파일 검증을 작성한다**

`ml/artifacts.py`에 다음 공개 인터페이스를 구현한다.

```python
@dataclass(frozen=True)
class LoadedArtifacts:
    model: Autoencoder
    mean: np.ndarray
    scale: np.ndarray
    threshold: float
    feature_schema_version: int
    model_version: str


def load_artifacts(
    artifact_dir: str, *, require_secure_permissions: bool = False
) -> LoadedArtifacts:
    ...
```

함수 본문은 파일 이름을 `autoencoder.pt`, `scaler.npz`, `metadata.json`으로 고정하고
`Path.resolve(strict=True)` 후 모두 일반 파일인지 확인한다. 온라인 모드에서는 POSIX group/other
write bit를 거부한다.

```python
def _require_regular_file(path: Path, require_secure_permissions: bool) -> None:
    file_stat = path.stat()
    if not path.is_file():
        raise ValueError(f"artifact가 일반 파일이 아님: {path}")
    if require_secure_permissions and file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PermissionError(f"artifact가 group/other 쓰기 가능: {path}")
```

metadata는 아래 조건을 모두 검사한다.

```python
if metadata["features"] != FEATURES:
    raise ValueError("metadata 특징 순서 불일치")
if metadata["n_features"] != len(FEATURES):
    raise ValueError("metadata 특징 개수 불일치")
if metadata["feature_schema_version"] != FEATURE_SCHEMA_VERSION:
    raise ValueError("metadata 특징 스키마 불일치")
if not isinstance(metadata["model_version"], str) or not metadata["model_version"]:
    raise ValueError("metadata 모델 버전 오류")
```

scaler는 `np.load(path, allow_pickle=False)`로 읽고 mean·scale이 shape `(27,)`, 모두 finite,
scale이 모두 0보다 큰지 검사한다. threshold는 `float`로 바꾼 뒤 finite이고 0 이상인지 검사한다.
가중치는 다음 방식으로만 읽는다.

```python
model = Autoencoder(len(FEATURES))
state_dict = torch.load(model_path, map_location="cpu", weights_only=True)
model.load_state_dict(state_dict)
model.eval()
```

- [ ] **Step 4: 평가 코드가 공통 loader를 사용하게 한다**

`ml/evaluate.py`의 중복 `load_artifacts()`를 삭제하고 다음 import와 사용으로 교체한다.

```python
from ml.artifacts import load_artifacts
```

```python
artifacts = load_artifacts(ARTIFACTS)
false_positive_rate = float(
    (_errors(artifacts.model, artifacts.mean, artifacts.scale, benign_test)
     > artifacts.threshold).mean()
)
```

공격 데이터 계산도 같은 `artifacts` 필드를 사용한다.

- [ ] **Step 5: Python 문법·스타일만 검증한다**

Run:

```bash
python3 -m compileall ml
python3 -m ruff check ml
```

Expected: 두 명령 exit code 0. 모델 파일이 없어도 import·compile 단계는 성공한다.

- [ ] **Step 6: Task 2를 커밋한다**

```bash
git add ml/artifacts.py ml/features.py ml/train.py ml/evaluate.py
git commit -m "feat: version and validate AI artifacts"
```

---

### Task 3: Python ZeroMQ 온라인 추론 서버

**Files:**
- Create: `ml/online_server.py`

**Interfaces:**
- Consumes: `load_artifacts()`, `LoadedArtifacts`, JSON request schema version 1
- Produces: `infer_request(artifacts, request)`, `run(endpoint, artifact_dir)`, `python -m ml.online_server`

- [ ] **Step 1: 요청 오류를 응답 코드로 바꾸는 예외를 선언한다**

```python
class RequestError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
```

지원 error code는 다음으로 고정한다.

```python
INVALID_JSON = "INVALID_JSON"
INVALID_FIELD = "INVALID_FIELD"
SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
FEATURE_SCHEMA_MISMATCH = "FEATURE_SCHEMA_MISMATCH"
FEATURE_COUNT_MISMATCH = "FEATURE_COUNT_MISMATCH"
NONFINITE_FEATURE = "NONFINITE_FEATURE"
```

- [ ] **Step 2: 요청 필드와 특징 배열을 검증한다**

`infer_request()` 전에 호출할 `_validate_request()`가 다음을 검사한다.

```python
def _validate_request(request: object, artifacts: LoadedArtifacts) -> tuple[str, np.ndarray]:
    if not isinstance(request, dict):
        raise RequestError(INVALID_FIELD, "요청이 JSON object가 아님")
    flow_id = request.get("flow_id")
    if not isinstance(flow_id, str) or not flow_id:
        raise RequestError(INVALID_FIELD, "flow_id 오류")
    if request.get("schema_version") != 1:
        raise RequestError(SCHEMA_MISMATCH, "schema_version 오류")
    if request.get("feature_schema_version") != artifacts.feature_schema_version:
        raise RequestError(FEATURE_SCHEMA_MISMATCH, "feature_schema_version 오류")
```

`src_ip`, `dst_ip`는 `ipaddress.IPv4Address`, port는 0~65535 정수, protocol은 0~255 정수,
timestamp는 boolean이 아닌 정수, `first_seen_ms <= last_seen_ms`, `end_reason`은 기존 C++ 문자열인
`tcp_fin|tcp_reset|timeout`인지 확인한다. 특징은 정확히 27개의 boolean이 아닌 int/float이며 모두 finite여야
한다.

```python
feature_values = request.get("features")
if not isinstance(feature_values, list) or len(feature_values) != len(FEATURES):
    raise RequestError(FEATURE_COUNT_MISMATCH, "특징 개수 오류")
if any(
    isinstance(value, bool) or not isinstance(value, (int, float))
    for value in feature_values
):
    raise RequestError(INVALID_FIELD, "특징 타입 오류")
features = np.asarray(feature_values, dtype=np.float64)
if not np.isfinite(features).all():
    raise RequestError(NONFINITE_FEATURE, "특징에 NaN 또는 Inf 포함")
return flow_id, features
```

- [ ] **Step 3: 정규화·복원오차·이상 판정을 구현한다**

```python
def infer_request(artifacts: LoadedArtifacts, request: object) -> dict[str, object]:
    flow_id, features = _validate_request(request, artifacts)
    scaled = (features - artifacts.mean) / artifacts.scale
    with torch.no_grad():
        input_tensor = torch.tensor(scaled[None, :], dtype=torch.float32)
        reconstructed = artifacts.model(input_tensor)
        score = float(((reconstructed - input_tensor) ** 2).mean().item())
    if not math.isfinite(score):
        raise RuntimeError("모델 복원오차가 유한하지 않음")
    return {
        "schema_version": 1,
        "flow_id": flow_id,
        "model_version": artifacts.model_version,
        "ok": True,
        "anomaly": score > artifacts.threshold,
        "score": score,
        "threshold": artifacts.threshold,
    }
```

- [ ] **Step 4: REP 서버 수명과 준비 메시지를 구현한다**

`run()`은 `os.umask(0o077)` 후 secure artifact loader를 호출하고 REP socket을 bind한다.

```python
artifacts = load_artifacts(artifact_dir, require_secure_permissions=True)
context = zmq.Context()
socket = context.socket(zmq.REP)
socket.setsockopt(zmq.LINGER, 0)
socket.setsockopt(zmq.RCVTIMEO, 250)
socket.bind(endpoint)
print(
    json.dumps(
        {
            "event": "AI_READY",
            "schema_version": 1,
            "model_version": artifacts.model_version,
        }
    ),
    flush=True,
)
```

SIGINT·SIGTERM handler는 module-level boolean만 `False`로 바꾼다. 250ms receive timeout마다 종료
여부를 확인한다. 받은 bytes는 UTF-8 strict decode와 `json.loads()`를 거쳐 `infer_request()`에
전달한다. UTF-8·JSON 문법 오류는 `INVALID_JSON`, `RequestError`는 해당 code의 `ok=false` 응답으로
돌려준다. 예상하지 못한 모델 오류만 stderr에 기록하고 프로세스를 exit code 1로 끝내 supervisor
재시작을 유도한다.

- [ ] **Step 5: CLI를 고정한다**

```python
parser = argparse.ArgumentParser()
parser.add_argument("--endpoint", required=True)
parser.add_argument("--artifact-dir", required=True)
args = parser.parse_args()
run(args.endpoint, args.artifact_dir)
```

- [ ] **Step 6: 서버 모듈을 정적으로 검증한다**

Run:

```bash
python3 -m compileall ml
python3 -m ruff check ml
python3 -m ml.online_server --help
```

Expected: 세 명령 exit code 0, help에 `--endpoint`와 `--artifact-dir`가 표시된다.

- [ ] **Step 7: Task 3을 커밋한다**

```bash
git add ml/online_server.py
git commit -m "feat: add Python online inference server"
```

---

### Task 4: C++ AI 메시지 자료형과 JSON 계약

**Files:**
- Create: `src/ai/ai_types.h`
- Create: `src/ai/ai_protocol.h`
- Create: `src/ai/ai_protocol.cpp`
- Modify: `src/ai/flow_consumer.h`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `FlowRecord`, `FiveTuple`, `flow_end_reason_to_string()`
- Produces: `AiState`, `AiResponse`, `AiDecision`, `AiBlockEvent`, `AiClientStatsSnapshot`, `CaptureStatsSnapshot`, `serialize_flow_request()`, `parse_ai_response()`

- [ ] **Step 1: 스레드 사이에서 이동할 자료형을 선언한다**

`src/ai/ai_types.h`에 다음 핵심 필드를 선언한다.

```cpp
enum class AiState { DISABLED, STARTING, ONLINE, RESTART_WAIT, OFFLINE, STOPPING };

struct AiResponse {
    bool ok;
    std::string flow_id;
    std::string model_version;
    bool anomaly = false;
    double score = 0.0;
    double threshold = 0.0;
    std::string error_code;
};

struct AiDecision {
    FlowRecord record;
    bool anomaly;
    double score;
    double threshold;
    std::string model_version;
};

struct AiBlockEvent {
    std::string flow_id;
    uint32_t source_ip;
    double score;
    double threshold;
    int ttl_seconds;
    std::string model_version;
};

struct AiClientStatsSnapshot {
    uint64_t submitted = 0;
    uint64_t unavailable_dropped = 0;
    uint64_t queue_full_dropped = 0;
    uint64_t normal_responses = 0;
    uint64_t anomaly_responses = 0;
    uint64_t protocol_errors = 0;
    uint64_t timeouts = 0;
};

struct CaptureStatsSnapshot {
    uint64_t rule_blocks = 0;
    uint64_t ai_new_blocks = 0;
    uint64_t ai_duplicates = 0;
    uint64_t ai_whitelisted = 0;
};
```

- [ ] **Step 2: FlowConsumer에 결과 drain 기본 동작을 추가한다**

기존 logging consumer를 깨지 않도록 pure virtual이 아닌 기본 구현을 둔다.

```cpp
virtual std::vector<AiDecision> drain_decisions() { return {}; }
```

`flow_consumer.h`는 `ai/ai_types.h`와 `<vector>`를 include한다.

- [ ] **Step 3: 요청 serializer를 구현한다**

`src/ai/ai_protocol.h`의 공개 함수는 다음으로 고정한다.

```cpp
std::string serialize_flow_request(const FlowRecord& record);

std::optional<AiResponse> parse_ai_response(const std::string& json_text,
                                            const std::string& expected_flow_id,
                                            const std::string& expected_model_version,
                                            std::string* error);
```

serializer는 spec 7장의 모든 필드를 넣고 `features` 27개를 순서대로 JSON array에 넣는다.

```cpp
nlohmann::json request{
    {"schema_version", 1},
    {"flow_id", record.flow_id},
    {"src_ip", ip_to_string(record.key.src_ip)},
    {"src_port", record.key.src_port},
    {"dst_ip", ip_to_string(record.key.dst_ip)},
    {"dst_port", record.key.dst_port},
    {"protocol", record.key.protocol},
    {"first_seen_ms", record.first_seen_ms},
    {"last_seen_ms", record.last_seen_ms},
    {"end_reason", flow_end_reason_to_string(record.end_reason)},
    {"feature_schema_version", record.feature_schema_version},
    {"features", record.features},
};
```

- [ ] **Step 4: 응답 parser를 fail-closed-for-blocking으로 구현한다**

JSON 문법, object 여부, schema, `flow_id`, `model_version`, `ok` 타입을 검사한다. `ok=false`이면
string `error_code`가 있어야 하며 유효한 `AiResponse`로 반환하되 차단 정보는 사용하지 않는다.
`ok=true`이면 anomaly boolean과 finite·nonnegative score/threshold를 요구한다.

```cpp
if (response.at("flow_id").get<std::string>() != expected_flow_id) {
    *error = "flow_id 불일치";
    return std::nullopt;
}
if (response.at("model_version").get<std::string>() != expected_model_version) {
    *error = "model_version 불일치";
    return std::nullopt;
}
if (!std::isfinite(score) || score < 0.0 || !std::isfinite(threshold) || threshold < 0.0) {
    *error = "score 또는 threshold 범위 오류";
    return std::nullopt;
}
```

예외는 함수 밖으로 보내지 않고 `error`에 이유를 기록한 뒤 `std::nullopt`를 반환한다.

- [ ] **Step 5: 센서 target에 protocol source를 추가한다**

`CMakeLists.txt`의 `ips` source 목록에 다음을 추가한다.

```cmake
src/ai/ai_protocol.cpp
```

- [ ] **Step 6: C++ 정적 검사를 수행한다**

Run:

```bash
git diff --check -- src/ai/ai_types.h src/ai/ai_protocol.h src/ai/ai_protocol.cpp src/ai/flow_consumer.h CMakeLists.txt
rg -n "schema_version|flow_id|model_version|isfinite|drain_decisions" src/ai
```

Expected: 모든 계약 필드와 유한성 검사가 검색되고 whitespace 오류가 없다.

- [ ] **Step 7: Task 4를 커밋한다**

```bash
git add src/ai/ai_types.h src/ai/ai_protocol.h src/ai/ai_protocol.cpp src/ai/flow_consumer.h CMakeLists.txt
git commit -m "feat: define online AI message protocol"
```

---

### Task 5: 비동기 C++ ZeroMQ Flow consumer

**Files:**
- Create: `src/ai/async_ai_client.h`
- Create: `src/ai/async_ai_client.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `AiConfig`, `FlowConsumer`, protocol serializer/parser, `AiDecision`
- Produces: `AsyncAiClient::start()`, `set_online()`, `set_offline()`, `stop()`, `consume()`, `drain_decisions()`, `stats()`

- [ ] **Step 1: public 수명·상태 인터페이스를 선언한다**

```cpp
class AsyncAiClient final : public FlowConsumer {
 public:
    using TransportFailureHandler = std::function<void(const std::string&)>;

    AsyncAiClient(const AiConfig& config, TransportFailureHandler failure_handler);
    ~AsyncAiClient() override;

    void start();
    void set_online(std::string endpoint, std::string model_version);
    void set_offline();
    void stop();

    bool consume(FlowRecord record) override;
    std::vector<AiDecision> drain_decisions() override;
    AiClientStatsSnapshot stats() const;

 private:
    void run();
    void fail_transport(const std::string& reason, bool timed_out);
};
```

복사·대입은 삭제하고 destructor는 `stop()`을 호출한다.

- [ ] **Step 2: bounded 입력·결과 큐와 generation 상태를 추가한다**

한 mutex와 condition variable 아래 다음 상태를 둔다.

```cpp
std::mutex mutex_;
std::condition_variable condition_;
std::deque<FlowRecord> pending_flows_;
std::deque<AiDecision> pending_decisions_;
std::thread worker_;
bool started_ = false;
bool stop_requested_ = false;
bool online_ = false;
uint64_t connection_generation_ = 0;
std::string endpoint_;
std::string model_version_;
```

큐 상한은 `config.ai.queue_capacity` 하나를 입력·결과 큐에 같이 사용한다. 카운터는
`std::atomic<uint64_t>`로 보관해 Qt 메인 스레드가 lock 없이 snapshot을 읽게 한다.

- [ ] **Step 3: 패킷 스레드를 막지 않는 `consume()`을 구현한다**

```cpp
bool AsyncAiClient::consume(FlowRecord record) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!online_ || stop_requested_) {
        ++unavailable_dropped_;
        return false;
    }
    if (pending_flows_.size() >= queue_capacity_) {
        ++queue_full_dropped_;
        return false;
    }
    pending_flows_.push_back(std::move(record));
    ++submitted_;
    condition_.notify_one();
    return true;
}
```

offline과 queue-full 경고는 각각 첫 발생과 60초마다 최근 누계를 한 줄로 출력한다. 이 로그는
`AsyncAiClient`가 소유하고 `PacketCapture`는 `false`를 queue-full로 단정하지 않는다.

- [ ] **Step 4: online/offline 전환 시 모든 세대별 큐를 초기화한다**

`set_online()`은 endpoint와 model version을 교체하고 generation을 증가시킨 뒤 online으로 바꾼다.
`set_offline()`은 online을 false로 바꾸고 generation을 증가시키며 두 deque를 모두 clear한다.
두 함수 모두 condition variable을 깨운다. socket close는 worker가 generation 변경을 확인한 뒤
자기 스레드에서 수행한다.

- [ ] **Step 5: worker가 한 요청씩 REQ/REP 처리하게 한다**

`run()` 안에서 `zmq::context_t`와 `zmq::socket_t`를 생성한다. socket 옵션은 다음과 같다.

```cpp
socket.set(zmq::sockopt::linger, 0);
socket.set(zmq::sockopt::immediate, 1);
socket.set(zmq::sockopt::sndtimeo, response_timeout_ms_);
socket.set(zmq::sockopt::rcvtimeo, response_timeout_ms_);
```

worker는 online이고 입력 큐가 비어 있지 않을 때 한 Flow를 꺼내 로컬 `in_flight`와 현재
`connection_generation`을 보관한다. JSON을 send하고 reply를 receive한 뒤 generation을 다시
검사한다. 달라졌으면 이전 Python 세대의 응답이므로 조용히 폐기한다. 같을 때만
`parse_ai_response()`에 현재 Flow ID와 ready model version을 넘긴다.

- parser가 `std::nullopt`이면 protocol error를 올리고 다음 Flow로 진행한다.
- `ok=false`이면 error code를 기록하고 다음 Flow로 진행한다.
- 정상 성공이면 normal counter만 올리고 결과 큐에는 넣지 않는다.
- 이상 성공이면 원본 `FlowRecord`를 포함한 `AiDecision`을 만든다.
- 결과 큐가 가득 차면 condition variable에서 자리가 생길 때까지 AI worker만 기다린다. 대기
  predicate는 stop 또는 generation 변경도 확인해 재시작 시 오래된 결정을 폐기한다.
- 결과가 들어간 뒤 다음 입력 Flow를 꺼낸다.

send/receive timeout이나 ZeroMQ exception은 `fail_transport()`를 호출한다. 이 함수는 online을 false로
바꾸고 두 큐를 비우며 socket을 worker에서 닫은 뒤, mutex 밖에서 failure handler를 한 번 호출한다.

- [ ] **Step 6: drain과 멱등 종료를 구현한다**

```cpp
std::vector<AiDecision> AsyncAiClient::drain_decisions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AiDecision> drained;
    drained.reserve(pending_decisions_.size());
    while (!pending_decisions_.empty()) {
        drained.push_back(std::move(pending_decisions_.front()));
        pending_decisions_.pop_front();
    }
    condition_.notify_all();
    return drained;
}
```

`stop()`은 stop flag 설정, 두 큐 clear, notify, worker join 순서로 동작하며 여러 번 호출해도 안전해야
한다.

- [ ] **Step 7: 빌드 목록에 client를 추가한다**

```cmake
src/ai/async_ai_client.cpp
```

- [ ] **Step 8: 정적 검사를 수행한다**

Run:

```bash
git diff --check -- src/ai/async_ai_client.h src/ai/async_ai_client.cpp CMakeLists.txt
rg -n "linger|immediate|sndtimeo|rcvtimeo|connection_generation|pending_decisions|join" src/ai/async_ai_client.*
```

Expected: socket은 worker 함수 안에서만 생성·사용되고, stop 경로에 notify와 join이 있다.

- [ ] **Step 9: Task 5를 커밋한다**

```bash
git add src/ai/async_ai_client.h src/ai/async_ai_client.cpp CMakeLists.txt
git commit -m "feat: add asynchronous ZeroMQ AI client"
```

---

### Task 6: AI 판정의 캡처 스레드 적용

**Files:**
- Modify: `src/capture/packet_capture.h`
- Modify: `src/capture/packet_capture.cpp`

**Interfaces:**
- Consumes: `FlowConsumer::drain_decisions()`, `AiDecision`, 기존 Whitelist·BlockList·FlowManager
- Produces: `AiBlockHandler`, `PacketCapture::capture_stats()`, Rule/AI 분리 통계, 후속 Flow TTL 차단

- [ ] **Step 1: Qt 비의존 callback과 통계를 선언한다**

`PacketCapture`에 다음 interface를 추가한다.

```cpp
using AiBlockHandler = std::function<void(const AiBlockEvent&)>;

PacketCapture(const Config& config, Whitelist whitelist,
              std::unique_ptr<FlowConsumer> flow_consumer,
              AiBlockHandler ai_block_handler = {});

CaptureStatsSnapshot capture_stats() const;
```

private에는 handler와 세 atomic counter를 둔다.

```cpp
AiBlockHandler ai_block_handler_;
std::atomic<uint64_t> rule_blocks_{0};
std::atomic<uint64_t> ai_new_blocks_{0};
std::atomic<uint64_t> ai_duplicates_{0};
std::atomic<uint64_t> ai_whitelisted_{0};
```

기존 Rule 적중 분기에서 BlockList 등록 직전에 `++rule_blocks_;`를 추가한다.

- [ ] **Step 2: tick 시작에서 AI 결과를 먼저 적용한다**

`on_tick()` 첫 줄에서 `apply_ai_decisions(now)`를 호출한 뒤 Flow 만료와 BlockList 만료 정리를
수행한다. 이렇게 해야 이전 틱에 도착한 차단 결과보다 새 만료 Flow 전송이 앞서지 않는다.

```cpp
void PacketCapture::apply_ai_decisions(TimePoint now) {
    for (AiDecision& decision : flow_consumer_->drain_decisions()) {
        if (!decision.anomaly) {
            continue;
        }
        const uint32_t source_ip = decision.record.key.src_ip;
        if (whitelist_.is_whitelisted(source_ip)) {
            ++ai_whitelisted_;
            continue;
        }
        if (block_list_.is_blocked(source_ip, now)) {
            ++ai_duplicates_;
            LOG(INFO) << "AI_DECISION action=duplicate flow_id=" << decision.record.flow_id;
            continue;
        }
        flow_manager_.discard_source_flows(source_ip);
        block_list_.block(source_ip, block_ttl_seconds_, now);
        ++ai_new_blocks_;
        LOG(WARNING) << "AI_DECISION action=blocked flow_id=" << decision.record.flow_id
                     << " source_ip=" << ip_to_string(source_ip)
                     << " score=" << decision.score
                     << " threshold=" << decision.threshold
                     << " model_version=" << decision.model_version;
        if (ai_block_handler_) {
            ai_block_handler_(AiBlockEvent{decision.record.flow_id, source_ip,
                                           decision.score, decision.threshold,
                                           block_ttl_seconds_, decision.model_version});
        }
    }
}
```

- [ ] **Step 3: Flow 제출 실패의 잘못된 queue-full 로그를 제거한다**

`consume_flow()`은 `flow_consumer_->consume(std::move(record));`만 호출한다. offline과 queue-full의
원인은 consumer가 구분해 빈도 제한 로그와 카운터를 남긴다.

- [ ] **Step 4: action 통계 snapshot을 구현한다**

```cpp
CaptureStatsSnapshot PacketCapture::capture_stats() const {
    return CaptureStatsSnapshot{
        rule_blocks_.load(),
        ai_new_blocks_.load(),
        ai_duplicates_.load(),
        ai_whitelisted_.load(),
    };
}
```

- [ ] **Step 5: 정적 검사를 수행한다**

Run:

```bash
git diff --check -- src/capture/packet_capture.h src/capture/packet_capture.cpp
rg -n "apply_ai_decisions|is_whitelisted|is_blocked|discard_source_flows|ai_block_handler|AI_DECISION" src/capture/packet_capture.*
```

Expected: 적용 순서가 whitelist → duplicate → active Flow 폐기 → TTL block → callback이며 outbound
DROP 코드는 추가되지 않는다.

- [ ] **Step 6: Task 6을 커밋한다**

```bash
git add src/capture/packet_capture.h src/capture/packet_capture.cpp
git commit -m "feat: apply AI decisions to future flow blocking"
```

---

### Task 7: Qt Python 프로세스 supervisor

**Files:**
- Create: `src/app/ai_process_supervisor.h`
- Create: `src/app/ai_process_supervisor.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `AiConfig`, Qt5 `QProcess`·`QTimer`, `AiState`
- Produces: `AiProcessSupervisor::start()`, `stop()`, `report_transport_failure()`, `snapshot()`

- [ ] **Step 1: callback 기반 supervisor interface를 선언한다**

Qt custom signal을 만들지 않아 AUTOMOC 의존을 늘리지 않는다.

```cpp
struct AiSupervisorSnapshot {
    AiState state = AiState::DISABLED;
    std::string model_version;
    uint64_t restart_count = 0;
    std::string detail;
};

class AiProcessSupervisor final : public QObject {
 public:
    using ReadyHandler = std::function<void(const std::string&, const std::string&)>;
    using StateHandler = std::function<void(AiState, const std::string&)>;

    AiProcessSupervisor(const AiConfig& config, ReadyHandler ready_handler,
                        StateHandler state_handler, QObject* parent = nullptr);
    void start();
    void stop();
    void report_transport_failure(const std::string& reason);
    AiSupervisorSnapshot snapshot() const;
};
```

- [ ] **Step 2: PID endpoint와 QProcess 실행 인자를 고정한다**

constructor에서 다음 값을 만든다.

```cpp
socket_path_ = "/tmp/ips-with-ai-" + std::to_string(QCoreApplication::applicationPid()) +
               ".sock";
endpoint_ = "ipc://" + socket_path_;
process_.setProgram("/usr/bin/python3");
process_.setArguments({"-m", "ml.online_server", "--endpoint",
                       QString::fromStdString(endpoint_), "--artifact-dir",
                       QString::fromStdString(config.artifact_dir)});
process_.setWorkingDirectory(QDir::currentPath());
process_.setProcessChannelMode(QProcess::SeparateChannels);

QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
environment.insert("PYTHONNOUSERSITE", "1");
environment.insert(
    "PYTHONPATH",
    "/opt/ips-with-ai/python-packages:" + QDir::currentPath());
process_.setProcessEnvironment(environment);
```

각 start attempt 전에 `QFile::remove(socket_path)`로 이 센서 PID의 stale socket만 제거한다.

- [ ] **Step 3: stdout의 완전한 한 줄만 준비 메시지로 파싱한다**

`readyReadStandardOutput`에서 buffer에 append하고 newline 단위로 꺼낸다. JSON object가
`event=AI_READY`, `schema_version=1`, 비어 있지 않은 string `model_version`을 모두 만족할 때만
startup timer를 멈추고 상태를 ONLINE으로 바꾼다. ready handler에는 endpoint와 model version을
전달한다. 다른 stdout 줄과 stderr는 접두사 `AI_PROCESS`를 붙여 glog에 전달한다.

- [ ] **Step 4: 시작 제한시간과 프로세스 종료를 하나의 실패 경로로 모은다**

아래 사건은 `handle_failure(reason)` 하나로 들어간다.

- startup timer 10000ms 만료
- `QProcess::errorOccurred`
- STOPPING이 아닌 상태의 `QProcess::finished`
- ONLINE 상태에서 받은 `report_transport_failure()`

한 attempt의 `errorOccurred`와 `finished`가 연달아 와도 `failure_handled_for_attempt_` guard로 한 번만
처리한다. 실패 시작 즉시 재시작 기회가 남았으면 RESTART_WAIT, 없으면 OFFLINE을 state handler에
알려 client가 새 Flow를 거부하게 한다. 그 뒤 실행 중 process에는 terminate를 보내고 최대 2초
기다린다. 여전히 실행 중이면 kill하고 종료를 확인한다.

- [ ] **Step 5: 1·2·4초 재시작과 60초 reset을 구현한다**

```cpp
int restart_delay_ms(int attempt_index) {
    return 1000 * (1 << std::min(attempt_index, 2));
}
```

`restart_attempts_ < config.max_restarts`이면 RESTART_WAIT 상태에서 해당 delay의 single-shot
timer를 시작한다. 기본 3회는 1·2·4초이고 설정값을 4 이상으로 올리면 이후 delay는 4초를
유지한다. attempt 시작 때 restart count를 증가시킨다. 한도에 도달했을 때만 OFFLINE으로 바꾸고
detail에 실제 `max_restarts` 실패 횟수를 넣는다. 재시작 대기 중에는 OFFLINE 알림을 띄우지 않는다.
ONLINE 진입 후
`restart_reset_seconds * 1000` timer가 만료되면 연속 attempt index만 0으로 되돌린다. 표시용 누적
restart count는 감소시키지 않는다.

- [ ] **Step 6: 멱등 stop을 구현한다**

STOPPING 상태를 먼저 설정하고 모든 timer를 중지한다. process가 실행 중이면 terminate 후 최대
2000ms 기다리고, 남아 있으면 kill 후 종료를 확인한다. 마지막으로 정확한 PID socket만 제거한다.
STOPPING 중 발생한 QProcess signal은 재시작을 예약하지 않는다.

- [ ] **Step 7: CMake source 목록을 갱신한다**

```cmake
src/app/ai_process_supervisor.cpp
```

- [ ] **Step 8: 정적 검사를 수행한다**

Run:

```bash
git diff --check -- src/app/ai_process_supervisor.h src/app/ai_process_supervisor.cpp CMakeLists.txt
rg -n "AI_READY|1000|2000|4000|restart_reset_seconds|/usr/bin/python3|QFile::remove|STOPPING" src/app/ai_process_supervisor.*
```

Expected: 준비 전 ONLINE 전환이 없고 실패 event 중복 guard와 3단계 delay가 검색된다.

- [ ] **Step 9: Task 7을 커밋한다**

```bash
git add src/app/ai_process_supervisor.h src/app/ai_process_supervisor.cpp CMakeLists.txt
git commit -m "feat: supervise Python AI process"
```

---

### Task 8: Qt5 트레이 UI

**Files:**
- Create: `src/ui/tray_controller.h`
- Create: `src/ui/tray_controller.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `AiState`, `AiBlockEvent`
- Produces: `TrayController::set_ai_state()`, `show_ai_block()`, `show_ai_offline()`, `show_status()`

- [ ] **Step 1: Qt callback 기반 interface를 선언한다**

```cpp
class TrayController final : public QObject {
 public:
    using ActionHandler = std::function<void()>;

    TrayController(ActionHandler status_handler, ActionHandler exit_handler,
                   QObject* parent = nullptr);
    void set_ai_state(AiState state, const std::string& detail);
    void show_ai_block(const AiBlockEvent& event);
    void show_ai_offline(const std::string& reason);
    void show_status(const std::string& text);
    bool is_available() const;
};
```

- [ ] **Step 2: 코드로 회색·초록·노란 원형 아이콘을 만든다**

```cpp
QIcon make_status_icon(const QColor& color) {
    QPixmap pixmap(16, 16);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setPen(Qt::NoPen);
    painter.setBrush(color);
    painter.drawEllipse(2, 2, 12, 12);
    return QIcon(pixmap);
}
```

STARTING·RESTART_WAIT·STOPPING은 회색, ONLINE은 초록색, DISABLED·OFFLINE은 노란색을 사용한다.

- [ ] **Step 3: 메뉴 두 개와 availability fallback을 구현한다**

QMenu에 `상태 보기`와 `종료` QAction만 추가하고 각각 constructor callback을 호출한다.
`QSystemTrayIcon::isSystemTrayAvailable()`가 false이면 `available_=false`로 두고 경고 로그만 남긴다.
다른 controller 메서드는 이 경우 즉시 반환해 캡처·AI 동작에 영향을 주지 않는다.

- [ ] **Step 4: 이상·오프라인 알림과 상태 창을 구현한다**

`show_ai_block()`의 제목과 본문은 다음 형식을 사용한다.

```cpp
const QString body =
    QString::fromStdString(ip_to_string(event.source_ip)) +
    "의 종료된 Flow를 이상으로 판정했습니다.\n이후 수신 패킷을 " +
    QString::number(event.ttl_seconds) + "초 동안 차단합니다.\nscore=" +
    QString::number(event.score, 'g', 6) + ", threshold=" +
    QString::number(event.threshold, 'g', 6);
tray_icon_->showMessage("AI 이상 Flow 탐지", body, QSystemTrayIcon::Warning, 5000);
```

`show_ai_offline()`은 `AI 오프라인`을 한 번 표시한다. `show_status()`는
`QMessageBox::information(nullptr, "IPS 상태", QString::fromStdString(text))`를 사용한다.

- [ ] **Step 5: CMake source 목록을 갱신한다**

```cmake
src/ui/tray_controller.cpp
```

- [ ] **Step 6: 정적 검사를 수행한다**

Run:

```bash
git diff --check -- src/ui/tray_controller.h src/ui/tray_controller.cpp CMakeLists.txt
rg -n "상태 보기|종료|AI 이상 Flow 탐지|AI 오프라인|isSystemTrayAvailable|drawEllipse" src/ui
```

Expected: 메뉴가 두 개뿐이고 아이콘 세 상태와 popup 문자열이 모두 검색된다.

- [ ] **Step 7: Task 8을 커밋한다**

```bash
git add src/ui/tray_controller.h src/ui/tray_controller.cpp CMakeLists.txt
git commit -m "feat: add Qt system tray notifications"
```

---

### Task 9: 애플리케이션 수명·스레드 연결

**Files:**
- Create: `src/app/application_controller.h`
- Create: `src/app/application_controller.cpp`
- Modify: `src/main.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `AsyncAiClient`, `PacketCapture`, `AiProcessSupervisor`, `TrayController`, `Config`, `Whitelist`
- Produces: `ApplicationController::start()`, `begin_shutdown()`, 상태 snapshot 문자열, 안전한 Qt event loop

- [ ] **Step 1: controller 소유권을 선언한다**

```cpp
class ApplicationController final : public QObject {
 public:
    ApplicationController(Config config, Whitelist whitelist, QObject* parent = nullptr);
    ~ApplicationController() override;

    bool start();
    void begin_shutdown(int exit_code = 0);

 private:
    void post_transport_failure(const std::string& reason);
    void post_ai_block(const AiBlockEvent& event);
    void show_status();
    std::string format_status() const;
};
```

controller는 supervisor와 tray를 직접 소유하고, `PacketCapture`를 `unique_ptr`, 캡처 실행을
`std::thread`로 소유한다. `AsyncAiClient`는 기존 PacketCapture 생성자 계약에 맞춰
`unique_ptr<FlowConsumer>`로 PacketCapture에 넘기되 이동 전 raw pointer를 저장한다.
PacketCapture가 파괴되기 전까지만 raw pointer를 사용하고 종료 순서로 수명을 보장한다.

- [ ] **Step 2: worker callback을 Qt main thread로 전달한다**

AI transport failure callback과 AI block callback은 worker에서 직접 Qt 객체를 호출하지 않는다.

```cpp
QMetaObject::invokeMethod(
    this,
    [this, reason]() { supervisor_->report_transport_failure(reason); },
    Qt::QueuedConnection);
```

```cpp
QMetaObject::invokeMethod(
    this,
    [this, event]() { tray_->show_ai_block(event); },
    Qt::QueuedConnection);
```

캡처 thread의 `PacketCapture::start()`가 반환하면 결과를 같은 방식으로 main thread에 전달한다.
shutdown 요청 전 false 반환이면 exit code 1로 전체 종료하며, 정상 stop 뒤 true 반환은 재종료를
요청하지 않는다.

- [ ] **Step 3: AI ready·offline 상태를 client와 tray에 연결한다**

supervisor ready callback은 main thread에서 다음 두 호출을 순서대로 실행한다.

```cpp
ai_client_->set_online(endpoint, model_version);
tray_->set_ai_state(AiState::ONLINE, model_version);
```

STARTING·RESTART_WAIT·OFFLINE·STOPPING state callback은 먼저 `ai_client_->set_offline()`을 호출하고
tray 상태를 갱신한다. supervisor는 재시작 기회가 남았을 때 RESTART_WAIT, 모두 소진됐을 때만
OFFLINE을 전달하므로 OFFLINE에서 `show_ai_offline()`을 한 번 호출한다.

- [ ] **Step 4: start 순서를 구현한다**

1. `AsyncAiClient::start()`
2. `PacketCapture::start()`를 실행하는 capture thread 생성
3. AI enabled이면 supervisor `start()`, 아니면 DISABLED 상태 표시

캡처 thread를 먼저 시작하되 Qt main thread는 결과를 기다리지 않는다. AI 준비 전 종료 Flow는 client가
즉시 거부한다.

- [ ] **Step 5: 상태 보기 문자열을 세 snapshot에서 만든다**

`format_status()`는 supervisor, client, PacketCapture snapshot을 읽어 아래 항목을 줄 단위로
만든다.

```text
AI 상태: ONLINE
모델 버전: ae-20260828T120000Z
가동 시간: 125초
Python 재시작: 1
AI 큐 등록/즉시 폐기: 100/3
정상/이상 응답: 92/5
Rule 차단: 8
AI 신규 차단/중복/화이트리스트 제외: 4/1/0
프로토콜 오류/타임아웃: 0/1
```

- [ ] **Step 6: 종료 순서를 멱등으로 구현한다**

`begin_shutdown()`은 `stopping_` guard 뒤 다음 순서로 실행한다.

1. tray를 STOPPING 회색으로 변경
2. `capture_->stop()` 요청
3. `ai_client_->stop()`으로 입력·결과 큐 clear와 worker join
4. `supervisor_->stop()`으로 Python terminate/kill
5. capture thread join; 이 반환 전에 PacketCapture가 NFQUEUE와 iptables를 정리함
6. `QCoreApplication::exit(exit_code)`

destructor는 아직 종료하지 않았다면 같은 함수를 호출하며, 이미 join된 thread에는 join을 다시
호출하지 않는다.

- [ ] **Step 7: `main()`을 root Qt 진입점으로 바꾼다**

시그널 handler는 아래 flag만 설정한다.

```cpp
volatile std::sig_atomic_t g_shutdown_requested = 0;

void handle_signal(int /*signum*/) { g_shutdown_requested = 1; }
```

main 흐름은 다음으로 고정한다.

```cpp
int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = true;
    if (geteuid() != 0) {
        LOG(ERROR) << "root 계정에서만 실행할 수 있습니다";
        return 1;
    }
    const auto config = load_config("config.json");
    if (!config.has_value()) {
        return 1;
    }
    Whitelist whitelist;
    if (!whitelist.load(config->whitelist)) {
        return 1;
    }
    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    ApplicationController controller(*config, std::move(whitelist));
    if (!controller.start()) {
        return 1;
    }
```

200ms `QTimer`가 signal flag를 확인해 `controller.begin_shutdown(0)`을 호출한다. `app.exec()` 반환
뒤 `google::ShutdownGoogleLogging()`을 호출하고 Qt exit code를 반환한다.

- [ ] **Step 8: CMake source 목록을 갱신한다**

```cmake
src/app/application_controller.cpp
```

- [ ] **Step 9: Ubuntu에서 센서 target만 빌드한다**

Run on Ubuntu:

```bash
cmake -S . -B build
cmake --build build --target ips -j2
```

Expected: `ips` target exit code 0. 테스트 executable과 `ctest`는 실행하지 않는다.

- [ ] **Step 10: Task 9를 커밋한다**

```bash
git add src/app/application_controller.h src/app/application_controller.cpp src/main.cpp CMakeLists.txt
git commit -m "feat: coordinate capture AI and Qt lifecycles"
```

---

### Task 10: 운영 문서와 Ubuntu 수동 검증

**Files:**
- Create: `config.example.json`
- Modify: `README.md`
- Modify: `docs/design/online_inference.md`
- Modify: `docs/design/ai_training.md`
- Modify: `docs/code_explained.md`

**Interfaces:**
- Consumes: 완성된 실행 옵션·설정·로그·트레이 상태
- Produces: root GUI 운영 절차, 장애 재현 절차, 수동 완료 증거

- [ ] **Step 1: 전체 기본 설정 예시를 추가한다**

`config.example.json`은 현재 Rule 설정을 보존하면서 다음 AI object를 포함한다.

```json
{
  "queue_num": 0,
  "block_ttl_seconds": 600,
  "whitelist": [],
  "rules": {
    "window_seconds": 10,
    "port_scan": {"distinct_port_threshold": 20},
    "syn_flood": {"syn_threshold": 100}
  },
  "ai": {
    "enabled": true,
    "artifact_dir": "ml/artifacts",
    "queue_capacity": 1024,
    "startup_timeout_ms": 10000,
    "response_timeout_ms": 2000,
    "max_restarts": 3,
    "restart_reset_seconds": 60
  }
}
```

- [ ] **Step 2: README 설치·실행 명령을 실제 구조와 맞춘다**

Ubuntu dependency 명령에 다음 패키지를 포함한다.

```bash
apt install cmake build-essential iptables libnetfilter-queue-dev libgoogle-glog-dev \
  nlohmann-json3-dev libzmq3-dev cppzmq-dev qtbase5-dev libgtest-dev \
  python3-pip
install -d -m 0755 -o root -g root /opt/ips-with-ai/python-packages
/usr/bin/python3 -m pip install --target /opt/ips-with-ai/python-packages \
  -r ml/runtime-requirements.txt
chown -R root:root /opt/ips-with-ai
chmod -R go-w /opt/ips-with-ai
```

`ml/requirements.txt`는 오프라인 학습용 가상환경에서 사용한다. root 센서의 고정
`/usr/bin/python3`은 일반 user site를 읽지 않고 위 root 소유 target directory만 추가로 읽는다.

root GUI 터미널에서 저장소 루트를 current directory로 두고 실행한다.

```bash
cp config.example.json config.json
cmake -S . -B build
cmake --build build --target ips -j2
./build/ips
```

일반 사용자용 `sudo ./ips`를 공식 실행 예시로 두지 않는다. root GUI 로그인 환경과
`geteuid()==0` 조건을 바로 위에 명시한다.

- [ ] **Step 3: 설계 문서의 이전 결정을 새 spec과 동기화한다**

`docs/design/online_inference.md`에서 다음 오래된 설명을 교체한다.

- 사용자가 endpoint를 설정함 → PID 기반 IPC 자동 생성
- AI 전용 TTL → 기존 `block_ttl_seconds` 공유
- 일반 dashboard 표시 → Qt5 tray-only 상태·알림
- 단순 AI fail-open → QProcess 자동 실행, 1·2·4초 최대 3회 재시작

상세 계약은 spec 문서 링크로 연결하고 같은 JSON schema를 중복해서 다르게 쓰지 않는다.
`docs/design/ai_training.md`에는 metadata의 `feature_schema_version`, `model_version`과 secure loader를
추가한다. `docs/code_explained.md`에는 세 스레드 소유권과 현재 Flow/후속 Flow 차이를 쉬운 말로
설명한다.

- [ ] **Step 4: 전체 정적 검증을 수행한다**

Run:

```bash
git diff --check
python3 -m compileall ml
python3 -m ruff check ml
cmake -S . -B build
cmake --build build --target ips -j2
```

Expected: 모두 exit code 0. `ctest`와 테스트 executable은 실행하지 않는다.

- [ ] **Step 5: root GUI 기본 동작을 기록한다**

Run in Ubuntu root GUI terminal:

```bash
./build/ips
```

다른 terminal에서 다음을 확인한다.

```bash
pgrep -a -f "python3 -m ml.online_server"
find /tmp -maxdepth 1 -user root -name "ips-with-ai-*.sock" -ls
iptables -S INPUT
iptables -S OUTPUT
iptables -S IPS_WITH_AI
```

Expected: Python 자식 한 개, PID 기반 IPC socket 한 개, 관리 INPUT·OUTPUT jump 한 개씩, tray 초록
아이콘과 model version이 확인된다.

고정 interpreter가 분리 설치된 runtime을 실제로 읽는지도 확인한다.

```bash
PYTHONNOUSERSITE=1 \
PYTHONPATH=/opt/ips-with-ai/python-packages:. \
/usr/bin/python3 -c "import numpy, torch, zmq; print(torch.__version__)"
```

Expected: import exit code 0이고 출력된 PyTorch major/minor가 2.1 이상이다.

- [ ] **Step 6: AI 장애와 Rule-only 지속을 기록한다**

Python PID를 조회한 뒤 강제 종료한다.

```bash
ai_process_pid=$(pgrep -f "^/usr/bin/python3 -m ml.online_server" | head -n 1)
kill -9 "$ai_process_pid"
```

Expected: in-flight·입력·결과 Flow가 폐기되고 1초 뒤 Python이 다시 생긴다. 같은 방법으로 새 PID를
세 번 연속 종료하면 delay가 1초·2초·4초로 증가하고 마지막에는 노란 tray와 `AI 오프라인` 알림이
나온다. 이 동안 Kali VM에서 기존 Rule 임계값을 넘는 SYN 패킷을 보내 Rule DROP 로그와 차단이 계속
되는지 기록한다.

- [ ] **Step 7: 응답 timeout과 정상 복구를 기록한다**

AI가 ONLINE인 상태에서 Python을 정지하고 원격 Flow를 하나 종료시킨다.

```bash
ai_process_pid=$(pgrep -f "^/usr/bin/python3 -m ml.online_server" | head -n 1)
kill -STOP "$ai_process_pid"
```

Expected: 요청 뒤 약 2초에 timeout이 기록되고 supervisor가 해당 Python을 종료한 뒤 재시작한다.
packet verdict와 Rule counter는 계속 증가한다.

- [ ] **Step 8: 이상·중복·TTL·화이트리스트 동작을 기록한다**

오프라인 평가에서 threshold를 넘는 것으로 확인된 공격 트래픽을 Kali VM에서 같은 고정 IP로
재생한다. 상태 창과 로그에서 다음 순서를 캡처한다.

1. `anomaly_responses` 증가
2. `AI_DECISION action=blocked` 한 건
3. tray popup 한 번
4. 같은 IP의 다음 inbound 패킷 DROP
5. TTL 내 추가 결과는 `action=duplicate`이고 popup 없음
6. TTL 만료 후 통과

그 IP를 `config.json` whitelist에 넣어 재시작하고 같은 입력을 보내면 `whitelisted`만 증가하고
BlockList와 popup은 변하지 않아야 한다.

- [ ] **Step 9: 정상 종료 정리를 기록한다**

tray `종료`와 별도 실행의 `SIGTERM`을 각각 확인한다.

```bash
sensor_process_pid=$(pgrep -x ips | head -n 1)
kill -TERM "$sensor_process_pid"
```

종료 후 다음 명령 결과에 관리 자원이 없어야 한다.

```bash
pgrep -a -f "python3 -m ml.online_server"
find /tmp -maxdepth 1 -user root -name "ips-with-ai-*.sock" -ls
iptables -S INPUT
iptables -S OUTPUT
iptables -S IPS_WITH_AI
```

Expected: Python과 IPC socket이 없고 INPUT·OUTPUT에 관리 jump가 없으며 전용 chain 조회는 실패한다.

- [ ] **Step 10: Task 10을 커밋한다**

```bash
git add config.example.json README.md docs/design/online_inference.md docs/design/ai_training.md docs/code_explained.md
git commit -m "docs: document online AI operation and verification"
```

---

## Final Review Gate

- [ ] spec 1~20장의 각 요구사항이 Task 1~10 중 하나에 연결되는지 표와 checklist로 대조한다.
- [ ] `rg -n "T[B]D|implem[e]nt later|add appropr[i]ate|write te[s]ts for|similar t[o]" docs/superpowers/plans/2026-08-28-online-ai-tray.md` 결과가 비어 있는지 확인한다.
- [ ] `AiState`, `AiDecision`, `AiBlockEvent`, snapshot 이름과 method signature가 모든 task에서 같은지 확인한다.
- [ ] `git diff --check`와 Python 정적 검사, Ubuntu `ips` target build 결과를 기록한다.
- [ ] 테스트 파일이 수정되지 않았고 `ctest`·테스트 executable을 실행하지 않았는지 확인한다.
- [ ] root GUI에서 기본 동작·재시작·timeout·차단·TTL·화이트리스트·정상 종료 증거를 README 체크리스트에 연결한다.
