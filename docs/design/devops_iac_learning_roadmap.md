# IPS 프로젝트 DevOps·IaC 학습 로드맵

## 1. 문서 목적

이 문서는 IPS 기능을 더 많이 만드는 계획이 아니라, 한 개발자가 다음 DevOps 흐름을 직접
반복해 보며 익히기 위한 학습 순서다.

```text
코드 변경 → 자동 검사 → 패키징 → Kali 환경 구성 → 서비스 실행 → 지표 확인
```

현재 프로젝트의 Kali 센서·Python AI·향후 Prometheus/Grafana를 실습 대상으로 사용한다.
실제 패킷 차단 규칙과 운영 네트워크를 자동 변경하는 것은 학습 범위에 포함하지 않는다.

## 2. IaC와 DevOps 도구의 역할

| 영역 | 도구 | 쉽게 말하면 | 이 프로젝트에서의 역할 |
| --- | --- | --- | --- |
| CI/CD | GitHub Actions | 코드가 바뀌면 검사·빌드하는 자동 작업 | Python 테스트, Ruff, Bandit, CMake/CTest |
| 애플리케이션 묶음 | Docker Compose | 여러 컨테이너를 한 번에 실행 | Prometheus·Grafana·Exporter 실습 |
| 서버 구성 관리 | Ansible | 서버를 원하는 상태로 맞춤 | Kali 패키지, 디렉터리, systemd, runtime 구성 |
| 인프라 프로비저닝 | OpenTofu 또는 Terraform | VM·네트워크 같은 자원을 코드로 생성 | 공격자 VM·센서 VM 실험 환경 구성 |
| 관측성 | Prometheus·Grafana | 상태를 수치로 모으고 화면에 표시 | 처리량, 지연, 차단, 큐 상태 대시보드 |

IaC를 두 종류로 나누어 이해한다.

- **프로비저닝:** 아직 없는 VM·네트워크·디스크를 만든다. OpenTofu/Terraform의 `write → plan → apply` 흐름이 여기에 해당한다.
- **구성 관리:** 이미 있는 Kali 서버에 패키지·설정·서비스를 설치하고 원하는 상태로 맞춘다. Ansible이 여기에 해당한다.

따라서 현재처럼 이미 존재하는 Kali 한 대를 관리할 때는 Ansible이 먼저고, 여러 VM을
반복해서 만들 때 OpenTofu/Terraform을 추가한다.

## 3. 권장 학습 순서

### 0단계: Linux 운영 기초

먼저 다음 명령과 개념을 익힌다.

- `systemd`, `systemctl`, `journalctl`, 프로세스·시그널·종료 코드
- SSH, 파일 소유자·그룹·권한, `/etc`, `/var/lib`, `/var/log`
- `apt`, Python `venv`, 환경 변수, 로그 회전
- `iptables`/`nftables`, NFQUEUE, 네트워크 네임스페이스

완료 기준은 센서 프로세스를 수동으로 시작·중지하고, 로그·권한·실패 원인을 직접
확인할 수 있는 것이다. 이 단계가 부족하면 IaC가 실패했을 때 도구 탓인지 Linux 설정
탓인지 구분하기 어렵다.

### 1단계: GitHub Actions로 CI 완성

현재 저장소의 워크플로를 학습 재료로 삼는다.

- Pull Request마다 Python 테스트·Ruff·Bandit·CMake/CTest를 실행한다.
- 실패 로그에서 원인을 찾고 수정 후 다시 실행한다.
- 빌드 결과와 테스트 결과를 별도 artifact로 보관한다.
- 비밀값은 YAML에 쓰지 않고 GitHub Secrets/Variables의 역할을 구분한다.

GitHub Actions는 빌드·테스트·배포 작업을 자동화하는 CI/CD 플랫폼이다.
[공식 시작 문서](https://docs.github.com/en/actions/get-started/understand-github-actions)

### 2단계: Docker와 Compose

처음부터 NFQUEUE 센서 자체를 컨테이너화하지 않는다. 권한·호스트 네트워크·iptables
상호작용이 복잡하고, 잘못된 설정이 실제 패킷 경로를 바꿀 수 있기 때문이다.

먼저 다음 관측성 묶음을 Compose로 실행한다.

```text
Prometheus ← exporter/metrics endpoint
Grafana    ← Prometheus data source
```

학습할 항목은 이미지·컨테이너·볼륨·네트워크·healthcheck·환경 변수·로그 확인이다.
Compose는 여러 컨테이너 애플리케이션을 YAML 한 파일로 정의하고 실행하는 도구다.
[공식 문서](https://docs.docker.com/compose)

### 3단계: Ansible — 첫 번째 IaC 실습

Ansible을 현재 프로젝트의 첫 IaC 도구로 사용한다. Ansible은 inventory에 적은 관리
노드의 원하는 상태를 playbook으로 선언하고 반복 적용한다.
[공식 시작 문서](https://docs.ansible.com/projects/ansible/latest/getting_started/index.html)

권장 실습 구조는 다음과 같다.

```text
infra/ansible/
├── inventory.ini
├── playbook.yml
└── roles/
    ├── common/
    ├── sensor_runtime/
    └── observability/
```

실습 순서:

1. Kali에 필요한 빌드·NFQUEUE·Qt 패키지를 설치한다.
2. root 소유 디렉터리와 로그 디렉터리를 만든다.
3. Python runtime과 C++ binary 경로를 배치한다.
4. sensor systemd unit을 등록하고 `systemctl enable`/`start`를 연습한다.
5. Prometheus 설정과 Grafana provisioning 파일을 배치한다.
6. `--check --diff`로 변경을 미리 확인한 뒤에만 적용한다.

첫 playbook에는 `iptables`/NFQUEUE 규칙 등록을 넣지 않는다. 방화벽 변경은 별도 태그와
명시적인 실행 명령으로 분리하고, 격리된 실험 네트워크에서만 검증한다.

### 4단계: OpenTofu 또는 Terraform

둘 다 같은 종류의 프로비저닝 도구이므로 처음부터 둘을 동시에 배우지 않는다. 다음
실험처럼 “환경 자체를 코드로 만든다”는 감각을 익힌다.

```text
실험 네트워크
├── sensor VM
└── attacker VM
```

학습 항목:

- provider, resource, variable, output, module
- `init`, `fmt`, `validate`, `plan`, `apply`, `destroy`
- state 파일의 역할과 비밀값 관리
- plan 결과 검토 후 apply하기
- 환경별 변수 분리와 재현성

OpenTofu의 핵심 흐름도 `write → plan → apply`이며, 구성과 실제 자원의 차이를 state로
추적한다. [OpenTofu 공식 문서](https://opentofu.org/docs/v1.11/intro/core-workflow/)

현재 Kali 한 대만 운영할 때는 이 단계를 생략해도 되며, VM을 여러 번 만들거나 클라우드
실험으로 확장할 때 시작한다.

### 5단계: Prometheus와 Grafana

센서와 AI runtime에서 다음 숫자만 우선 노출한다.

- 처리한 패킷·플로우 수
- Rule 탐지·AI 이상 판정·TTL 차단 수
- AI 큐 길이·timeout·재시작 수
- 처리 지연 p50/p95와 커널/NFQUEUE drop 수
- 프로세스 health와 모델 버전

Prometheus는 시계열 지표를 수집·저장하고, Grafana는 Prometheus를 data source로 조회해
대시보드로 표시한다. [Prometheus 개요](https://prometheus.io/docs/introduction/overview/)
[Grafana data source](https://grafana.com/docs/grafana/latest/datasources/)

첫 화면은 **로컬 읽기 전용 관제**로 제한한다. Grafana에서 차단·Rule 수정·서비스
재시작을 허용하지 않고, Qt 즉시 알림과 패킷 처리 경로를 분리한다. Prometheus label에
IP·원본 payload·flow ID를 무제한으로 넣지 않아 시계열 폭증과 개인정보 노출을 막는다.

### 6단계: Kubernetes는 후순위

Kubernetes·Helm·service mesh는 여러 서비스·노드 운영을 배운 뒤에 추가한다. 현재
졸업작품 규모에서는 먼저 Linux, CI, Compose, Ansible, 관측성을 완성하는 편이 더 많은
DevOps 핵심 경험을 짧은 경로로 얻는다.

## 4. 첫 번째 통합 실습의 완료 조건

다음 명령 한 번으로 새 Kali 실험 환경을 재현할 수 있으면 1차 목표를 달성한 것으로 본다.

```text
Ansible: 패키지·디렉터리·systemd·runtime 구성
       ↓
빌드·테스트: GitHub Actions와 동일한 검사 실행
       ↓
Compose: Prometheus·Grafana 실행
       ↓
확인: 대시보드에서 센서 health와 안전한 합성 트래픽 지표 조회
```

필수 증거:

- Ansible `--check --diff` 결과와 실제 적용 결과
- systemd 상태·journal 로그
- Python/C++ 테스트 결과
- Prometheus target health와 Grafana dashboard JSON
- 적용 전후 설정 diff

## 5. 현재 프로젝트에 적용할 때의 제한

- Kali 검증 전에는 IaC가 Linux 동작을 보장한다고 말하지 않는다.
- root 소유 파일·symbolic link·systemd·NFQUEUE는 root 소유 Linux 파일시스템에서 확인한다.
- 일반 네트워크에서 공격 트래픽을 자동 생성하거나 방화벽을 자동 변경하지 않는다.
- 비밀번호·토큰·모델 원본 데이터는 Git에 커밋하지 않는다.
- Grafana 장애가 센서의 차단·허용 판단을 멈추게 하지 않는다.
- 실제 CICIDS2017 데이터 검증과 IaC 실습 검증은 서로 다른 증거로 기록한다.

## 6. 현재 상태

현재 저장소에는 GitHub Actions와 Python 안정화 테스트가 있고, Kali에서의 Linux 통합
실행은 아직 남아 있다. Grafana와 IaC는 이 문서의 순서에 따라 다음 단계에서 설계·구현한다.
