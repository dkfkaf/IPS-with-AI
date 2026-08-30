# 상용 IPS/NGFW 대비 범위와 한계

> 대상: 대학생 졸업작품 수준의 AI 기반 인라인 IPS
> 비교 기준: 상용 IPS/NGFW가 일반적으로 제공하는 기능군

## 1. 결론

본 프로젝트는 **단일 방어 호스트의 IPv4 inbound에서 Rule 기반 즉시 차단과 AI 기반 사후
탐지·후속 플로우 차단을 시연하는 연구용 프로토타입**이다. OUTPUT은 양방향 Flow 통계를
보충할 때만 관찰하며 항상 통과시킨다. 상용 IPS/NGFW와 같은 완전한 네트워크 보안 장비가 아니다.

상용 제품은 애플리케이션 식별·정책별 제어, TLS 복호화 검사, 시그니처·위협 인텔리전스 업데이트, 중앙 이벤트 관리, HA 등을 제공한다. 예를 들어 FortiGate는 애플리케이션 제어·IPS 프로토콜 디코더와 TLS 검사 구성을 제공하며, Cisco Secure Firewall은 침입 이벤트를 중앙 관리 시스템으로 집계한다.

- 참고: [Fortinet Application Control](https://docs.fortinet.com/document/fortigate/latest/administration-guide/302748/application-control)
- 참고: [Fortinet SSL/SSH Inspection](https://docs.fortinet.com/document/fortigate/7.6.0/amp-architecture-guide/493047/key-components)
- 참고: [Fortinet IPS High Availability](https://docs.fortinet.com/document/fortigate/7.4.0/ips-architecture-guide/165358/ha)
- 참고: [Cisco Secure Firewall intrusion events](https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/admin/760/management-center-admin-76.pdf)

## 2. 비교표

| 기능 영역 | 상용 IPS/NGFW | 본 프로젝트 | 처리 방침 |
| --- | --- | --- | --- |
| 배치 범위 | 라우터·브리지·가상 와이어·클라우드 등 다양한 인라인 배치 | 단일 호스트 IPv4 INPUT·OUTPUT 관찰, inbound만 판정 | 범위 제외 명시 |
| 즉시 차단 | 시그니처·정책·콘텐츠 판정으로 현재 세션을 즉시 차단 | Rule만 즉시 DROP, AI는 종료된 플로우를 알림 | 현재 플로우 AI 차단 미지원 |
| AI 대응 | 제품별 정책에 따라 차단·격리·경보 | 이상 이벤트 후 동일 출발지 IP의 후속 플로우 TTL 차단 | 구현 대상 |
| IPv6 | IPv4/IPv6 정책과 검사 | IPv4만 설계 | 범위 제외 |
| 패킷·세션 처리 | 조각 재조립, TCP stream 재조립, 재전송·순서 변경 처리 | 기본 IP/TCP/UDP 헤더와 플로우 통계 | 범위 제외·우회 가능성 명시 |
| 지원 프로토콜 | ICMP, SCTP, GRE, QUIC/HTTP3 등 다수 | TCP/UDP 중심 | 범위 제외 |
| L7 식별 | HTTP/DNS/메일 등 프로토콜 디코더와 앱 식별 | 없음 | 범위 제외 |
| TLS 검사 | 인증서 관리 전제의 복호화·콘텐츠 검사 | 복호화하지 않는 플로우 메타데이터 분석 | 범위 제외 |
| 침입 시그니처 | CVE·공격 카테고리·위험도 기반 시그니처 DB와 자동 갱신 | 포트 스캔·SYN 플러드 Rule 2종 | 졸업작품 최소 Rule |
| 위협 인텔리전스 | IP·도메인·파일 평판과 IOC feed | 없음 | 범위 제외 |
| DDoS 방어 | rate limit, 세션·연결 상한, 공격 유형별 정책 | SYN 카운트 Rule, NFQUEUE 처리 한계 | 제한 사항 명시 |
| 정책 모델 | zone/interface, 주소·사용자·서비스·시간·앱 기반 정책 | 화이트리스트, 출발지 IP TTL 차단 | 최소 정책 모델 |
| 차단 단위 | 세션·IP·URL·도메인·사용자·앱별 조치 | 출발지 IP | NAT 공유 IP 오차단 위험 명시 |
| 오탐 처리 | monitor/block/quarantine, 예외·승인·정책 롤백 | 화이트리스트, TTL 자동 해제 | 구현 대상 |
| 모델 운영 | 서명·엔진·모델 버전 배포와 롤백 | feature/model version 검증, 수동 모델 배포 | 자동 배포 제외 |
| AI 품질 관리 | 드리프트, 피드백, 대규모 데이터 기반 튜닝 | CICIDS2017 오프라인 학습·평가 | 연구 한계 명시 |
| 장애 처리 | 전용 dataplane, watchdog, HA·상태 동기화 | AI 장애 시 fail-open, 단일 센서 | watchdog/HA 제외 |
| 과부하 처리 | 하드웨어 가속, 멀티큐, 클러스터 확장 | NFQUEUE 단일 처리 경로, AI 대기열 상한 | 처리량 측정·한계 기록 |
| 가용성 | active-passive/active-active HA, 세션 동기화 | 없음 | 범위 제외 |
| 로그·분석 | 중앙 수집, SIEM 연동, 장기 보존·검색 | 로컬 로그·Qt 이벤트 표시 | 외부 SIEM 제외 |
| 경보 | 이메일·syslog·SOAR·티켓 연동, 중복 억제 | 대시보드·로그, 오류 경보 빈도 제한 | 외부 연동 제외 |
| 관리 보안 | 다중 관리자, RBAC, 감사 로그, API | 로컬 단일 관리자 데모 | 인증·감사 로그는 향후 과제 |
| 설정 운영 | 정책 버전·백업·롤백·중앙 배포 | `config.json` 시작 시 로드 | hot reload·롤백 제외 |
| 제품 보안 | 서명 검증 업데이트, SBOM, 취약점 관리, 권한 분리 | root 실행, 입력 길이 검증 | 안전한 입력 처리만 구현 |
| 검증 | 광범위한 공격 DB·상호운용성·장기 부하 검증 | VM 기반 포트 스캔·SYN 플러드·AI 평가 | 재현 가능한 실험 기록 |

## 3. 졸업작품에서 반드시 증명할 것

1. Rule 기반 포트 스캔·SYN 플러드가 현재 패킷을 DROP한다.
2. AI가 이상 플로우를 탐지해 score·threshold·모델 버전과 함께 이벤트를 남긴다.
3. AI 이상 결과가 같은 출발지 IP의 **후속 플로우**를 TTL 동안 차단한다.
4. 화이트리스트·TTL 만료·AI 장애·AI 대기열 포화에서 fail-open 정책이 문서대로 동작한다.
5. 탐지율·오탐률·처리량·지연·NFQUEUE 드롭 수를 실험 환경과 함께 기록한다.

## 4. 발표에서의 표현

- 적절한 표현: “상용 IPS의 전체 기능을 목표로 하지 않고, 하이브리드 Rule+AI 탐지와 안전한 후속 플로우 차단을 검증한 프로토타입이다.”
- 피할 표현: “상용 IPS와 동등하다”, “AI가 모든 악성 패킷을 실시간 차단한다”, “제로데이를 보장해 탐지한다.”

*상세 AI 이벤트 계약·장애 정책·측정 항목은 `online_inference.md`를 따른다.*
