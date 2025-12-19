# ipTIME Firmware Fuzzer v2.0

ipTIME 공유기 펌웨어를 대상으로 하는 **고급 종합 퍼징 프레임워크**입니다.

---

## 🆕 v2.0 새 기능

| 기능                 | 설명                                                         |
| -------------------- | ------------------------------------------------------------ |
| **뮤테이션 엔진**    | AFL-style 11개 뮤테이터 (BitFlip, Arithmetic, Dictionary 등) |
| **에너지 스케줄링**  | 5종 스케줄링 전략 (FAST, COV, EXPLORE, EXPLOIT, QUAD)        |
| **고급 크래시 감지** | 응답 패턴 분석, 타이밍 이상 감지, 서비스 상태 확인           |
| **PPTP 퍼저**        | VPN 프로토콜 퍼징 추가                                       |
| **프로토콜 문법**    | 구조화된 메시지 생성 및 뮤테이션                             |
| **QEMU 커버리지**    | 코드 커버리지 수집 (그레이박스 퍼징)                         |
| **웹 대시보드**      | 실시간 통계 및 크래시 타임라인                               |
| **분산 퍼징**        | Redis 기반 멀티노드 코디네이션                               |
| **재현성**           | 뮤테이션 이력 기록 및 결정론적 재현                          |
| **QEMU 하네스**      | 시스템 에뮬레이션 기반 퍼징                                  |

---

## 🚀 빠른 시작

### 설치

```bash
pip install -r requirements.txt
```

### 기본 실행

```bash
# 모든 퍼저 동시 실행
python main.py -t 192.168.0.1

# 특정 퍼저만
python main.py -t 192.168.0.1 --http-only
python main.py -t 192.168.0.1 --udp-only
python main.py -t 192.168.0.1 --upnp-only
```

### 웹 대시보드

```bash
# 대시보드 활성화
python main.py -t 192.168.0.1 --dashboard

# 브라우저에서 http://127.0.0.1:8888 접속
```

### 분산 퍼징

```bash
# 노드 1
python main.py -t 192.168.0.1 --redis redis://master:6379

# 노드 2
python main.py -t 192.168.0.1 --redis redis://master:6379
```

---

## 📁 프로젝트 구조

```
iptime-fuzzer/
├── main.py                 # 엔트리 포인트
├── config/                 # 설정 파일
│   └── fuzzer.yaml
├── core/                   # 핵심 모듈
│   ├── controller.py       # 메인 컨트롤러
│   ├── scheduler.py        # 에너지 기반 스케줄러 🆕
│   ├── distributed.py      # 분산 코디네이터 🆕
│   └── reproducer.py       # 테스트케이스 재현 🆕
├── fuzzers/                # 프로토콜별 퍼저
│   ├── base.py             # 베이스 클래스
│   ├── udp_fuzzer.py       # UDP 퍼저
│   ├── http_fuzzer.py      # HTTP/CGI 퍼저
│   ├── upnp_fuzzer.py      # UPnP/SSDP 퍼저
│   └── pptp_fuzzer.py      # PPTP VPN 퍼저 🆕
├── mutators/               # 뮤테이션 엔진
│   └── mutator_engine.py   # AFL-style 뮤테이터 🆕
├── monitors/               # 모니터링
│   ├── crash_detector.py   # 크래시 감지 🆕
│   ├── coverage.py         # QEMU 커버리지 🆕
│   └── dashboard.py        # 웹 대시보드 🆕
├── protocols/              # 프로토콜 정의
│   └── iptime_protocol.py  # 문법 명세 🆕
├── harness/                # 에뮬레이션
│   └── qemu_harness.py     # QEMU 하네스 🆕
├── scripts/                # 유틸리티
│   └── mock_server.py      # 테스트용 목 서버
└── reports/                # 결과 저장
    ├── crashes/
    └── logs/
```

---

## 🎯 퍼징 타겟

| 타겟      | 프로토콜  | 포트       | 위험도  |
| --------- | --------- | ---------- | ------- |
| UDPserver | UDP       | 9999       | 🔴 높음 |
| httpd     | HTTP      | 80         | 🔴 높음 |
| upnpd     | UPnP/SSDP | 1900, 5000 | 🔴 높음 |
| pptpd     | PPTP      | 1723       | 🟠 중간 |

---

## ⚙️ 설정

### config/fuzzer.yaml

```yaml
target:
  host: "192.168.0.1"

fuzzers:
  udp:
    enabled: true
    port: 9999
    max_iterations: 50000
    delay: 0.01
  http:
    enabled: true
    port: 80
    max_iterations: 50000
  upnp:
    enabled: true
    http_port: 5000
  pptp: # 🆕
    enabled: true
    port: 1723

scheduling:
  strategy: "fast" # fast, cov, explore, exploit, quad

dashboard:
  enabled: true
  port: 8888

distributed:
  enabled: false
  redis_url: "redis://localhost:6379"
```

---

## 📊 API 사용 예제

### 뮤테이션 엔진

```python
from mutators import MutationEngine, create_http_mutator

engine = create_http_mutator()
original = b"GET / HTTP/1.1\r\n..."
mutated, ops = engine.mutate(original)
```

### 에너지 스케줄러

```python
from core.scheduler import EnergyScheduler, ScheduleStrategy

scheduler = EnergyScheduler(strategy=ScheduleStrategy.FAST)
scheduler.add(seed_data, protocol="http")
entry = scheduler.select()
```

### 크래시 감지

```python
from monitors import CrashDetector

detector = CrashDetector("192.168.0.1", 80)
crash_info, tags = detector.detect(response, timing, error)
```

---

## ⚠️ 주의사항

> **법적 고지**: 이 도구는 교육 및 연구 목적으로만 사용하세요.
> 허가 없이 타인의 네트워크 장비에 사용하는 것은 불법입니다.

---

## 📝 라이선스

MIT License
