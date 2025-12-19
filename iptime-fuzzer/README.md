# ipTIME Firmware Fuzzer

ipTIME 공유기 펌웨어를 대상으로 하는 종합 퍼징 프레임워크입니다.

## 특징

- **멀티 프로토콜 지원**: UDP, HTTP/CGI, UPnP/SSDP, PPTP
- **프로토콜 인식 뮤테이션**: ipTIME 고유 프로토콜 구조를 이해하는 스마트 뮤테이션
- **고위험 타겟 집중**: 정적 분석으로 확인된 취약 함수(gets, system 등)를 집중 공격
- **통합 모니터링**: 크래시 감지, 응답 분석, 자동 리포트 생성

## 설치

```bash
pip install -r requirements.txt
```

## 사용법

### 기본 실행 (모든 퍼저 동시 실행)
```bash
python main.py -t 192.168.0.1
```

### 특정 퍼저만 실행
```bash
# UDP 퍼저만
python main.py -t 192.168.0.1 --udp-only

# HTTP 퍼저만
python main.py -t 192.168.0.1 --http-only

# UPnP 퍼저만
python main.py -t 192.168.0.1 --upnp-only
```

### 설정 파일 사용
```bash
python main.py -c config/fuzzer.yaml
```

### 옵션
```
-t, --target      타겟 호스트 IP
-c, --config      설정 파일 경로
-n, --iterations  최대 반복 횟수 (기본: 10000)
--udp-only        UDP 퍼저만 실행
--http-only       HTTP 퍼저만 실행
--upnp-only       UPnP 퍼저만 실행
--sequential      순차 실행 (멀티스레드 비활성화)
```

## 프로젝트 구조

```
iptime-fuzzer/
├── config/           # 설정 파일
├── core/             # 핵심 컴포넌트 (컨트롤러 등)
├── fuzzers/          # 프로토콜별 퍼저
│   ├── base.py       # 베이스 클래스
│   ├── udp_fuzzer.py # UDP 퍼저
│   ├── http_fuzzer.py# HTTP 퍼저
│   └── upnp_fuzzer.py# UPnP 퍼저
├── mutators/         # 뮤테이션 전략
├── monitors/         # 모니터링 도구
├── protocols/        # 프로토콜 정의
├── corpus/           # 시드 코퍼스
├── harness/          # QEMU 하네스
├── reports/          # 크래시/로그 리포트
├── scripts/          # 유틸리티 스크립트
└── tests/            # 테스트 코드
```

## 퍼징 타겟

| 타겟 | 프로토콜 | 위험도 | 비고 |
|------|---------|--------|------|
| UDPserver | UDP | 🔴 높음 | gets(), system() 사용 |
| httpd | HTTP | 🔴 높음 | CGI 인젝션 가능 |
| upnpd | UPnP/SSDP | 🔴 높음 | system() 4회 호출 |
| pptpd | PPTP | 🟠 중간 | VPN 서버 |

## 크래시 리포트

크래시 발견 시 `reports/crashes/` 디렉토리에 자동 저장됩니다:
- `.bin`: 크래시 유발 페이로드
- `.json`: 메타데이터 (타임스탬프, 응답, 에러 등)

## 주의사항

⚠️ **법적 고지**: 이 도구는 교육 및 연구 목적으로만 사용하세요.
허가 없이 타인의 네트워크 장비에 사용하는 것은 불법입니다.

## 라이선스

MIT License
