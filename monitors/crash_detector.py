"""
ipTIME Firmware Fuzzer v2.0 - Crash Detection System
다중 소스 크래시 감지 및 응답 분석
"""

import re
import socket
import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple


class CrashType(Enum):
    """크래시 유형"""

    NONE = auto()
    NETWORK_ERROR = auto()  # 네트워크 에러 (연결 거부 등)
    SERVICE_DOWN = auto()  # 서비스 다운
    TIMEOUT = auto()  # 응답 없음 (타임아웃)
    CRASH_SIGNATURE = auto()  # 크래시 시그니처 감지
    HANG = auto()  # 행 (응답 지연)
    SEGFAULT = auto()  # 세그멘테이션 폴트
    STACK_OVERFLOW = auto()  # 스택 오버플로우
    HEAP_CORRUPTION = auto()  # 힙 손상
    DOS = auto()  # DoS (응답 시간 이상)
    UNEXPECTED_RESPONSE = auto()  # 예상치 못한 응답


class SeverityLevel(Enum):
    """심각도 수준"""

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class CrashInfo:
    """크래시 정보"""

    type: CrashType
    severity: SeverityLevel
    description: str
    evidence: bytes = b""
    timing: float = 0.0
    error_message: str = ""

    # 추가 메타데이터
    timestamp: float = field(default_factory=time.time)
    payload_hash: str = ""
    protocol: str = ""
    target: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.name,
            "severity": self.severity.name,
            "description": self.description,
            "evidence_hex": self.evidence.hex() if self.evidence else "",
            "timing": self.timing,
            "error_message": self.error_message,
            "timestamp": self.timestamp,
            "payload_hash": self.payload_hash,
            "protocol": self.protocol,
            "target": self.target,
        }


class ResponseAnalyzer:
    """응답 패턴 분석기"""

    # 크래시 시그니처 패턴
    CRASH_PATTERNS = [
        # 세그멘테이션 폴트
        (rb"[Ss]egmentation [Ff]ault", CrashType.SEGFAULT, SeverityLevel.CRITICAL),
        (rb"SIGSEGV", CrashType.SEGFAULT, SeverityLevel.CRITICAL),
        (rb"[Ss]ignal 11", CrashType.SEGFAULT, SeverityLevel.CRITICAL),
        # 스택 오버플로우
        (rb"[Ss]tack smashing", CrashType.STACK_OVERFLOW, SeverityLevel.CRITICAL),
        (rb"[Ss]tack overflow", CrashType.STACK_OVERFLOW, SeverityLevel.CRITICAL),
        (rb"buffer overflow", CrashType.STACK_OVERFLOW, SeverityLevel.CRITICAL),
        (rb"__stack_chk_fail", CrashType.STACK_OVERFLOW, SeverityLevel.CRITICAL),
        # 힙 손상
        (rb"[Hh]eap corruption", CrashType.HEAP_CORRUPTION, SeverityLevel.CRITICAL),
        (rb"double free", CrashType.HEAP_CORRUPTION, SeverityLevel.CRITICAL),
        (rb"free\(\): invalid", CrashType.HEAP_CORRUPTION, SeverityLevel.CRITICAL),
        (rb"malloc\(\): memory corruption", CrashType.HEAP_CORRUPTION, SeverityLevel.CRITICAL),
        # 일반 크래시
        (rb"[Cc]ore [Dd]umped", CrashType.CRASH_SIGNATURE, SeverityLevel.HIGH),
        (rb"[Aa]borted", CrashType.CRASH_SIGNATURE, SeverityLevel.HIGH),
        (rb"[Ff]atal [Ee]rror", CrashType.CRASH_SIGNATURE, SeverityLevel.HIGH),
        (rb"[Ee]xception", CrashType.CRASH_SIGNATURE, SeverityLevel.MEDIUM),
        (rb"panic", CrashType.CRASH_SIGNATURE, SeverityLevel.HIGH),
        # ASAN/MSAN
        (rb"AddressSanitizer", CrashType.CRASH_SIGNATURE, SeverityLevel.CRITICAL),
        (rb"MemorySanitizer", CrashType.CRASH_SIGNATURE, SeverityLevel.CRITICAL),
        (rb"UndefinedBehaviorSanitizer", CrashType.CRASH_SIGNATURE, SeverityLevel.HIGH),
    ]

    # 흥미로운 응답 패턴 (취약점 징후)
    INTERESTING_PATTERNS = [
        (rb"root:", "passwd_leak"),
        (rb"uid=\d+", "command_exec"),
        (rb"gid=\d+", "command_exec"),
        (rb"/bin/sh", "shell_access"),
        (rb"/etc/passwd", "path_traversal"),
        (rb"/etc/shadow", "path_traversal"),
        (rb"SQL syntax", "sql_injection"),
        (rb"mysql", "sql_injection"),
        (rb"sqlite", "sql_injection"),
        (rb"password", "info_disclosure"),
        (rb"secret", "info_disclosure"),
        (rb"token", "info_disclosure"),
        (rb"api[_-]?key", "info_disclosure"),
    ]

    def __init__(self):
        # 정규식 사전 컴파일
        self.crash_regexes = [
            (re.compile(pattern, re.IGNORECASE), crash_type, severity)
            for pattern, crash_type, severity in self.CRASH_PATTERNS
        ]

        self.interesting_regexes = [
            (re.compile(pattern, re.IGNORECASE), tag) for pattern, tag in self.INTERESTING_PATTERNS
        ]

    def analyze(self, response: bytes) -> Tuple[Optional[CrashInfo], List[str]]:
        """
        응답 분석

        Returns:
            (크래시 정보, 흥미로운 태그 리스트)
        """
        if not response:
            return None, []

        crash_info = None
        interesting_tags = []

        # 크래시 패턴 검사
        for regex, crash_type, severity in self.crash_regexes:
            match = regex.search(response)
            if match:
                crash_info = CrashInfo(
                    type=crash_type,
                    severity=severity,
                    description=f"Crash signature detected: {match.group().decode('utf-8', errors='replace')}",
                    evidence=response[:500],
                )
                break

        # 흥미로운 패턴 검사
        for regex, tag in self.interesting_regexes:
            if regex.search(response):
                interesting_tags.append(tag)

        return crash_info, interesting_tags


class TimingAnalyzer:
    """응답 시간 분석기"""

    def __init__(self, window_size: int = 100, threshold_factor: float = 3.0):
        """
        Args:
            window_size: 이동 평균 윈도우 크기
            threshold_factor: 이상 감지 임계값 (표준편차 배수)
        """
        self.window_size = window_size
        self.threshold_factor = threshold_factor
        self.timing_history: deque = deque(maxlen=window_size)

        self.baseline_mean = 0.0
        self.baseline_std = 0.0
        self.baseline_computed = False

    def add_timing(self, timing: float):
        """타이밍 기록 추가"""
        self.timing_history.append(timing)

        # 기준선 재계산 (충분한 데이터 수집 후)
        if len(self.timing_history) >= 20:
            self._update_baseline()

    def _update_baseline(self):
        """기준선 업데이트"""
        if len(self.timing_history) < 20:
            return

        timings = list(self.timing_history)
        self.baseline_mean = statistics.mean(timings)
        self.baseline_std = statistics.stdev(timings) if len(timings) > 1 else 0.1
        self.baseline_computed = True

    def is_anomaly(self, timing: float) -> Tuple[bool, str]:
        """
        타이밍 이상 감지

        Returns:
            (이상 여부, 이상 유형)
        """
        if not self.baseline_computed:
            return False, ""

        # Z-score 계산
        if self.baseline_std > 0:
            z_score = (timing - self.baseline_mean) / self.baseline_std
        else:
            z_score = 0

        if z_score > self.threshold_factor:
            return True, f"SLOW (z={z_score:.2f})"
        elif z_score < -self.threshold_factor and timing < 0.001:
            return True, f"FAST (z={z_score:.2f})"

        return False, ""

    def get_stats(self) -> Dict[str, float]:
        """타이밍 통계"""
        if not self.timing_history:
            return {}

        timings = list(self.timing_history)
        return {
            "mean": statistics.mean(timings),
            "std": statistics.stdev(timings) if len(timings) > 1 else 0,
            "min": min(timings),
            "max": max(timings),
            "median": statistics.median(timings),
            "samples": len(timings),
        }


class ServiceProber:
    """서비스 상태 확인기"""

    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.last_check_time = 0
        self.check_interval = 1.0  # 최소 체크 간격

    def is_alive(self, protocol: str = "tcp", timeout: float = 1.0) -> bool:
        """
        서비스 생존 확인

        Args:
            protocol: 'tcp' or 'udp'
            timeout: 타임아웃 (초)
        """
        now = time.time()
        if now - self.last_check_time < self.check_interval:
            return True  # 너무 자주 체크하지 않음

        self.last_check_time = now

        try:
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((self.target_host, self.target_port))
                sock.close()
                return result == 0
            else:
                # UDP는 연결 개념이 없으므로 간단한 패킷 전송
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(b"\x00", (self.target_host, self.target_port))
                sock.close()
                return True
        except:
            return False

    def ping(self, timeout: float = 1.0) -> Tuple[bool, float]:
        """
        ICMP Ping (권한 필요)

        Returns:
            (성공 여부, RTT)
        """
        # Windows에서는 subprocess로 ping 실행
        import subprocess

        try:
            output = subprocess.run(
                ["ping", "-n", "1", "-w", str(int(timeout * 1000)), self.target_host],
                capture_output=True,
                timeout=timeout + 1,
            )
            success = output.returncode == 0

            # RTT 추출
            if success:
                match = re.search(rb"time[=<](\d+)ms", output.stdout)
                if match:
                    return True, int(match.group(1)) / 1000.0

            return success, 0.0
        except:
            return False, 0.0


class CrashDetector:
    """
    통합 크래시 감지 시스템

    여러 소스를 통합하여 크래시를 감지하고 분류.
    """

    def __init__(self, target_host: str, target_port: int, protocol: str = "tcp"):
        self.target_host = target_host
        self.target_port = target_port
        self.protocol = protocol

        # 분석기들
        self.response_analyzer = ResponseAnalyzer()
        self.timing_analyzer = TimingAnalyzer()
        self.service_prober = ServiceProber(target_host, target_port)

        # 통계
        self.stats = {
            "total_checks": 0,
            "crashes_detected": 0,
            "service_downs": 0,
            "timeouts": 0,
            "interesting": 0,
        }

        # 크래시 이력 (중복 제거용)
        self.crash_hashes: set = set()

    def detect(
        self, response: Optional[bytes], timing: float, error: Optional[str] = None, payload_hash: str = ""
    ) -> Tuple[CrashInfo, List[str]]:
        """
        크래시 감지 및 분석

        Args:
            response: 응답 데이터
            timing: 응답 시간
            error: 에러 메시지
            payload_hash: 페이로드 해시 (중복 확인용)

        Returns:
            (CrashInfo, 흥미로운 태그 리스트)
        """
        self.stats["total_checks"] += 1
        interesting_tags = []

        # 1. 네트워크 에러 확인
        if error:
            crash_info = self._analyze_network_error(error)
            if crash_info:
                self.stats["crashes_detected"] += 1
                return crash_info, []

        # 2. 타임아웃 확인
        if response is None and timing >= 5.0:  # 타임아웃
            self.stats["timeouts"] += 1

            # 서비스 살아있는지 확인
            if not self.service_prober.is_alive(self.protocol):
                self.stats["service_downs"] += 1
                return (
                    CrashInfo(
                        type=CrashType.SERVICE_DOWN,
                        severity=SeverityLevel.CRITICAL,
                        description="Service is not responding",
                        timing=timing,
                        payload_hash=payload_hash,
                        protocol=self.protocol,
                        target=f"{self.target_host}:{self.target_port}",
                    ),
                    [],
                )

            return (
                CrashInfo(
                    type=CrashType.TIMEOUT,
                    severity=SeverityLevel.MEDIUM,
                    description="Request timed out",
                    timing=timing,
                ),
                [],
            )

        # 3. 응답 내용 분석
        if response:
            crash_info, tags = self.response_analyzer.analyze(response)
            interesting_tags.extend(tags)

            if crash_info:
                self.stats["crashes_detected"] += 1
                crash_info.timing = timing
                crash_info.payload_hash = payload_hash
                return crash_info, interesting_tags

        # 4. 타이밍 이상 감지
        self.timing_analyzer.add_timing(timing)
        is_anomaly, anomaly_type = self.timing_analyzer.is_anomaly(timing)

        if is_anomaly:
            return (
                CrashInfo(
                    type=CrashType.DOS if "SLOW" in anomaly_type else CrashType.HANG,
                    severity=SeverityLevel.LOW,
                    description=f"Timing anomaly: {anomaly_type}",
                    timing=timing,
                ),
                interesting_tags,
            )

        # 5. 흥미로운 결과 카운트
        if interesting_tags:
            self.stats["interesting"] += 1

        return (
            CrashInfo(
                type=CrashType.NONE,
                severity=SeverityLevel.INFO,
                description="Normal response",
                evidence=response[:200] if response else b"",
                timing=timing,
            ),
            interesting_tags,
        )

    def _analyze_network_error(self, error: str) -> Optional[CrashInfo]:
        """네트워크 에러 분석"""
        error_lower = error.lower()

        critical_errors = [
            ("connection refused", CrashType.SERVICE_DOWN, SeverityLevel.CRITICAL),
            ("connection reset", CrashType.NETWORK_ERROR, SeverityLevel.HIGH),
            ("broken pipe", CrashType.NETWORK_ERROR, SeverityLevel.HIGH),
            ("no route to host", CrashType.SERVICE_DOWN, SeverityLevel.CRITICAL),
            ("network is unreachable", CrashType.SERVICE_DOWN, SeverityLevel.CRITICAL),
        ]

        for pattern, crash_type, severity in critical_errors:
            if pattern in error_lower:
                return CrashInfo(
                    type=crash_type, severity=severity, description=f"Network error: {pattern}", error_message=error
                )

        return None

    def get_stats(self) -> Dict[str, Any]:
        """감지기 통계"""
        return {
            **self.stats,
            "timing_stats": self.timing_analyzer.get_stats(),
        }

    def is_unique_crash(self, payload_hash: str) -> bool:
        """중복 크래시 확인"""
        if payload_hash in self.crash_hashes:
            return False
        self.crash_hashes.add(payload_hash)
        return True


# 팩토리 함수
def create_detector(target_host: str, target_port: int, protocol: str = "tcp") -> CrashDetector:
    """크래시 감지기 생성"""
    return CrashDetector(target_host, target_port, protocol)
