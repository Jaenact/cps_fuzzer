"""
ipTIME Firmware Fuzzer v2.0 - PPTP Fuzzer
PPTP VPN 프로토콜 전용 퍼저

타겟: bin/pptpd (VPN 서버)
프로토콜: PPTP Control Connection (TCP 1723)
공격 벡터: Control Message Parsing, GRE Data Channel
"""

import random
import socket
import struct
from typing import Dict, List, Optional, Tuple

from .base import BaseFuzzer


class PPTPFuzzer(BaseFuzzer):
    """
    PPTP VPN 프로토콜 퍼저

    PPTP는 TCP/1723에서 Control Connection을 사용하며,
    GRE를 통해 데이터를 전송. 파싱 취약점이 많이 발견되는 프로토콜.
    """

    PORT = 1723

    # PPTP Magic Cookie
    MAGIC_COOKIE = 0x1A2B3C4D

    # PPTP Control Message Types
    MSG_TYPES = {
        # Control Connection Management
        1: "Start-Control-Connection-Request",
        2: "Start-Control-Connection-Reply",
        3: "Stop-Control-Connection-Request",
        4: "Stop-Control-Connection-Reply",
        5: "Echo-Request",
        6: "Echo-Reply",
        # Call Management
        7: "Outgoing-Call-Request",
        8: "Outgoing-Call-Reply",
        9: "Incoming-Call-Request",
        10: "Incoming-Call-Reply",
        11: "Incoming-Call-Connected",
        12: "Call-Clear-Request",
        13: "Call-Disconnect-Notify",
        # Error Reporting
        14: "WAN-Error-Notify",
        # PPP Session Control
        15: "Set-Link-Info",
    }

    # Framing Capabilities
    FRAME_CAP_ASYNC = 0x00000001
    FRAME_CAP_SYNC = 0x00000002

    # Bearer Capabilities
    BEARER_CAP_ANALOG = 0x00000001
    BEARER_CAP_DIGITAL = 0x00000002

    def __init__(self, config: dict):
        super().__init__(config)
        self.name = config.get("name", "PPTPFuzzer")
        self.target_port = config.get("target_port", self.PORT)

        # 세션 상태
        self.call_id = 0
        self.peer_call_id = 0

        # 뮤테이션 전략
        self.mutation_strategies = [
            self._mutate_message_type,
            self._mutate_length_field,
            self._mutate_reserved,
            self._mutate_call_id,
            self._mutate_payload_overflow,
            self._mutate_integer_fields,
            self._mutate_hostname,
            self._mutate_vendor_name,
            self._mutate_call_parameters,
        ]

    def send(self, data: bytes) -> Optional[bytes]:
        """TCP 기반 PPTP 메시지 전송"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((self.target_host, self.target_port))
            sock.sendall(data)

            # 응답 수신
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    # PPTP 메시지는 헤더의 length 필드로 크기 확인 가능
                    if len(response) >= 8:
                        msg_len = struct.unpack(">H", response[:2])[0]
                        if len(response) >= msg_len:
                            break
                except socket.timeout:
                    break

            return response if response else None

        except socket.timeout:
            return None
        except Exception as e:
            raise e
        finally:
            sock.close()

    def generate_seed(self) -> bytes:
        """유효한 PPTP 메시지 시드 생성"""
        seeds = [
            self._make_start_control_request(),
            self._make_echo_request(),
            self._make_outgoing_call_request(),
        ]
        return random.choice(seeds)

    def _make_pptp_header(self, msg_type: int, length: int) -> bytes:
        """
        PPTP Control Message 헤더 생성

        Structure:
            Length (2 bytes)
            PPTP Message Type (2 bytes) - Control Message = 1
            Magic Cookie (4 bytes)
            Control Message Type (2 bytes)
            Reserved0 (2 bytes)
        """
        # Length = 헤더(12) + 페이로드
        header = struct.pack(">H", length)  # Length
        header += struct.pack(">H", 1)  # PPTP Message Type (Control = 1)
        header += struct.pack(">I", self.MAGIC_COOKIE)  # Magic Cookie
        header += struct.pack(">H", msg_type)  # Control Message Type
        header += struct.pack(">H", 0)  # Reserved0
        return header

    def _make_start_control_request(self) -> bytes:
        """Start-Control-Connection-Request 생성"""
        msg_type = 1

        # 페이로드
        payload = struct.pack(">H", 0x0100)  # Protocol Version (1.0)
        payload += struct.pack(">H", 0)  # Reserved1
        payload += struct.pack(">I", self.FRAME_CAP_ASYNC | self.FRAME_CAP_SYNC)  # Framing Cap
        payload += struct.pack(">I", self.BEARER_CAP_ANALOG | self.BEARER_CAP_DIGITAL)  # Bearer Cap
        payload += struct.pack(">H", 65535)  # Maximum Channels
        payload += struct.pack(">H", 0x0100)  # Firmware Revision
        payload += b"fuzzer\x00".ljust(64, b"\x00")  # Host Name (64 bytes)
        payload += b"iPTIME-Fuzzer\x00".ljust(64, b"\x00")  # Vendor String (64 bytes)

        total_len = 12 + len(payload)
        header = self._make_pptp_header(msg_type, total_len)

        return header + payload

    def _make_echo_request(self) -> bytes:
        """Echo-Request 생성"""
        msg_type = 5

        payload = struct.pack(">I", random.randint(0, 0xFFFFFFFF))  # Identifier

        total_len = 12 + len(payload)
        header = self._make_pptp_header(msg_type, total_len)

        return header + payload

    def _make_outgoing_call_request(self) -> bytes:
        """Outgoing-Call-Request 생성"""
        msg_type = 7
        self.call_id = random.randint(1, 65535)

        payload = struct.pack(">H", self.call_id)  # Call ID
        payload += struct.pack(">H", 0)  # Call Serial Number
        payload += struct.pack(">I", 56000)  # Minimum BPS
        payload += struct.pack(">I", 64000)  # Maximum BPS
        payload += struct.pack(">I", self.BEARER_CAP_ANALOG)  # Bearer Type
        payload += struct.pack(">I", self.FRAME_CAP_ASYNC)  # Framing Type
        payload += struct.pack(">H", 2048)  # Packet Recv Window Size
        payload += struct.pack(">H", 0)  # Packet Processing Delay
        payload += struct.pack(">H", 0)  # Phone Number Length
        payload += struct.pack(">H", 0)  # Reserved1
        payload += b"\x00" * 64  # Phone Number (64 bytes)
        payload += b"\x00" * 64  # Subaddress (64 bytes)

        total_len = 12 + len(payload)
        header = self._make_pptp_header(msg_type, total_len)

        return header + payload

    def _make_call_clear_request(self) -> bytes:
        """Call-Clear-Request 생성"""
        msg_type = 12

        payload = struct.pack(">H", self.call_id)  # Call ID
        payload += struct.pack(">H", 0)  # Reserved1

        total_len = 12 + len(payload)
        header = self._make_pptp_header(msg_type, total_len)

        return header + payload

    def _make_set_link_info(self) -> bytes:
        """Set-Link-Info 생성"""
        msg_type = 15

        payload = struct.pack(">H", self.peer_call_id)  # Peer's Call ID
        payload += struct.pack(">H", 0)  # Reserved1
        payload += struct.pack(">I", 0xFFFFFFFF)  # Send ACCM
        payload += struct.pack(">I", 0xFFFFFFFF)  # Receive ACCM

        total_len = 12 + len(payload)
        header = self._make_pptp_header(msg_type, total_len)

        return header + payload

    def mutate(self, data: bytes) -> bytes:
        """PPTP 메시지 뮤테이션"""
        strategy = random.choice(self.mutation_strategies)
        return strategy(bytearray(data))

    # ========== 뮤테이션 전략들 ==========

    def _mutate_message_type(self, data: bytearray) -> bytes:
        """메시지 타입 변조"""
        if len(data) < 12:
            return bytes(data)

        # 유효한 타입 또는 잘못된 타입
        types = list(self.MSG_TYPES.keys()) + [0, 16, 255, 65535]
        new_type = random.choice(types)
        data[8:10] = struct.pack(">H", new_type)

        return bytes(data)

    def _mutate_length_field(self, data: bytearray) -> bytes:
        """길이 필드 변조 (정수 오버플로우)"""
        if len(data) < 2:
            return bytes(data)

        lengths = [
            0,  # 0 길이
            1,  # 최소
            11,  # 헤더보다 작음
            12,  # 헤더만
            len(data),  # 실제 길이
            len(data) * 2,  # 2배
            0x7FFF,  # signed max
            0x8000,  # signed overflow
            0xFFFF,  # unsigned max
        ]
        new_len = random.choice(lengths)
        data[0:2] = struct.pack(">H", new_len)

        return bytes(data)

    def _mutate_reserved(self, data: bytearray) -> bytes:
        """Reserved 필드에 데이터 삽입"""
        if len(data) < 12:
            return bytes(data)

        # Reserved0 (offset 10-12)
        values = [0, 1, 0xFFFF, random.randint(0, 0xFFFF)]
        data[10:12] = struct.pack(">H", random.choice(values))

        return bytes(data)

    def _mutate_call_id(self, data: bytearray) -> bytes:
        """Call ID 변조"""
        if len(data) < 14:
            return bytes(data)

        # Call ID는 보통 offset 12에 위치
        call_ids = [0, 1, 0xFFFF, 0x8000, random.randint(0, 0xFFFF)]
        data[12:14] = struct.pack(">H", random.choice(call_ids))

        return bytes(data)

    def _mutate_payload_overflow(self, data: bytearray) -> bytes:
        """페이로드 오버플로우"""
        base = bytes(data)
        overflow_sizes = [64, 128, 256, 512, 1024, 2048, 4096]
        size = random.choice(overflow_sizes)

        patterns = [
            b"A" * size,
            b"\x00" * size,
            b"\xff" * size,
            bytes([i & 0xFF for i in range(size)]),
        ]

        return base + random.choice(patterns)

    def _mutate_integer_fields(self, data: bytearray) -> bytes:
        """정수 필드 경계값 테스트"""
        if len(data) < 20:
            return bytes(data)

        interesting_values = [
            0,
            1,
            0xFF,
            0x100,
            0x7F,
            0x80,
            0xFFFF,
            0x7FFF,
            0x8000,
            0xFFFFFFFF,
            0x7FFFFFFF,
            0x80000000,
        ]

        # Start-Control-Request의 경우 (총 길이 156)
        if len(data) >= 24:
            # Framing Capabilities (offset 16-20)
            val = random.choice(interesting_values) & 0xFFFFFFFF
            data[16:20] = struct.pack(">I", val)

        if len(data) >= 28:
            # Bearer Capabilities (offset 20-24)
            val = random.choice(interesting_values) & 0xFFFFFFFF
            data[20:24] = struct.pack(">I", val)

        return bytes(data)

    def _mutate_hostname(self, data: bytearray) -> bytes:
        """Hostname 필드 퍼징"""
        if len(data) < 92:  # 헤더 + 페이로드 최소
            return bytes(data)

        # Hostname은 offset 32-96 (64바이트)
        payloads = [
            b"A" * 64,  # 최대 길이
            b"A" * 128,  # 오버플로우
            b"\x00" * 64,  # NULL
            b"; id\x00".ljust(64, b"\x00"),  # 명령어 인젝션
            b"%s%s%s%s%s\x00".ljust(64, b"\x00"),  # 포맷 스트링
            b"`id`\x00".ljust(64, b"\x00"),
            b"$(cat /etc/passwd)\x00".ljust(64, b"\x00"),
        ]

        payload = random.choice(payloads)
        if len(data) >= 96:
            data[32:96] = payload[:64].ljust(64, b"\x00")

        return bytes(data)

    def _mutate_vendor_name(self, data: bytearray) -> bytes:
        """Vendor Name 필드 퍼징"""
        if len(data) < 156:
            return bytes(data)

        # Vendor Name은 offset 96-160 (64바이트)
        payloads = [
            b"B" * 64,
            b"B" * 128,
            b"\xff" * 64,
            b"../../../etc/passwd\x00".ljust(64, b"\x00"),
        ]

        payload = random.choice(payloads)
        if len(data) >= 160:
            data[96:160] = payload[:64].ljust(64, b"\x00")

        return bytes(data)

    def _mutate_call_parameters(self, data: bytearray) -> bytes:
        """Call 관련 파라미터 퍼징 (Outgoing-Call-Request용)"""
        # 새로운 Outgoing-Call-Request 생성
        msg = bytearray(self._make_outgoing_call_request())

        # BPS 값 변조
        if random.random() < 0.5:
            min_bps = random.choice([0, 1, 0xFFFFFFFF, 0x7FFFFFFF])
            max_bps = random.choice([0, 1, 0xFFFFFFFF, 0x7FFFFFFF])
            msg[16:20] = struct.pack(">I", min_bps)
            msg[20:24] = struct.pack(">I", max_bps)

        # Window Size 변조
        if random.random() < 0.5:
            window = random.choice([0, 1, 0xFFFF, 0x8000])
            msg[32:34] = struct.pack(">H", window)

        # Phone Number Length 변조
        if random.random() < 0.5:
            phone_len = random.choice([0, 64, 128, 0xFFFF])
            msg[36:38] = struct.pack(">H", phone_len)

        return bytes(msg)

    def is_crash(self, response: Optional[bytes], error: Optional[str]) -> bool:
        """크래시 감지"""
        if error:
            crash_indicators = [
                "Connection refused",
                "Connection reset",
                "Broken pipe",
                "No route to host",
            ]
            return any(ind in error for ind in crash_indicators)

        # PPTP 응답 분석
        if response and len(response) >= 12:
            # Reply 코드 확인
            if len(response) >= 16:
                # Result Code 위치 (메시지 타입에 따라 다름)
                msg_type = struct.unpack(">H", response[8:10])[0]

                # Start-Control-Connection-Reply
                if msg_type == 2 and len(response) >= 16:
                    result_code = response[14]
                    if result_code != 1:  # 1 = Success
                        return False  # 에러지만 크래시는 아님

        return False

    def is_interesting(self, response: Optional[bytes]) -> bool:
        """흥미로운 응답 감지"""
        if response is None:
            return False

        interesting_patterns = [
            b"error",
            b"fail",
            b"invalid",
            b"root:",
            b"uid=",
            b"/bin/",
        ]

        response_lower = response.lower()
        return any(p in response_lower for p in interesting_patterns)


# 팩토리 함수
def create_pptp_fuzzer(config: dict) -> PPTPFuzzer:
    """PPTP 퍼저 생성"""
    return PPTPFuzzer(config)
