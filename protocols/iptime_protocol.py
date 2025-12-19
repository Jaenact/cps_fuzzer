"""
ipTIME Firmware Fuzzer v2.0 - Protocol Grammar
프로토콜 문법 정의 및 구조화 생성

ipTIME 장비의 고유 프로토콜 구조를 정의하고,
문법 기반 생성 및 뮤테이션을 지원.
"""

import random
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Type, Union

# ============================================================
# 기본 타입 정의
# ============================================================


class FieldType(Enum):
    """필드 타입"""

    UINT8 = auto()
    UINT16_LE = auto()
    UINT16_BE = auto()
    UINT32_LE = auto()
    UINT32_BE = auto()
    BYTES = auto()
    STRING = auto()
    COMPUTED = auto()  # 계산된 값 (체크섬 등)


@dataclass
class FieldSpec:
    """필드 명세"""

    name: str
    field_type: FieldType
    size: Optional[int] = None  # BYTES/STRING의 경우
    default: Any = None
    valid_values: List[Any] = field(default_factory=list)
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    compute_func: Optional[Callable] = None  # COMPUTED 타입용

    def generate(self, context: Dict[str, Any] = None) -> bytes:
        """필드 값 생성"""
        if self.field_type == FieldType.COMPUTED and self.compute_func:
            value = self.compute_func(context or {})
        elif self.valid_values:
            value = random.choice(self.valid_values)
        elif self.default is not None:
            value = self.default
        else:
            value = self._generate_random()

        return self._pack(value)

    def _generate_random(self) -> Any:
        """랜덤 값 생성"""
        if self.field_type == FieldType.UINT8:
            return random.randint(self.min_value or 0, self.max_value or 255)
        elif self.field_type in (FieldType.UINT16_LE, FieldType.UINT16_BE):
            return random.randint(self.min_value or 0, self.max_value or 65535)
        elif self.field_type in (FieldType.UINT32_LE, FieldType.UINT32_BE):
            return random.randint(self.min_value or 0, self.max_value or 0xFFFFFFFF)
        elif self.field_type == FieldType.BYTES:
            return bytes([random.randint(0, 255) for _ in range(self.size or 16)])
        elif self.field_type == FieldType.STRING:
            return b"test\x00".ljust(self.size or 32, b"\x00")
        return b"\x00"

    def _pack(self, value: Any) -> bytes:
        """값을 바이트로 변환"""
        if self.field_type == FieldType.UINT8:
            return struct.pack("B", value & 0xFF)
        elif self.field_type == FieldType.UINT16_LE:
            return struct.pack("<H", value & 0xFFFF)
        elif self.field_type == FieldType.UINT16_BE:
            return struct.pack(">H", value & 0xFFFF)
        elif self.field_type == FieldType.UINT32_LE:
            return struct.pack("<I", value & 0xFFFFFFFF)
        elif self.field_type == FieldType.UINT32_BE:
            return struct.pack(">I", value & 0xFFFFFFFF)
        elif self.field_type in (FieldType.BYTES, FieldType.STRING):
            if isinstance(value, str):
                value = value.encode()
            return value.ljust(self.size or len(value), b"\x00")[: self.size]
        elif self.field_type == FieldType.COMPUTED:
            if isinstance(value, bytes):
                return value
            elif isinstance(value, int):
                return struct.pack("<H", value & 0xFFFF)
            return bytes(value)
        return b""


@dataclass
class MessageSpec:
    """메시지 명세"""

    name: str
    fields: List[FieldSpec]
    description: str = ""

    def generate(self, context: Dict[str, Any] = None) -> bytes:
        """메시지 생성"""
        ctx = context or {}
        result = b""

        # 먼저 모든 필드 생성 (COMPUTED 제외)
        field_values = {}
        for field_spec in self.fields:
            if field_spec.field_type != FieldType.COMPUTED:
                value = field_spec.generate(ctx)
                field_values[field_spec.name] = value
                result += value

        # COMPUTED 필드 처리
        for i, field_spec in enumerate(self.fields):
            if field_spec.field_type == FieldType.COMPUTED:
                ctx["_partial_data"] = result
                ctx["_field_values"] = field_values
                value = field_spec.generate(ctx)

                # 결과에서 해당 위치 업데이트
                offset = sum(len(fv) for fv in list(field_values.values())[:i])
                result = result[:offset] + value + result[offset + len(value) :]

        return result

    def get_field_offsets(self) -> Dict[str, int]:
        """필드별 오프셋 반환"""
        offsets = {}
        current_offset = 0

        for field_spec in self.fields:
            offsets[field_spec.name] = current_offset

            if field_spec.field_type == FieldType.UINT8:
                current_offset += 1
            elif field_spec.field_type in (FieldType.UINT16_LE, FieldType.UINT16_BE):
                current_offset += 2
            elif field_spec.field_type in (FieldType.UINT32_LE, FieldType.UINT32_BE):
                current_offset += 4
            elif field_spec.field_type in (FieldType.BYTES, FieldType.STRING):
                current_offset += field_spec.size or 0

        return offsets


# ============================================================
# ipTIME UDP 프로토콜 정의
# ============================================================


def _calculate_iptime_checksum(ctx: Dict[str, Any]) -> bytes:
    """ipTIME UDP 체크섬 계산"""
    data = ctx.get("_partial_data", b"")
    checksum = 0
    for byte in data:
        checksum ^= byte
    return struct.pack("<H", checksum & 0xFFFF)


class IPTimeUDPSpec:
    """ipTIME UDP 프로토콜 명세"""

    # 헤더 명세
    HEADER = MessageSpec(
        name="iptime_udp_header",
        description="ipTIME UDP Discovery Protocol Header",
        fields=[
            FieldSpec(
                name="magic", field_type=FieldType.BYTES, size=4, default=b"EFUD", valid_values=[b"EFUD", b"ipTM"]
            ),
            FieldSpec(
                name="cmd",
                field_type=FieldType.UINT16_LE,
                valid_values=[0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006],
            ),
            FieldSpec(name="length", field_type=FieldType.UINT16_LE, min_value=0, max_value=4096),
            FieldSpec(name="checksum", field_type=FieldType.COMPUTED, compute_func=_calculate_iptime_checksum),
        ],
    )

    # 명령어 정의
    COMMANDS = {
        0x0001: "DISCOVERY",
        0x0002: "GET_CONFIG",
        0x0003: "SET_CONFIG",
        0x0004: "GET_STATUS",
        0x0005: "REBOOT",
        0x0006: "UPGRADE",
    }

    # 디스커버리 페이로드
    DISCOVERY_PAYLOAD = MessageSpec(
        name="discovery_payload",
        description="Discovery Request Payload",
        fields=[
            FieldSpec(name="padding", field_type=FieldType.BYTES, size=32, default=b"\x00" * 32),
        ],
    )

    # 설정 요청 페이로드
    CONFIG_REQUEST_PAYLOAD = MessageSpec(
        name="config_request",
        description="Configuration Request Payload",
        fields=[
            FieldSpec(
                name="action",
                field_type=FieldType.STRING,
                size=32,
                default=b"get_config\x00",
                valid_values=[b"get_config\x00", b"set_config\x00", b"get_status\x00"],
            ),
            FieldSpec(name="param", field_type=FieldType.STRING, size=64, default=b"\x00" * 64),
        ],
    )

    @classmethod
    def generate_discovery(cls) -> bytes:
        """디스커버리 패킷 생성"""
        payload = cls.DISCOVERY_PAYLOAD.generate()

        ctx = {"payload_length": len(payload)}
        header = cls.HEADER.generate(ctx)

        # 길이 필드 업데이트
        total_len = len(header) + len(payload)
        result = bytearray(header + payload)
        result[6:8] = struct.pack("<H", len(payload))

        # 체크섬 재계산
        checksum = 0
        for byte in result:
            checksum ^= byte
        result[8:10] = struct.pack("<H", checksum)

        return bytes(result)

    @classmethod
    def generate_config_request(cls, action: str = "get_config") -> bytes:
        """설정 요청 패킷 생성"""
        ctx = {"action": action}
        payload = cls.CONFIG_REQUEST_PAYLOAD.generate(ctx)
        header = cls.HEADER.generate({"cmd": 0x0002})

        result = bytearray(header + payload)
        result[4:6] = struct.pack("<H", 0x0002)  # GET_CONFIG
        result[6:8] = struct.pack("<H", len(payload))

        # 체크섬 재계산
        checksum = 0
        for byte in result:
            checksum ^= byte
        result[8:10] = struct.pack("<H", checksum)

        return bytes(result)


# ============================================================
# HTTP 프로토콜 정의
# ============================================================


class HTTPSpec:
    """HTTP 프로토콜 명세"""

    METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]

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
    ]

    PARAMETERS = [
        "username",
        "password",
        "cmd",
        "action",
        "ip",
        "port",
        "mac",
        "ssid",
        "file",
        "path",
        "url",
        "redirect",
    ]

    CONTENT_TYPES = [
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/json",
        "text/xml",
    ]

    @classmethod
    def generate_get_request(
        cls, endpoint: str = None, params: Dict[str, str] = None, host: str = "192.168.0.1"
    ) -> bytes:
        """GET 요청 생성"""
        if endpoint is None:
            endpoint = random.choice(cls.ENDPOINTS)

        path = endpoint
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            path = f"{endpoint}?{query}"

        request = f"GET {path} HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"
        request += "User-Agent: iptime-fuzzer/2.0\r\n"
        request += "Accept: */*\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"

        return request.encode()

    @classmethod
    def generate_post_request(
        cls, endpoint: str = None, body: str = "", content_type: str = None, host: str = "192.168.0.1"
    ) -> bytes:
        """POST 요청 생성"""
        if endpoint is None:
            endpoint = random.choice(cls.ENDPOINTS)
        if content_type is None:
            content_type = cls.CONTENT_TYPES[0]

        request = f"POST {endpoint} HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"
        request += "User-Agent: iptime-fuzzer/2.0\r\n"
        request += f"Content-Type: {content_type}\r\n"
        request += f"Content-Length: {len(body)}\r\n"
        request += "Accept: */*\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        request += body

        return request.encode()


# ============================================================
# UPnP/SOAP 프로토콜 정의
# ============================================================


class UPnPSpec:
    """UPnP/SOAP 프로토콜 명세"""

    SSDP_MULTICAST = "239.255.255.250"
    SSDP_PORT = 1900

    SERVICE_URNS = [
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "urn:schemas-upnp-org:service:Layer3Forwarding:1",
    ]

    ACTIONS = [
        "AddPortMapping",
        "DeletePortMapping",
        "GetExternalIPAddress",
        "GetGenericPortMappingEntry",
        "GetSpecificPortMappingEntry",
        "GetStatusInfo",
        "SetConnectionType",
    ]

    @classmethod
    def generate_msearch(cls, st: str = "upnp:rootdevice", mx: int = 3) -> bytes:
        """M-SEARCH 요청 생성"""
        request = "M-SEARCH * HTTP/1.1\r\n"
        request += f"HOST: {cls.SSDP_MULTICAST}:{cls.SSDP_PORT}\r\n"
        request += 'MAN: "ssdp:discover"\r\n'
        request += f"MX: {mx}\r\n"
        request += f"ST: {st}\r\n"
        request += "\r\n"

        return request.encode()

    @classmethod
    def generate_soap_request(
        cls, action: str, service: str = None, args: Dict[str, str] = None, host: str = "192.168.0.1", port: int = 5000
    ) -> bytes:
        """SOAP 요청 생성"""
        if service is None:
            service = cls.SERVICE_URNS[0]
        if args is None:
            args = {}

        # XML 인자 생성
        args_xml = ""
        for name, value in args.items():
            args_xml += f"      <{name}>{value}</{name}>\n"

        body = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action} xmlns:u="{service}">
{args_xml}    </u:{action}>
  </s:Body>
</s:Envelope>"""

        request = f"POST /ctl/IPConn HTTP/1.1\r\n"
        request += f"Host: {host}:{port}\r\n"
        request += 'Content-Type: text/xml; charset="utf-8"\r\n'
        request += f'SOAPAction: "{service}#{action}"\r\n'
        request += f"Content-Length: {len(body)}\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        request += body

        return request.encode()

    @classmethod
    def generate_add_port_mapping(
        cls,
        external_port: int = 8080,
        internal_port: int = 80,
        internal_client: str = "192.168.0.10",
        protocol: str = "TCP",
        description: str = "Fuzzer",
        **kwargs,
    ) -> bytes:
        """AddPortMapping 요청 생성"""
        args = {
            "NewRemoteHost": "",
            "NewExternalPort": str(external_port),
            "NewProtocol": protocol,
            "NewInternalPort": str(internal_port),
            "NewInternalClient": internal_client,
            "NewEnabled": "1",
            "NewPortMappingDescription": description,
            "NewLeaseDuration": "0",
        }
        args.update(kwargs)

        return cls.generate_soap_request("AddPortMapping", args=args, **kwargs)


# ============================================================
# Protocol Factory
# ============================================================


class ProtocolFactory:
    """프로토콜 팩토리"""

    PROTOCOLS = {
        "udp": IPTimeUDPSpec,
        "http": HTTPSpec,
        "upnp": UPnPSpec,
    }

    @classmethod
    def get_spec(cls, protocol: str):
        """프로토콜 명세 반환"""
        return cls.PROTOCOLS.get(protocol.lower())

    @classmethod
    def generate_sample(cls, protocol: str, msg_type: str = None) -> bytes:
        """샘플 메시지 생성"""
        spec = cls.get_spec(protocol)
        if not spec:
            return b""

        if protocol.lower() == "udp":
            return spec.generate_discovery()
        elif protocol.lower() == "http":
            return spec.generate_get_request()
        elif protocol.lower() == "upnp":
            return spec.generate_msearch()

        return b""
