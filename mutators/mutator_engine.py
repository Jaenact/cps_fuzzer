"""
ipTIME Firmware Fuzzer v2.0 - Mutation Engine
AFL/libFuzzer 스타일의 고급 뮤테이션 전략
"""

import random
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

# ============================================================
# 흥미로운 값 (경계값, 특수값)
# ============================================================
INTERESTING_8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]

INTERESTING_16 = [-32768, -129, -128, -1, 0, 1, 127, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 65535]

INTERESTING_32 = [
    -2147483648,
    -100663046,
    -32769,
    -32768,
    -129,
    -128,
    -1,
    0,
    1,
    127,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    32768,
    65535,
    65536,
    100663045,
    2147483647,
]


@dataclass
class MutationOp:
    """뮤테이션 연산 기록"""

    name: str
    offset: int
    size: int
    old_value: bytes
    new_value: bytes

    def __repr__(self):
        return f"MutationOp({self.name}@{self.offset}, {len(self.old_value)}→{len(self.new_value)})"


class BaseMutator(ABC):
    """뮤테이터 베이스 클래스"""

    name: str = "base"
    weight: float = 1.0  # 선택 확률 가중치

    @abstractmethod
    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        """
        데이터 뮤테이션

        Returns:
            (변조된 데이터, 뮤테이션 연산 기록)
        """
        pass


class BitFlipMutator(BaseMutator):
    """비트 플립 뮤테이터 (AFL havoc 스타일)"""

    name = "bitflip"
    weight = 2.0

    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        if len(data) == 0:
            return data, None

        pos = random.randint(0, len(data) - 1)
        bit = random.randint(0, 7)
        old_val = bytes([data[pos]])

        data[pos] ^= 1 << bit

        return data, MutationOp(name=self.name, offset=pos, size=1, old_value=old_val, new_value=bytes([data[pos]]))


class ByteFlipMutator(BaseMutator):
    """바이트 플립 뮤테이터"""

    name = "byteflip"
    weight = 1.5

    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        if len(data) == 0:
            return data, None

        # 1, 2, 4 바이트 플립
        flip_size = random.choice([1, 2, 4])
        if len(data) < flip_size:
            flip_size = len(data)

        pos = random.randint(0, len(data) - flip_size)
        old_val = bytes(data[pos : pos + flip_size])

        for i in range(flip_size):
            data[pos + i] ^= 0xFF

        return data, MutationOp(
            name=self.name, offset=pos, size=flip_size, old_value=old_val, new_value=bytes(data[pos : pos + flip_size])
        )


class ArithmeticMutator(BaseMutator):
    """산술 연산 뮤테이터 (AFL arith 스타일)"""

    name = "arithmetic"
    weight = 2.0

    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        if len(data) == 0:
            return data, None

        # 8, 16, 32비트 산술
        arith_size = random.choice([1, 2, 4])
        if len(data) < arith_size:
            arith_size = 1

        pos = random.randint(0, len(data) - arith_size)
        old_val = bytes(data[pos : pos + arith_size])

        delta = random.randint(-35, 35)
        if delta == 0:
            delta = 1

        if arith_size == 1:
            val = data[pos]
            data[pos] = (val + delta) & 0xFF
        elif arith_size == 2:
            val = struct.unpack("<H", data[pos : pos + 2])[0]
            new_val = (val + delta) & 0xFFFF
            data[pos : pos + 2] = struct.pack("<H", new_val)
        else:  # 4
            val = struct.unpack("<I", data[pos : pos + 4])[0]
            new_val = (val + delta) & 0xFFFFFFFF
            data[pos : pos + 4] = struct.pack("<I", new_val)

        return data, MutationOp(
            name=self.name,
            offset=pos,
            size=arith_size,
            old_value=old_val,
            new_value=bytes(data[pos : pos + arith_size]),
        )


class InterestingValueMutator(BaseMutator):
    """흥미로운 값 삽입 (경계값 테스트)"""

    name = "interesting"
    weight = 1.5

    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        if len(data) == 0:
            return data, None

        int_size = random.choice([1, 2, 4])
        if len(data) < int_size:
            int_size = 1

        pos = random.randint(0, len(data) - int_size)
        old_val = bytes(data[pos : pos + int_size])

        if int_size == 1:
            val = random.choice(INTERESTING_8) & 0xFF
            data[pos] = val
        elif int_size == 2:
            val = random.choice(INTERESTING_16) & 0xFFFF
            endian = random.choice(["<", ">"])
            data[pos : pos + 2] = struct.pack(f"{endian}H", val)
        else:
            val = random.choice(INTERESTING_32) & 0xFFFFFFFF
            endian = random.choice(["<", ">"])
            data[pos : pos + 4] = struct.pack(f"{endian}I", val)

        return data, MutationOp(
            name=self.name, offset=pos, size=int_size, old_value=old_val, new_value=bytes(data[pos : pos + int_size])
        )


class RandomByteMutator(BaseMutator):
    """랜덤 바이트 삽입/교체"""

    name = "random_byte"
    weight = 1.0

    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        if len(data) == 0:
            # 빈 데이터면 랜덤 바이트 추가
            new_byte = bytes([random.randint(0, 255)])
            data.extend(new_byte)
            return data, MutationOp("random_byte", 0, 1, b"", new_byte)

        pos = random.randint(0, len(data) - 1)
        num_bytes = random.randint(1, min(4, len(data) - pos))
        old_val = bytes(data[pos : pos + num_bytes])

        for i in range(num_bytes):
            data[pos + i] = random.randint(0, 255)

        return data, MutationOp(
            name=self.name, offset=pos, size=num_bytes, old_value=old_val, new_value=bytes(data[pos : pos + num_bytes])
        )


class DeleteMutator(BaseMutator):
    """바이트 삭제"""

    name = "delete"
    weight = 0.8

    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        if len(data) <= 1:
            return data, None

        del_len = random.randint(1, min(16, len(data) - 1))
        pos = random.randint(0, len(data) - del_len)
        old_val = bytes(data[pos : pos + del_len])

        del data[pos : pos + del_len]

        return data, MutationOp(name=self.name, offset=pos, size=del_len, old_value=old_val, new_value=b"")


class InsertMutator(BaseMutator):
    """바이트 삽입"""

    name = "insert"
    weight = 0.8

    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        pos = random.randint(0, len(data))
        ins_len = random.randint(1, 16)

        # 삽입 패턴 선택
        patterns = [
            bytes([random.randint(0, 255) for _ in range(ins_len)]),  # 랜덤
            bytes([0x00] * ins_len),  # NULL
            bytes([0xFF] * ins_len),  # 0xFF
            bytes([0x41] * ins_len),  # 'A'
        ]
        new_bytes = random.choice(patterns)[:ins_len]

        data[pos:pos] = new_bytes

        return data, MutationOp(name=self.name, offset=pos, size=0, old_value=b"", new_value=new_bytes)


class DuplicateMutator(BaseMutator):
    """블록 복제"""

    name = "duplicate"
    weight = 0.5

    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        if len(data) < 4:
            return data, None

        # 복제할 블록 선택
        block_len = random.randint(1, min(32, len(data) // 2))
        src_pos = random.randint(0, len(data) - block_len)
        block = bytes(data[src_pos : src_pos + block_len])

        # 삽입 위치
        dst_pos = random.randint(0, len(data))
        data[dst_pos:dst_pos] = block

        return data, MutationOp(name=self.name, offset=dst_pos, size=0, old_value=b"", new_value=block)


class OverwriteMutator(BaseMutator):
    """블록 덮어쓰기 (내부 복사)"""

    name = "overwrite"
    weight = 0.5

    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        if len(data) < 4:
            return data, None

        block_len = random.randint(1, min(16, len(data) // 2))
        src_pos = random.randint(0, len(data) - block_len)
        dst_pos = random.randint(0, len(data) - block_len)

        if src_pos == dst_pos:
            return data, None

        old_val = bytes(data[dst_pos : dst_pos + block_len])
        block = bytes(data[src_pos : src_pos + block_len])
        data[dst_pos : dst_pos + block_len] = block

        return data, MutationOp(name=self.name, offset=dst_pos, size=block_len, old_value=old_val, new_value=block)


class DictionaryMutator(BaseMutator):
    """딕셔너리 기반 뮤테이터"""

    name = "dictionary"
    weight = 1.5

    # 기본 딕셔너리 (프로토콜 공통)
    DEFAULT_DICT = [
        # 매직 바이트
        b"EFUD",
        b"ipTM",
        b"HTTP",
        b"MAN:",
        b"M-SEARCH",
        # 명령어 인젝션
        b"; id",
        b"| id",
        b"`id`",
        b"$(id)",
        b"; cat /etc/passwd",
        b"| ls -la",
        b"; nc -e /bin/sh ",
        b"; wget ",
        # 포맷 스트링
        b"%s%s%s%s",
        b"%n%n%n%n",
        b"%x%x%x%x%x%x",
        b"AAAA%08x.%08x.%08x",
        # 경로 순회
        b"../../../etc/passwd",
        b"....//....//....//etc/passwd",
        b"..%2f..%2f..%2fetc/passwd",
        # SQL 인젝션
        b"' OR '1'='1",
        b"' OR '1'='1' --",
        b"1 OR 1=1",
        # XSS
        b"<script>alert(1)</script>",
        b'"><script>',
        # NULL 바이트
        b"\x00",
        b"\x00\x00\x00\x00",
        # 특수값
        b"\xff\xff\xff\xff",
        b"\x7f\xff\xff\xff",
    ]

    def __init__(self, extra_dict: List[bytes] = None):
        self.dictionary = self.DEFAULT_DICT.copy()
        if extra_dict:
            self.dictionary.extend(extra_dict)

    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        entry = random.choice(self.dictionary)

        # 삽입 또는 교체
        if len(data) == 0 or random.random() < 0.5:
            # 삽입
            pos = random.randint(0, len(data))
            data[pos:pos] = entry
            return data, MutationOp(name=self.name, offset=pos, size=0, old_value=b"", new_value=entry)
        else:
            # 교체
            pos = random.randint(0, max(0, len(data) - len(entry)))
            old_val = bytes(data[pos : pos + len(entry)])
            data[pos : pos + len(entry)] = entry
            return data, MutationOp(name=self.name, offset=pos, size=len(old_val), old_value=old_val, new_value=entry)


class SpliceMutator(BaseMutator):
    """코퍼스 간 결합 (Crossover)"""

    name = "splice"
    weight = 1.0

    def __init__(self):
        self.corpus: List[bytes] = []

    def set_corpus(self, corpus: List[bytes]):
        self.corpus = corpus

    def mutate(self, data: bytearray) -> Tuple[bytearray, Optional[MutationOp]]:
        if len(self.corpus) < 2 or len(data) < 4:
            return data, None

        # 다른 시드 선택
        other = random.choice(self.corpus)
        if len(other) < 4:
            return data, None

        # 교차점 선택
        split_a = random.randint(1, len(data) - 1)
        split_b = random.randint(1, len(other) - 1)

        # 결합
        if random.random() < 0.5:
            result = data[:split_a] + bytearray(other[split_b:])
        else:
            result = bytearray(other[:split_b]) + data[split_a:]

        return result, MutationOp(
            name=self.name,
            offset=split_a,
            size=len(data) - split_a,
            old_value=bytes(data[split_a:]),
            new_value=bytes(result[split_a:]),
        )


# ============================================================
# 뮤테이션 엔진
# ============================================================


class MutationEngine:
    """
    통합 뮤테이션 엔진

    여러 뮤테이터를 가중치 기반으로 선택하여 적용.
    프로토콜별 딕셔너리와 힌트 지원.
    """

    def __init__(self, extra_dict: List[bytes] = None, max_stacked: int = 5):
        """
        Args:
            extra_dict: 추가 딕셔너리 항목
            max_stacked: 스택 뮤테이션 최대 횟수
        """
        self.max_stacked = max_stacked

        # 뮤테이터 초기화
        self.mutators: List[BaseMutator] = [
            BitFlipMutator(),
            ByteFlipMutator(),
            ArithmeticMutator(),
            InterestingValueMutator(),
            RandomByteMutator(),
            DeleteMutator(),
            InsertMutator(),
            DuplicateMutator(),
            OverwriteMutator(),
            DictionaryMutator(extra_dict),
        ]

        # Splice 뮤테이터는 특별 관리
        self.splice_mutator = SpliceMutator()

        # 가중치 계산
        self._update_weights()

        # 통계
        self.stats = {m.name: 0 for m in self.mutators}
        self.stats["splice"] = 0

    def _update_weights(self):
        """가중치 기반 확률 계산"""
        total = sum(m.weight for m in self.mutators)
        self.probabilities = [m.weight / total for m in self.mutators]

    def set_corpus(self, corpus: List[bytes]):
        """코퍼스 설정 (splice용)"""
        self.splice_mutator.set_corpus(corpus)

    def add_dictionary(self, entries: List[bytes]):
        """딕셔너리 항목 추가"""
        for m in self.mutators:
            if isinstance(m, DictionaryMutator):
                m.dictionary.extend(entries)

    def mutate(self, data: bytes, protocol_hints: Dict[str, Any] = None) -> Tuple[bytes, List[MutationOp]]:
        """
        데이터 뮤테이션

        Args:
            data: 원본 데이터
            protocol_hints: 프로토콜별 힌트 (예: {'skip_header': 8})

        Returns:
            (변조된 데이터, 뮤테이션 이력)
        """
        result = bytearray(data)
        ops: List[MutationOp] = []

        # 스택 뮤테이션 횟수 결정
        num_mutations = random.randint(1, self.max_stacked)

        for _ in range(num_mutations):
            # Splice 확률 (코퍼스가 있을 때만)
            if self.splice_mutator.corpus and random.random() < 0.1:
                result, op = self.splice_mutator.mutate(result)
                if op:
                    ops.append(op)
                    self.stats["splice"] += 1
                continue

            # 일반 뮤테이터 선택
            mutator = random.choices(self.mutators, weights=self.probabilities)[0]

            # 프로토콜 힌트 적용
            if protocol_hints and protocol_hints.get("skip_header"):
                skip = protocol_hints["skip_header"]
                if len(result) > skip:
                    # 헤더 보존, 페이로드만 뮤테이션
                    header = result[:skip]
                    payload = result[skip:]
                    payload, op = mutator.mutate(payload)
                    if op:
                        op.offset += skip  # 오프셋 조정
                        ops.append(op)
                    result = header + payload
                    self.stats[mutator.name] += 1
                    continue

            result, op = mutator.mutate(result)
            if op:
                ops.append(op)
            self.stats[mutator.name] += 1

        return bytes(result), ops

    def havoc(self, data: bytes, rounds: int = None) -> bytes:
        """
        Havoc 모드 - 대량 랜덤 뮤테이션 (AFL havoc 스타일)

        Args:
            data: 원본 데이터
            rounds: 뮤테이션 라운드 수 (기본: 256)
        """
        if rounds is None:
            rounds = random.choice([2, 4, 8, 16, 32, 64, 128, 256])

        result = bytearray(data)

        for _ in range(rounds):
            mutator = random.choices(self.mutators, weights=self.probabilities)[0]
            result, _ = mutator.mutate(result)

        return bytes(result)

    def get_stats(self) -> Dict[str, int]:
        """뮤테이션 통계 반환"""
        return self.stats.copy()

    def reset_stats(self):
        """통계 초기화"""
        for key in self.stats:
            self.stats[key] = 0


# ============================================================
# 프로토콜별 뮤테이터 팩토리
# ============================================================


def create_udp_mutator() -> MutationEngine:
    """UDP 프로토콜용 뮤테이터 생성"""
    extra_dict = [
        b"EFUD",
        b"ipTM",
        b"get_config\x00",
        b"set_config\x00",
        b"status\x00",
        b"reboot\x00",
        b"\x00\x01",
        b"\x00\x02",
        b"\x00\x03",  # 명령어 코드
    ]
    return MutationEngine(extra_dict=extra_dict)


def create_http_mutator() -> MutationEngine:
    """HTTP 프로토콜용 뮤테이터 생성"""
    extra_dict = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HTTP/1.1\r\n",
        b"HTTP/1.0\r\n",
        b"Host: ",
        b"Content-Type: ",
        b"Content-Length: ",
        b"Cookie: ",
        b"Authorization: ",
        b"/cgi/d.cgi",
        b"/cgi/firmware.cgi",
        b"/login.cgi",
        b"/admin/",
        b"username=",
        b"password=",
        b"application/x-www-form-urlencoded",
        b"multipart/form-data",
    ]
    return MutationEngine(extra_dict=extra_dict)


def create_upnp_mutator() -> MutationEngine:
    """UPnP 프로토콜용 뮤테이터 생성"""
    extra_dict = [
        b"M-SEARCH * HTTP/1.1",
        b"NOTIFY * HTTP/1.1",
        b'MAN: "ssdp:discover"',
        b"ST: upnp:rootdevice",
        b"SOAPAction:",
        b"AddPortMapping",
        b"DeletePortMapping",
        b"GetExternalIPAddress",
        b"urn:schemas-upnp-org:service:WANIPConnection:1",
        b"<s:Envelope",
        b"</s:Envelope>",
        b"<NewRemoteHost>",
        b"<NewExternalPort>",
        b"<NewInternalClient>",
        b"<NewPortMappingDescription>",
    ]
    return MutationEngine(extra_dict=extra_dict)


def create_pptp_mutator() -> MutationEngine:
    """PPTP 프로토콜용 뮤테이터 생성"""
    extra_dict = [
        b"\x00\x9c",  # PPTP magic
        b"\x00\x01",  # Start-Control-Connection-Request
        b"\x00\x07",  # Outgoing-Call-Request
        b"\x1a\x2b\x3c\x4d",  # Cookie
    ]
    return MutationEngine(extra_dict=extra_dict)
