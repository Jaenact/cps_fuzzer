"""
ipTIME Firmware Fuzzer v2.0 - QEMU Coverage Collection
QEMU 기반 코드 커버리지 수집

QEMU User Mode 또는 System Mode를 사용하여
ARM/MIPS 바이너리의 코드 커버리지를 수집.
"""

import hashlib
import os
import re
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class CoverageResult:
    """커버리지 수집 결과"""

    edges: Set[int] = field(default_factory=set)
    blocks: Set[int] = field(default_factory=set)
    execution_time: float = 0.0
    exit_code: int = 0
    stdout: bytes = b""
    stderr: bytes = b""
    crashed: bool = False
    timeout: bool = False

    def get_edge_count(self) -> int:
        return len(self.edges)

    def get_block_count(self) -> int:
        return len(self.blocks)


class AFLBitmap:
    """AFL-style 커버리지 비트맵"""

    BITMAP_SIZE = 65536  # 64KB

    def __init__(self):
        self.bitmap = bytearray(self.BITMAP_SIZE)
        self.virgin_bits = bytearray([0xFF] * self.BITMAP_SIZE)

    def record_edge(self, src: int, dst: int):
        """엣지 기록"""
        edge_id = (src ^ dst) % self.BITMAP_SIZE
        self.bitmap[edge_id] = min(255, self.bitmap[edge_id] + 1)

    def record_block(self, addr: int):
        """블록 기록"""
        block_id = addr % self.BITMAP_SIZE
        self.bitmap[block_id] = min(255, self.bitmap[block_id] + 1)

    def has_new_coverage(self) -> bool:
        """새 커버리지 여부 확인"""
        for i in range(self.BITMAP_SIZE):
            if self.bitmap[i] and (self.virgin_bits[i] & self.bitmap[i]):
                return True
        return False

    def update_virgin_bits(self):
        """virgin bits 업데이트"""
        for i in range(self.BITMAP_SIZE):
            if self.bitmap[i]:
                self.virgin_bits[i] &= ~self.bitmap[i]

    def get_edge_count(self) -> int:
        """발견된 엣지 수"""
        return sum(1 for b in self.bitmap if b > 0)

    def get_total_hits(self) -> int:
        """총 히트 수"""
        return sum(self.bitmap)

    def reset(self):
        """비트맵 초기화"""
        self.bitmap = bytearray(self.BITMAP_SIZE)

    def merge_from(self, other: "AFLBitmap"):
        """다른 비트맵과 병합"""
        for i in range(self.BITMAP_SIZE):
            self.bitmap[i] = min(255, self.bitmap[i] + other.bitmap[i])


class QEMUCoverageCollector:
    """
    QEMU 기반 커버리지 수집기

    QEMU의 -d exec 옵션을 사용하여 실행된 주소를 추출하고,
    AFL-style 비트맵으로 변환.
    """

    def __init__(
        self, qemu_path: str = "qemu-mipsel", binary_path: str = None, libs_path: str = None, timeout: float = 5.0
    ):
        """
        Args:
            qemu_path: QEMU 실행 파일 경로
            binary_path: 타겟 바이너리 경로
            libs_path: 라이브러리 경로 (LD_LIBRARY_PATH)
            timeout: 실행 타임아웃
        """
        self.qemu_path = qemu_path
        self.binary_path = binary_path
        self.libs_path = libs_path
        self.timeout = timeout

        # 커버리지 데이터
        self.global_bitmap = AFLBitmap()
        self.all_edges: Set[int] = set()
        self.all_blocks: Set[int] = set()

        # 통계
        self.stats = {
            "total_runs": 0,
            "total_edges": 0,
            "total_blocks": 0,
            "crashes": 0,
            "timeouts": 0,
        }

        # 임시 디렉토리
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="qemu_cov_"))

    def run_with_coverage(self, input_data: bytes, stdin_input: bool = True) -> CoverageResult:
        """
        입력으로 바이너리 실행 및 커버리지 수집

        Args:
            input_data: 입력 데이터
            stdin_input: True면 stdin으로, False면 파일로 전달

        Returns:
            CoverageResult
        """
        result = CoverageResult()

        # 입력 파일 생성
        input_file = self.tmp_dir / f"input_{self.stats['total_runs']:08d}"
        input_file.write_bytes(input_data)

        # 로그 파일
        log_file = self.tmp_dir / f"trace_{self.stats['total_runs']:08d}.log"

        # QEMU 명령어 구성
        cmd = [
            self.qemu_path,
            "-d",
            "exec,nochain",
            "-D",
            str(log_file),
        ]

        if self.libs_path:
            cmd.extend(["-L", self.libs_path])

        cmd.append(self.binary_path)

        if not stdin_input:
            cmd.append(str(input_file))

        # 환경 변수
        env = os.environ.copy()
        if self.libs_path:
            env["LD_LIBRARY_PATH"] = self.libs_path

        # 실행
        start_time = time.time()
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if stdin_input else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )

            stdin_data = input_data if stdin_input else None
            stdout, stderr = proc.communicate(input=stdin_data, timeout=self.timeout)

            result.execution_time = time.time() - start_time
            result.exit_code = proc.returncode
            result.stdout = stdout
            result.stderr = stderr

            # 크래시 감지
            if proc.returncode < 0:
                result.crashed = True
                self.stats["crashes"] += 1

        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            result.timeout = True
            result.execution_time = self.timeout
            self.stats["timeouts"] += 1
        except Exception as e:
            result.stderr = str(e).encode()

        # 트레이스 파싱
        if log_file.exists():
            edges, blocks = self._parse_trace(log_file)
            result.edges = edges
            result.blocks = blocks

            # 전역 커버리지 업데이트
            self.all_edges.update(edges)
            self.all_blocks.update(blocks)

            for edge in edges:
                self.global_bitmap.record_edge(edge >> 16, edge & 0xFFFF)

        self.stats["total_runs"] += 1
        self.stats["total_edges"] = len(self.all_edges)
        self.stats["total_blocks"] = len(self.all_blocks)

        # 임시 파일 정리
        try:
            input_file.unlink()
            if log_file.exists():
                log_file.unlink()
        except:
            pass

        return result

    def _parse_trace(self, log_file: Path) -> Tuple[Set[int], Set[int]]:
        """QEMU 트레이스 로그 파싱"""
        edges: Set[int] = set()
        blocks: Set[int] = set()

        # 정규식: QEMU exec 로그 형식
        # Trace 0: 0x00400000 [...]
        addr_pattern = re.compile(rb"Trace \d+: 0x([0-9a-fA-F]+)")

        prev_addr = 0

        try:
            with open(log_file, "rb") as f:
                for line in f:
                    match = addr_pattern.search(line)
                    if match:
                        addr = int(match.group(1), 16)
                        blocks.add(addr)

                        if prev_addr:
                            # 엣지 = (이전 주소, 현재 주소)의 해시
                            edge = (prev_addr << 16) | (addr & 0xFFFF)
                            edges.add(edge)

                        prev_addr = addr
        except Exception:
            pass

        return edges, blocks

    def has_new_coverage(self, edges: Set[int]) -> bool:
        """새 커버리지 발견 여부"""
        return bool(edges - self.all_edges)

    def get_new_edges(self, edges: Set[int]) -> Set[int]:
        """새로 발견된 엣지"""
        return edges - self.all_edges

    def get_stats(self) -> Dict[str, Any]:
        """통계 반환"""
        return {
            **self.stats,
            "bitmap_coverage": self.global_bitmap.get_edge_count(),
            "bitmap_density": self.global_bitmap.get_edge_count() / AFLBitmap.BITMAP_SIZE * 100,
        }

    def cleanup(self):
        """임시 파일 정리"""
        import shutil

        try:
            shutil.rmtree(self.tmp_dir)
        except:
            pass


class DRCovCollector:
    """
    DynamoRIO Coverage 형식 파싱

    DynamoRIO의 drcov 도구로 수집된 커버리지 파일을 파싱.
    (QEMU 대신 DynamoRIO를 사용할 경우)
    """

    def __init__(self):
        self.modules: Dict[str, Tuple[int, int]] = {}  # name -> (base, size)
        self.coverage: Set[int] = set()

    def parse_drcov(self, filepath: str) -> Set[int]:
        """drcov 파일 파싱"""
        blocks: Set[int] = set()

        with open(filepath, "rb") as f:
            # 헤더 파싱
            line = f.readline()
            if not line.startswith(b"DRCOV VERSION:"):
                return blocks

            # 모듈 테이블 파싱
            while True:
                line = f.readline()
                if line.startswith(b"Module Table:"):
                    count = int(line.split(b":")[1].strip())
                    break

            # 모듈 정보 읽기
            header_line = f.readline()  # Columns 헤더
            for _ in range(count):
                line = f.readline().decode("utf-8", errors="replace")
                parts = line.strip().split(",")
                if len(parts) >= 5:
                    mod_id = int(parts[0])
                    base = int(parts[1], 16)
                    size = int(parts[2], 16)
                    name = parts[4]
                    self.modules[name] = (base, size)

            # BB 테이블 파싱
            while True:
                line = f.readline()
                if line.startswith(b"BB Table:"):
                    count = int(line.split(b":")[1].strip().split()[0])
                    break

            # BB 엔트리 읽기 (바이너리)
            for _ in range(count):
                entry = f.read(8)  # 4bytes offset, 2bytes size, 2bytes module_id
                if len(entry) < 8:
                    break
                offset, size, mod_id = struct.unpack("<IHH", entry)
                blocks.add(offset)

        self.coverage.update(blocks)
        return blocks


class NetworkCoverageProxy:
    """
    네트워크 기반 커버리지 프록시

    타겟이 원격인 경우, 커버리지 정보를 수집하는 프록시.
    QEMU가 타겟에서 실행되고, 커버리지는 소켓으로 전송.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9876):
        self.host = host
        self.port = port
        self.coverage_buffer: List[bytes] = []

    def receive_coverage(self, timeout: float = 1.0) -> Set[int]:
        """커버리지 데이터 수신"""
        import socket

        edges: Set[int] = set()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.bind((self.host, self.port))

            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    # 데이터 형식: [edge_count][edge1][edge2]...
                    count = struct.unpack("<I", data[:4])[0]
                    for i in range(min(count, (len(data) - 4) // 4)):
                        edge = struct.unpack("<I", data[4 + i * 4 : 8 + i * 4])[0]
                        edges.add(edge)
                except socket.timeout:
                    break

            sock.close()
        except:
            pass

        return edges


# 팩토리 함수
def create_coverage_collector(
    arch: str = "mipsel", binary_path: str = None, libs_path: str = None
) -> QEMUCoverageCollector:
    """커버리지 수집기 생성"""
    qemu_map = {
        "mipsel": "qemu-mipsel",
        "mips": "qemu-mips",
        "arm": "qemu-arm",
        "aarch64": "qemu-aarch64",
        "x86": "qemu-i386",
        "x86_64": "qemu-x86_64",
    }

    qemu_path = qemu_map.get(arch.lower(), f"qemu-{arch}")

    return QEMUCoverageCollector(qemu_path=qemu_path, binary_path=binary_path, libs_path=libs_path)
