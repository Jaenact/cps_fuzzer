"""
ipTIME Firmware Fuzzer v2.0 - Reproducible Test Case Generator
재현 가능한 테스트케이스 생성 및 관리

뮤테이션 이력을 기록하여 동일한 테스트케이스를
결정론적으로 재생성할 수 있게 함.
"""

import hashlib
import json
import random
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class MutationRecord:
    """뮤테이션 기록"""

    mutator_name: str
    offset: int
    size: int
    old_value_hex: str
    new_value_hex: str
    random_seed: int  # 재현용 랜덤 시드

    @classmethod
    def from_op(cls, op, seed: int) -> "MutationRecord":
        """MutationOp에서 생성"""
        return cls(
            mutator_name=op.name,
            offset=op.offset,
            size=op.size,
            old_value_hex=op.old_value.hex(),
            new_value_hex=op.new_value.hex(),
            random_seed=seed,
        )


@dataclass
class ReproducibleTestCase:
    """재현 가능한 테스트케이스"""

    # 식별
    case_id: str
    protocol: str

    # 시드 정보
    seed_hash: str
    seed_data_hex: str  # 원본 시드 (hex)

    # 뮤테이션 이력
    mutations: List[MutationRecord] = field(default_factory=list)
    global_random_seed: int = 0

    # 결과 데이터
    final_data_hex: str = ""
    final_size: int = 0

    # 메타데이터
    created_at: float = field(default_factory=time.time)
    discovered_crash: bool = False
    crash_type: str = ""
    interesting: bool = False
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReproducibleTestCase":
        mutations = [MutationRecord(**m) if isinstance(m, dict) else m for m in data.get("mutations", [])]
        data["mutations"] = mutations
        return cls(**data)

    def get_seed_data(self) -> bytes:
        """원본 시드 데이터 반환"""
        return bytes.fromhex(self.seed_data_hex)

    def get_final_data(self) -> bytes:
        """최종 데이터 반환"""
        return bytes.fromhex(self.final_data_hex)

    def replay(self, mutation_engine=None) -> bytes:
        """
        뮤테이션 재현

        동일한 시드와 랜덤 시드를 사용하여
        동일한 결과 데이터를 생성.
        """
        # 랜덤 시드 복원
        random.seed(self.global_random_seed)

        # 시드 데이터로 시작
        data = bytearray(self.get_seed_data())

        # 뮤테이션 순차 적용
        for record in self.mutations:
            random.seed(record.random_seed)

            # 뮤테이션 적용 (직접 적용)
            new_value = bytes.fromhex(record.new_value_hex)
            if record.size == 0:  # 삽입
                data[record.offset : record.offset] = new_value
            else:  # 교체/삭제
                data[record.offset : record.offset + record.size] = new_value

        return bytes(data)

    def to_report(self) -> str:
        """사람이 읽을 수 있는 리포트 생성"""
        lines = [
            f"# Test Case Report: {self.case_id}",
            f"",
            f"**Protocol:** {self.protocol}",
            f"**Created:** {datetime.fromtimestamp(self.created_at)}",
            f"**Crash:** {self.crash_type if self.discovered_crash else 'No'}",
            f"",
            f"## Seed Info",
            f"- Hash: {self.seed_hash}",
            f"- Size: {len(self.seed_data_hex) // 2} bytes",
            f"",
            f"## Mutations ({len(self.mutations)} total)",
        ]

        for i, m in enumerate(self.mutations):
            lines.append(f"{i+1}. {m.mutator_name} @ offset {m.offset}")

        lines.extend(
            [
                f"",
                f"## Final Data",
                f"- Size: {self.final_size} bytes",
                f"- Hash: {hashlib.sha256(self.get_final_data()).hexdigest()[:16]}",
                f"",
                f"```",
                self.final_data_hex[:200] + ("..." if len(self.final_data_hex) > 200 else ""),
                f"```",
            ]
        )

        return "\n".join(lines)


class TestCaseRecorder:
    """
    테스트케이스 레코더

    퍼징 중 테스트케이스를 기록하고 재현 가능하게 저장.
    """

    def __init__(self, output_dir: str = "./testcases"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.current_seed: bytes = b""
        self.current_seed_hash: str = ""
        self.current_mutations: List[MutationRecord] = []
        self.current_random_seed: int = 0

        self.case_counter = 0

    def start_case(self, seed: bytes, protocol: str = ""):
        """테스트케이스 기록 시작"""
        self.current_seed = seed
        self.current_seed_hash = hashlib.sha256(seed).hexdigest()[:16]
        self.current_mutations = []
        self.current_random_seed = random.randint(0, 2**32 - 1)
        self.protocol = protocol

    def record_mutation(self, op, random_seed: int = None):
        """뮤테이션 기록"""
        if random_seed is None:
            random_seed = random.randint(0, 2**32 - 1)

        record = MutationRecord.from_op(op, random_seed)
        self.current_mutations.append(record)

    def finish_case(
        self,
        final_data: bytes,
        discovered_crash: bool = False,
        crash_type: str = "",
        interesting: bool = False,
        tags: List[str] = None,
    ) -> ReproducibleTestCase:
        """테스트케이스 기록 완료"""
        self.case_counter += 1

        case = ReproducibleTestCase(
            case_id=f"tc_{self.case_counter:08d}_{self.current_seed_hash[:8]}",
            protocol=self.protocol,
            seed_hash=self.current_seed_hash,
            seed_data_hex=self.current_seed.hex(),
            mutations=self.current_mutations.copy(),
            global_random_seed=self.current_random_seed,
            final_data_hex=final_data.hex(),
            final_size=len(final_data),
            discovered_crash=discovered_crash,
            crash_type=crash_type,
            interesting=interesting,
            tags=tags or [],
        )

        return case

    def save_case(self, case: ReproducibleTestCase, include_binary: bool = True) -> Tuple[Path, Optional[Path]]:
        """테스트케이스 저장"""
        # JSON 메타데이터
        json_path = self.output_dir / f"{case.case_id}.json"
        with open(json_path, "w") as f:
            json.dump(case.to_dict(), f, indent=2)

        bin_path = None
        if include_binary:
            # 바이너리 데이터
            bin_path = self.output_dir / f"{case.case_id}.bin"
            bin_path.write_bytes(case.get_final_data())

        return json_path, bin_path

    def load_case(self, case_id: str) -> Optional[ReproducibleTestCase]:
        """테스트케이스 로드"""
        json_path = self.output_dir / f"{case_id}.json"

        if not json_path.exists():
            return None

        with open(json_path, "r") as f:
            data = json.load(f)

        return ReproducibleTestCase.from_dict(data)

    def list_cases(self, crashes_only: bool = False, protocol: str = None) -> List[str]:
        """저장된 테스트케이스 목록"""
        cases = []

        for json_file in self.output_dir.glob("tc_*.json"):
            try:
                with open(json_file, "r") as f:
                    data = json.load(f)

                if crashes_only and not data.get("discovered_crash"):
                    continue

                if protocol and data.get("protocol") != protocol:
                    continue

                cases.append(data["case_id"])
            except:
                pass

        return sorted(cases)


class TestCaseReplayer:
    """
    테스트케이스 재생기

    저장된 테스트케이스를 로드하여 재현.
    """

    def __init__(self, testcase_dir: str = "./testcases"):
        self.testcase_dir = Path(testcase_dir)

    def replay(self, case_id: str) -> Optional[bytes]:
        """테스트케이스 재현"""
        json_path = self.testcase_dir / f"{case_id}.json"

        if not json_path.exists():
            return None

        with open(json_path, "r") as f:
            data = json.load(f)

        case = ReproducibleTestCase.from_dict(data)
        return case.replay()

    def verify(self, case_id: str) -> bool:
        """재현 검증 (원본과 재생 결과 비교)"""
        case = self.load_case(case_id)
        if not case:
            return False

        replayed = case.replay()
        original = case.get_final_data()

        return replayed == original

    def load_case(self, case_id: str) -> Optional[ReproducibleTestCase]:
        """테스트케이스 로드"""
        json_path = self.testcase_dir / f"{case_id}.json"

        if not json_path.exists():
            return None

        with open(json_path, "r") as f:
            data = json.load(f)

        return ReproducibleTestCase.from_dict(data)

    def export_poc(self, case_id: str, output_path: str = None) -> Optional[str]:
        """PoC 스크립트 생성"""
        case = self.load_case(case_id)
        if not case:
            return None

        # Note: Using regular string formatting to avoid f-string escaping issues
        poc_script = '''#!/usr/bin/env python3
"""
PoC for Test Case: {case_id}
Protocol: {protocol}
Generated: {generated}
"""

import socket

# Payload (hex decoded)
PAYLOAD = bytes.fromhex("{payload_hex}")

def main():
    # TODO: 타겟 설정
    TARGET_HOST = "192.168.0.1"
    TARGET_PORT = 80  # Check protocol
    
    print(f"Sending payload ({{len(PAYLOAD)}} bytes) to {{TARGET_HOST}}:{{TARGET_PORT}}")
    
    # TCP 전송
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        sock.connect((TARGET_HOST, TARGET_PORT))
        sock.sendall(PAYLOAD)
        response = sock.recv(4096)
        print(f"Response: {{response[:100]}}")
    except Exception as e:
        print(f"Error: {{e}}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
'''.format(
            case_id=case.case_id,
            protocol=case.protocol,
            generated=datetime.now().isoformat(),
            payload_hex=case.final_data_hex,
        )

        if output_path:
            Path(output_path).write_text(poc_script)

        return poc_script


# 팩토리 함수
def create_recorder(output_dir: str = "./testcases") -> TestCaseRecorder:
    """레코더 생성"""
    return TestCaseRecorder(output_dir)


def create_replayer(testcase_dir: str = "./testcases") -> TestCaseReplayer:
    """재생기 생성"""
    return TestCaseReplayer(testcase_dir)
