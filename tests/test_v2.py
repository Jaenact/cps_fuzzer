"""
ipTIME Fuzzer v2.0 - Test Suite
v2.0 기능 단위 테스트
"""

import os
import sys
from pathlib import Path

# 프로젝트 루트 추가
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# yaml 없어도 테스트 가능하도록 환경 설정
os.chdir(project_root)


class TestMutatorEngine:
    """뮤테이션 엔진 테스트"""

    def test_import(self):
        """모듈 임포트 테스트"""
        from mutators.mutator_engine import BitFlipMutator, MutationEngine

        assert MutationEngine is not None
        assert BitFlipMutator is not None

    def test_bitflip_mutator(self):
        """BitFlip 뮤테이터 테스트"""
        from mutators.mutator_engine import BitFlipMutator

        mutator = BitFlipMutator()
        original = b"AAAA"
        mutated, ops = mutator.mutate(bytearray(original))

        # 뮤테이션이 발생했는지 확인
        assert mutated is not None
        assert len(mutated) == len(original)

    def test_mutation_engine(self):
        """MutationEngine 전체 테스트"""
        from mutators.mutator_engine import MutationEngine

        engine = MutationEngine()
        original = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"
        mutated, ops = engine.mutate(original)

        assert mutated is not None
        assert isinstance(ops, list)


class TestScheduler:
    """스케줄러 테스트"""

    def test_import(self):
        """모듈 임포트 테스트"""
        from core.scheduler import CorpusEntry, EnergyScheduler, ScheduleStrategy

        assert EnergyScheduler is not None

    def test_energy_scheduler(self):
        """EnergyScheduler 테스트"""
        from core.scheduler import EnergyScheduler, ScheduleStrategy

        scheduler = EnergyScheduler(strategy=ScheduleStrategy.FAST)
        scheduler.add(b"seed1", "test")
        scheduler.add(b"seed2", "test")

        entry = scheduler.select()
        assert entry is not None
        assert entry.data in [b"seed1", b"seed2"]

    def test_strategy_change(self):
        """전략 변경 테스트"""
        from core.scheduler import EnergyScheduler, ScheduleStrategy

        scheduler = EnergyScheduler(strategy=ScheduleStrategy.EXPLORE)
        assert scheduler.strategy == ScheduleStrategy.EXPLORE

        scheduler.set_strategy(ScheduleStrategy.EXPLOIT)
        assert scheduler.strategy == ScheduleStrategy.EXPLOIT


class TestCrashDetector:
    """크래시 감지 테스트"""

    def test_import(self):
        """모듈 임포트 테스트"""
        from monitors.crash_detector import CrashDetector, CrashType

        assert CrashDetector is not None
        assert CrashType is not None

    def test_response_analyzer(self):
        """ResponseAnalyzer 테스트"""
        from monitors.crash_detector import ResponseAnalyzer

        analyzer = ResponseAnalyzer()

        # 정상 응답
        crash, tags = analyzer.analyze(b"HTTP/1.1 200 OK")
        assert crash is None

        # 크래시 시그니처
        crash, tags = analyzer.analyze(b"Segmentation fault at 0x41414141")
        assert crash is not None
        assert crash.type.name == "SEGFAULT"


class TestProtocols:
    """프로토콜 정의 테스트"""

    def test_import(self):
        """모듈 임포트 테스트"""
        from protocols.iptime_protocol import HTTPSpec, IPTimeUDPSpec, UPnPSpec

        assert IPTimeUDPSpec is not None

    def test_udp_generation(self):
        """UDP 패킷 생성 테스트"""
        from protocols.iptime_protocol import IPTimeUDPSpec

        packet = IPTimeUDPSpec.generate_discovery()
        assert packet is not None
        assert len(packet) > 0
        assert packet[:4] == b"EFUD"

    def test_http_generation(self):
        """HTTP 요청 생성 테스트"""
        from protocols.iptime_protocol import HTTPSpec

        request = HTTPSpec.generate_get_request("/test")
        assert b"GET /test" in request


class TestPPTPFuzzer:
    """PPTP 퍼저 테스트"""

    def test_import(self):
        """모듈 임포트 테스트"""
        from fuzzers.pptp_fuzzer import PPTPFuzzer

        assert PPTPFuzzer is not None

    def test_seed_generation(self):
        """시드 생성 테스트"""
        from fuzzers.pptp_fuzzer import PPTPFuzzer

        fuzzer = PPTPFuzzer(
            {
                "name": "test",
                "target_host": "127.0.0.1",
                "target_port": 1723,
            }
        )

        seed = fuzzer.generate_seed()
        assert seed is not None
        assert len(seed) > 0


class TestDistributed:
    """분산 기능 테스트"""

    def test_import(self):
        """모듈 임포트 테스트"""
        from core.distributed import LocalCoordinator, create_coordinator

        assert LocalCoordinator is not None

    def test_local_coordinator(self):
        """LocalCoordinator 테스트"""
        from core.distributed import LocalCoordinator

        coord = LocalCoordinator()

        # 코퍼스 공유
        hash1 = coord.share_corpus(b"test_corpus", "http")
        assert hash1 is not None

        # 코퍼스 가져오기
        corpus = coord.get_corpus()
        assert b"test_corpus" in corpus


class TestReproducer:
    """재현 기능 테스트"""

    def test_import(self):
        """모듈 임포트 테스트"""
        from core.reproducer import ReproducibleTestCase, TestCaseRecorder

        assert ReproducibleTestCase is not None

    def test_testcase_creation(self):
        """테스트케이스 생성 테스트"""
        from core.reproducer import ReproducibleTestCase

        tc = ReproducibleTestCase(
            case_id="tc_test",
            protocol="http",
            seed_hash="abc123",
            seed_data_hex="48454c4c4f",  # HELLO
            final_data_hex="48454c4c4f",
            final_size=5,
        )

        assert tc.get_seed_data() == b"HELLO"


def run_all_tests():
    """모든 테스트 실행"""
    test_classes = [
        TestMutatorEngine,
        TestScheduler,
        TestCrashDetector,
        TestProtocols,
        TestPPTPFuzzer,
        TestDistributed,
        TestReproducer,
    ]

    total = 0
    passed = 0
    failed = 0

    for test_class in test_classes:
        print(f"\n[+] Running {test_class.__name__}...")
        instance = test_class()

        for method_name in dir(instance):
            if method_name.startswith("test_"):
                total += 1
                try:
                    getattr(instance, method_name)()
                    print(f"  ✓ {method_name}")
                    passed += 1
                except Exception as e:
                    print(f"  ✗ {method_name}: {e}")
                    failed += 1

    print(f"\n{'='*50}")
    print(f"Results: {passed}/{total} passed, {failed} failed")

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
