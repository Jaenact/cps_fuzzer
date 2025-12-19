"""
ipTIME Firmware Fuzzer - Base Fuzzer Class
모든 프로토콜별 퍼저의 기본 클래스
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import time
import os
import json
import hashlib


@dataclass
class FuzzCase:
    """퍼징 테스트 케이스"""
    id: str
    data: bytes
    protocol: str
    timestamp: float
    mutations: List[str] = field(default_factory=list)
    parent_id: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'data_hex': self.data.hex(),
            'data_len': len(self.data),
            'protocol': self.protocol,
            'timestamp': self.timestamp,
            'mutations': self.mutations,
            'parent_id': self.parent_id
        }
    
    def get_hash(self) -> str:
        return hashlib.sha256(self.data).hexdigest()[:16]


@dataclass
class FuzzResult:
    """퍼징 결과"""
    case: FuzzCase
    response: Optional[bytes]
    response_time: float
    is_crash: bool
    is_timeout: bool
    is_interesting: bool
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            'case': self.case.to_dict(),
            'response_hex': self.response.hex() if self.response else None,
            'response_len': len(self.response) if self.response else 0,
            'response_time': self.response_time,
            'is_crash': self.is_crash,
            'is_timeout': self.is_timeout,
            'is_interesting': self.is_interesting,
            'error': self.error
        }


class BaseFuzzer(ABC):
    """
    퍼저 베이스 클래스
    
    모든 프로토콜별 퍼저가 상속받아야 하는 추상 클래스.
    공통 기능(통계, 코퍼스 관리, 크래시 저장 등)을 제공하고,
    프로토콜별 구현은 서브클래스에서 담당.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config.get('name', self.__class__.__name__)
        self.target_host = config.get('target_host', '127.0.0.1')
        self.target_port = config.get('target_port')
        self.timeout = config.get('timeout', 5.0)
        self.max_iterations = config.get('max_iterations', 100000)
        self.delay = config.get('delay', 0.01)  # 요청 간 딜레이
        
        # 저장 경로
        self.crash_dir = config.get('crash_dir', './reports/crashes')
        self.log_dir = config.get('log_dir', './reports/logs')
        
        # 통계
        self.stats = {
            'total_cases': 0,
            'crashes': 0,
            'timeouts': 0,
            'interesting': 0,
            'unique_crashes': 0,
            'start_time': None,
            'last_crash_time': None,
            'exec_per_sec': 0.0
        }
        
        # 코퍼스 및 크래시 관리
        self.corpus: List[bytes] = []
        self.crash_cases: List[FuzzCase] = []
        self.interesting_cases: List[FuzzCase] = []
        self.seen_crashes: set = set()  # 중복 크래시 필터링
        
        # 실행 상태
        self.running = False
        
        # 디렉토리 생성
        os.makedirs(self.crash_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
    
    # ========== 추상 메서드 (서브클래스에서 구현) ==========
    
    @abstractmethod
    def send(self, data: bytes) -> Optional[bytes]:
        """
        데이터 전송 및 응답 수신
        
        Args:
            data: 전송할 페이로드
            
        Returns:
            응답 데이터 또는 None (타임아웃/에러 시)
        """
        pass
    
    @abstractmethod
    def generate_seed(self) -> bytes:
        """
        초기 시드 데이터 생성
        
        Returns:
            유효한 프로토콜 형식의 시드 데이터
        """
        pass
    
    @abstractmethod
    def mutate(self, data: bytes) -> bytes:
        """
        데이터 뮤테이션
        
        Args:
            data: 원본 데이터
            
        Returns:
            변조된 데이터
        """
        pass
    
    @abstractmethod
    def is_crash(self, response: Optional[bytes], error: Optional[str]) -> bool:
        """
        크래시 여부 판단
        
        Args:
            response: 응답 데이터
            error: 에러 메시지
            
        Returns:
            크래시 여부
        """
        pass
    
    # ========== 선택적 오버라이드 ==========
    
    def is_interesting(self, response: Optional[bytes]) -> bool:
        """
        흥미로운 응답 여부 판단 (코퍼스 추가 기준)
        기본 구현: 항상 False
        """
        return False
    
    def on_crash(self, result: FuzzResult):
        """크래시 발견 시 콜백"""
        pass
    
    def on_interesting(self, result: FuzzResult):
        """흥미로운 케이스 발견 시 콜백"""
        pass
    
    # ========== 핵심 퍼징 로직 ==========
    
    def fuzz_one(self, seed: bytes) -> FuzzResult:
        """단일 퍼징 실행"""
        mutated = self.mutate(seed)
        
        case = FuzzCase(
            id=f"{self.name}_{self.stats['total_cases']:08d}",
            data=mutated,
            protocol=self.name,
            timestamp=time.time(),
            mutations=[]
        )
        
        start_time = time.time()
        response = None
        error = None
        
        try:
            response = self.send(mutated)
            response_time = time.time() - start_time
            
            is_crash = self.is_crash(response, None)
            is_timeout = response is None and response_time >= self.timeout
            is_interesting = self.is_interesting(response)
            
        except Exception as e:
            response_time = time.time() - start_time
            error = str(e)
            is_crash = self.is_crash(None, error)
            is_timeout = True
            is_interesting = False
        
        return FuzzResult(
            case=case,
            response=response,
            response_time=response_time,
            is_crash=is_crash,
            is_timeout=is_timeout,
            is_interesting=is_interesting,
            error=error
        )
    
    def select_seed(self) -> bytes:
        """시드 선택 전략 (기본: 랜덤)"""
        import random
        if not self.corpus:
            return self.generate_seed()
        return random.choice(self.corpus)
    
    def process_result(self, result: FuzzResult):
        """결과 처리"""
        if result.is_crash:
            crash_hash = result.case.get_hash()
            
            # 중복 크래시 필터링
            if crash_hash not in self.seen_crashes:
                self.seen_crashes.add(crash_hash)
                self.stats['unique_crashes'] += 1
                self.crash_cases.append(result.case)
                self.save_crash(result)
                self.on_crash(result)
            
            self.stats['crashes'] += 1
            self.stats['last_crash_time'] = time.time()
        
        if result.is_timeout:
            self.stats['timeouts'] += 1
        
        if result.is_interesting:
            self.stats['interesting'] += 1
            self.interesting_cases.append(result.case)
            self.corpus.append(result.case.data)
            self.on_interesting(result)
    
    def save_crash(self, result: FuzzResult):
        """크래시 저장"""
        crash_hash = result.case.get_hash()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        # 바이너리 데이터 저장
        crash_file = os.path.join(
            self.crash_dir, 
            f"crash_{self.name}_{timestamp}_{crash_hash}.bin"
        )
        with open(crash_file, 'wb') as f:
            f.write(result.case.data)
        
        # 메타데이터 저장
        meta_file = os.path.join(
            self.crash_dir,
            f"crash_{self.name}_{timestamp}_{crash_hash}.json"
        )
        with open(meta_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        
        print(f"\n[!] CRASH SAVED: {crash_file}")
    
    def load_corpus(self, corpus_dir: str):
        """코퍼스 로드"""
        if not os.path.exists(corpus_dir):
            return
        
        for filename in os.listdir(corpus_dir):
            filepath = os.path.join(corpus_dir, filename)
            if os.path.isfile(filepath):
                with open(filepath, 'rb') as f:
                    self.corpus.append(f.read())
        
        print(f"[*] Loaded {len(self.corpus)} seeds from {corpus_dir}")
    
    def print_stats(self):
        """통계 출력"""
        elapsed = time.time() - self.stats['start_time']
        rate = self.stats['total_cases'] / elapsed if elapsed > 0 else 0
        self.stats['exec_per_sec'] = rate
        
        print(f"\r[{self.name}] "
              f"Cases: {self.stats['total_cases']:,} | "
              f"Crashes: {self.stats['unique_crashes']} | "
              f"Interesting: {self.stats['interesting']} | "
              f"Corpus: {len(self.corpus)} | "
              f"Rate: {rate:.1f}/s", end='', flush=True)
    
    def run(self):
        """메인 퍼징 루프"""
        self.stats['start_time'] = time.time()
        self.running = True
        
        # 시드 코퍼스 초기화
        if not self.corpus:
            self.corpus.append(self.generate_seed())
        
        print(f"\n[+] Starting {self.name} fuzzer")
        print(f"    Target: {self.target_host}:{self.target_port}")
        print(f"    Max iterations: {self.max_iterations:,}")
        print(f"    Initial corpus: {len(self.corpus)} seeds")
        print()
        
        iteration = 0
        try:
            while self.running and iteration < self.max_iterations:
                # 시드 선택
                seed = self.select_seed()
                
                # 퍼징 실행
                result = self.fuzz_one(seed)
                self.stats['total_cases'] += 1
                iteration += 1
                
                # 결과 처리
                self.process_result(result)
                
                # 상태 출력
                if iteration % 100 == 0:
                    self.print_stats()
                
                # 딜레이
                if self.delay > 0:
                    time.sleep(self.delay)
                    
        except KeyboardInterrupt:
            print("\n\n[!] Fuzzing interrupted by user")
        
        self.running = False
        self.print_final_stats()
    
    def print_final_stats(self):
        """최종 통계 출력"""
        elapsed = time.time() - self.stats['start_time']
        
        print("\n" + "=" * 60)
        print(f" {self.name} FINAL STATISTICS")
        print("=" * 60)
        print(f"  Total cases:     {self.stats['total_cases']:,}")
        print(f"  Unique crashes:  {self.stats['unique_crashes']}")
        print(f"  Total crashes:   {self.stats['crashes']}")
        print(f"  Interesting:     {self.stats['interesting']}")
        print(f"  Timeouts:        {self.stats['timeouts']}")
        print(f"  Final corpus:    {len(self.corpus)}")
        print(f"  Elapsed time:    {elapsed:.1f}s")
        print(f"  Avg exec/sec:    {self.stats['total_cases']/elapsed:.1f}")
        print("=" * 60)
    
    def stop(self):
        """퍼저 중지"""
        self.running = False
