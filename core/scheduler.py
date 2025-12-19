"""
ipTIME Firmware Fuzzer v2.0 - Energy-Based Scheduler
AFL-style 에너지 기반 코퍼스 스케줄링
"""

import random
import time
import math
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class ScheduleStrategy(Enum):
    """스케줄링 전략"""
    FAST = "fast"           # AFL-fast: 적은 실행 우선
    COV = "cov"             # 커버리지 우선
    EXPLORE = "explore"     # 탐색 우선 (새로운 시드)
    EXPLOIT = "exploit"     # 착취 우선 (성공적인 시드)
    QUAD = "quad"           # 제곱 가중치


@dataclass
class CorpusEntry:
    """코퍼스 엔트리 (에너지 정보 포함)"""
    
    # 식별
    id: str
    data: bytes
    
    # 에너지 및 스케줄링
    energy: float = 1.0
    handicap: float = 1.0       # 불리함 가중치
    depth: int = 0              # 뮤테이션 깊이 (부모로부터)
    
    # 통계
    exec_count: int = 0         # 실행 횟수
    found_crashes: int = 0      # 발견한 크래시 수
    found_new_cov: int = 0      # 발견한 새 커버리지
    found_interesting: int = 0  # 발견한 흥미로운 케이스
    
    # 시간
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    
    # 부모 추적
    parent_id: Optional[str] = None
    
    # 추가 메타데이터
    protocol: str = ""
    source: str = "initial"     # initial, mutation, splice, import
    
    def update_energy(self, strategy: ScheduleStrategy):
        """전략에 따라 에너지 업데이트"""
        base_energy = 1.0
        
        if strategy == ScheduleStrategy.FAST:
            # 적게 실행된 시드에 높은 에너지
            if self.exec_count == 0:
                base_energy = 8.0
            else:
                base_energy = max(1.0, 8.0 / math.log2(self.exec_count + 1))
                
        elif strategy == ScheduleStrategy.COV:
            # 커버리지 발견에 비례
            base_energy = 1.0 + (self.found_new_cov * 2.0)
            
        elif strategy == ScheduleStrategy.EXPLORE:
            # 최근 생성된 시드 우선
            age = time.time() - self.created_at
            base_energy = max(1.0, 10.0 / (1 + age / 3600))  # 1시간 기준
            
        elif strategy == ScheduleStrategy.EXPLOIT:
            # 성공적인 시드 우선
            success = self.found_crashes + self.found_interesting
            base_energy = 1.0 + (success * 3.0)
            
        elif strategy == ScheduleStrategy.QUAD:
            # 제곱 가중치
            if self.exec_count == 0:
                base_energy = 16.0
            else:
                base_energy = max(1.0, 16.0 / (self.exec_count ** 0.5))
        
        # 핸디캡 적용
        self.energy = base_energy * self.handicap
        
        # 깊이에 따른 페널티 (너무 깊은 뮤테이션 방지)
        if self.depth > 10:
            self.energy *= 0.5
        elif self.depth > 20:
            self.energy *= 0.25


class EnergyScheduler:
    """
    에너지 기반 코퍼스 스케줄러
    
    AFL의 power scheduling을 구현하여,
    더 유망한 시드에 더 많은 에너지를 할당.
    """
    
    def __init__(self, 
                 strategy: ScheduleStrategy = ScheduleStrategy.FAST,
                 min_energy: float = 0.1,
                 max_energy: float = 100.0):
        self.strategy = strategy
        self.min_energy = min_energy
        self.max_energy = max_energy
        
        self.corpus: List[CorpusEntry] = []
        self.entry_map: Dict[str, CorpusEntry] = {}
        
        # 통계
        self.total_mutations = 0
        self.total_crashes = 0
        self.total_interesting = 0
    
    def add(self, data: bytes, 
            parent_id: Optional[str] = None,
            protocol: str = "",
            source: str = "initial") -> CorpusEntry:
        """
        새 엔트리 추가
        
        Returns:
            생성된 CorpusEntry
        """
        entry_id = f"{protocol}_{len(self.corpus):08d}_{hash(data) & 0xFFFFFFFF:08x}"
        
        # 부모 깊이 계산
        depth = 0
        if parent_id and parent_id in self.entry_map:
            depth = self.entry_map[parent_id].depth + 1
        
        entry = CorpusEntry(
            id=entry_id,
            data=data,
            depth=depth,
            parent_id=parent_id,
            protocol=protocol,
            source=source
        )
        
        entry.update_energy(self.strategy)
        
        self.corpus.append(entry)
        self.entry_map[entry_id] = entry
        
        return entry
    
    def select(self) -> Optional[CorpusEntry]:
        """
        에너지 기반 시드 선택
        
        Returns:
            선택된 CorpusEntry
        """
        if not self.corpus:
            return None
        
        # 에너지 정규화
        total_energy = sum(e.energy for e in self.corpus)
        if total_energy == 0:
            return random.choice(self.corpus)
        
        # 룰렛 휠 선택
        pick = random.uniform(0, total_energy)
        current = 0
        
        for entry in self.corpus:
            current += entry.energy
            if current >= pick:
                entry.exec_count += 1
                entry.last_used = time.time()
                return entry
        
        return self.corpus[-1]
    
    def update_on_result(self, entry_id: str, 
                         is_crash: bool = False,
                         is_interesting: bool = False,
                         new_coverage: bool = False):
        """
        실행 결과에 따라 엔트리 업데이트
        
        Args:
            entry_id: 엔트리 ID
            is_crash: 크래시 발생 여부
            is_interesting: 흥미로운 결과 여부
            new_coverage: 새 커버리지 발견 여부
        """
        if entry_id not in self.entry_map:
            return
            
        entry = self.entry_map[entry_id]
        
        if is_crash:
            entry.found_crashes += 1
            self.total_crashes += 1
            
        if is_interesting:
            entry.found_interesting += 1
            self.total_interesting += 1
            
        if new_coverage:
            entry.found_new_cov += 1
        
        # 에너지 재계산
        entry.update_energy(self.strategy)
        
        # 에너지 범위 제한
        entry.energy = max(self.min_energy, min(self.max_energy, entry.energy))
    
    def cull(self, keep_top: int = None, 
             min_corpus_size: int = 100) -> int:
        """
        코퍼스 정리 (저에너지 엔트리 제거)
        
        Args:
            keep_top: 유지할 상위 엔트리 수
            min_corpus_size: 최소 코퍼스 크기
            
        Returns:
            제거된 엔트리 수
        """
        if len(self.corpus) <= min_corpus_size:
            return 0
            
        if keep_top is None:
            keep_top = max(min_corpus_size, len(self.corpus) // 2)
        
        # 에너지 기준 정렬
        sorted_corpus = sorted(self.corpus, key=lambda e: e.energy, reverse=True)
        
        # 상위 유지, 하위 제거
        to_remove = sorted_corpus[keep_top:]
        removed_count = len(to_remove)
        
        for entry in to_remove:
            if entry.id in self.entry_map:
                del self.entry_map[entry.id]
        
        self.corpus = sorted_corpus[:keep_top]
        
        return removed_count
    
    def get_mutations_for_entry(self, entry: CorpusEntry) -> int:
        """
        엔트리에 적용할 뮤테이션 횟수 결정
        
        에너지에 비례하여 뮤테이션 횟수 결정.
        
        Returns:
            권장 뮤테이션 횟수
        """
        base_mutations = 16
        mutations = int(base_mutations * entry.energy)
        
        # 범위 제한
        return max(1, min(mutations, 1024))
    
    def set_strategy(self, strategy: ScheduleStrategy):
        """전략 변경 및 전체 에너지 재계산"""
        self.strategy = strategy
        for entry in self.corpus:
            entry.update_energy(strategy)
    
    def get_stats(self) -> Dict[str, Any]:
        """스케줄러 통계"""
        if not self.corpus:
            return {
                'corpus_size': 0,
                'total_energy': 0,
                'avg_energy': 0,
            }
            
        energies = [e.energy for e in self.corpus]
        exec_counts = [e.exec_count for e in self.corpus]
        
        return {
            'corpus_size': len(self.corpus),
            'total_energy': sum(energies),
            'avg_energy': sum(energies) / len(self.corpus),
            'max_energy': max(energies),
            'min_energy': min(energies),
            'total_executions': sum(exec_counts),
            'avg_executions': sum(exec_counts) / len(self.corpus),
            'total_crashes': self.total_crashes,
            'total_interesting': self.total_interesting,
            'strategy': self.strategy.value,
        }
    
    def get_top_entries(self, n: int = 10) -> List[CorpusEntry]:
        """에너지 기준 상위 엔트리"""
        return sorted(self.corpus, key=lambda e: e.energy, reverse=True)[:n]
    
    def export_corpus(self) -> List[bytes]:
        """순수 바이트 코퍼스 추출 (하위 호환용)"""
        return [entry.data for entry in self.corpus]
    
    def import_from_bytes(self, corpus: List[bytes], protocol: str = ""):
        """바이트 리스트에서 코퍼스 임포트"""
        for data in corpus:
            self.add(data, protocol=protocol, source="import")


class AdaptiveScheduler(EnergyScheduler):
    """
    적응형 스케줄러
    
    퍼징 진행 상황에 따라 자동으로 전략 전환.
    """
    
    def __init__(self, initial_strategy: ScheduleStrategy = ScheduleStrategy.EXPLORE):
        super().__init__(strategy=initial_strategy)
        
        self.phase = "explore"
        self.phase_start = time.time()
        self.phase_duration = 300  # 5분
        
        self.last_crash_time = 0
        self.last_interesting_time = 0
    
    def update_phase(self):
        """퍼징 페이즈 업데이트"""
        now = time.time()
        elapsed = now - self.phase_start
        
        if elapsed < self.phase_duration:
            return
        
        # 최근 성과에 따라 전략 결정
        crash_gap = now - self.last_crash_time if self.last_crash_time else float('inf')
        interesting_gap = now - self.last_interesting_time if self.last_interesting_time else float('inf')
        
        if crash_gap > 600 and interesting_gap > 300:
            # 오래 발견 없음 → 탐색 모드
            if self.strategy != ScheduleStrategy.EXPLORE:
                self.set_strategy(ScheduleStrategy.EXPLORE)
                self.phase = "explore"
                
        elif self.total_crashes > 0 and crash_gap < 120:
            # 최근 크래시 발견 → 착취 모드
            if self.strategy != ScheduleStrategy.EXPLOIT:
                self.set_strategy(ScheduleStrategy.EXPLOIT)
                self.phase = "exploit"
                
        else:
            # 기본 → FAST
            if self.strategy != ScheduleStrategy.FAST:
                self.set_strategy(ScheduleStrategy.FAST)
                self.phase = "fast"
        
        self.phase_start = now
    
    def update_on_result(self, entry_id: str, 
                         is_crash: bool = False,
                         is_interesting: bool = False,
                         new_coverage: bool = False):
        super().update_on_result(entry_id, is_crash, is_interesting, new_coverage)
        
        now = time.time()
        if is_crash:
            self.last_crash_time = now
        if is_interesting:
            self.last_interesting_time = now
        
        # 주기적으로 페이즈 업데이트
        self.update_phase()
