"""
ipTIME Firmware Fuzzer v2.0 - Core Module
핵심 모듈 (컨트롤러, 스케줄러, 분산)
"""

from .controller import FuzzerController, main

try:
    from .scheduler import (
        ScheduleStrategy,
        CorpusEntry,
        EnergyScheduler,
        AdaptiveScheduler,
    )
except ImportError:
    pass

try:
    from .distributed import (
        NodeInfo,
        SharedCrash,
        RedisCoordinator,
        LocalCoordinator,
        create_coordinator,
    )
except ImportError:
    pass

__all__ = [
    'FuzzerController',
    'main',
    # Scheduler
    'ScheduleStrategy',
    'CorpusEntry',
    'EnergyScheduler',
    'AdaptiveScheduler',
    # Distributed
    'NodeInfo',
    'SharedCrash',
    'RedisCoordinator',
    'LocalCoordinator',
    'create_coordinator',
]
