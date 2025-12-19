"""
ipTIME Firmware Fuzzer - Main Controller
모든 퍼저를 통합 관리하는 메인 컨트롤러
"""

import os
import sys
import yaml
import time
import signal
import threading
from pathlib import Path
from typing import Dict, List, Optional

# 프로젝트 루트를 path에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from fuzzers.base import BaseFuzzer
from fuzzers.udp_fuzzer import UDPFuzzer
from fuzzers.http_fuzzer import HTTPFuzzer
from fuzzers.upnp_fuzzer import UPnPFuzzer


class FuzzerController:
    """
    퍼저 메인 컨트롤러
    
    여러 프로토콜 퍼저를 동시에 실행하고 통합 관리.
    """
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.fuzzers: Dict[str, BaseFuzzer] = {}
        self.threads: List[threading.Thread] = []
        self.running = False
        self.start_time = None
        
        # 시그널 핸들러 설정
        signal.signal(signal.SIGINT, self._signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _load_config(self, config_path: str) -> dict:
        """설정 파일 로드"""
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        
        # 기본 설정
        return {
            'target': {
                'host': '192.168.0.1',
            },
            'fuzzers': {
                'udp': {
                    'enabled': True,
                    'port': 9999,
                    'timeout': 5.0,
                    'max_iterations': 10000,
                    'delay': 0.01,
                },
                'http': {
                    'enabled': True,
                    'port': 80,
                    'timeout': 10.0,
                    'max_iterations': 10000,
                    'delay': 0.05,
                },
                'upnp': {
                    'enabled': True,
                    'http_port': 5000,
                    'timeout': 5.0,
                    'max_iterations': 5000,
                    'delay': 0.02,
                },
            },
            'monitoring': {
                'crash_dir': './reports/crashes',
                'log_dir': './reports/logs',
            },
            'corpus': {
                'udp_seeds': './corpus/udp',
                'http_seeds': './corpus/http',
                'upnp_seeds': './corpus/upnp',
            },
        }
    
    def _signal_handler(self, signum, frame):
        """시그널 핸들러"""
        print("\n\n[!] Received interrupt signal. Stopping fuzzers...")
        self.stop()
    
    def setup_fuzzers(self):
        """퍼저 초기화"""
        target = self.config.get('target', {})
        target_host = target.get('host', '127.0.0.1')
        monitoring = self.config.get('monitoring', {})
        corpus = self.config.get('corpus', {})
        
        fuzzers_config = self.config.get('fuzzers', {})
        
        # UDP Fuzzer
        if fuzzers_config.get('udp', {}).get('enabled', False):
            udp_config = fuzzers_config['udp']
            self.fuzzers['udp'] = UDPFuzzer({
                'name': 'UDP',
                'target_host': target_host,
                'target_port': udp_config.get('port', 9999),
                'timeout': udp_config.get('timeout', 5.0),
                'max_iterations': udp_config.get('max_iterations', 10000),
                'delay': udp_config.get('delay', 0.01),
                'crash_dir': monitoring.get('crash_dir', './reports/crashes'),
                'log_dir': monitoring.get('log_dir', './reports/logs'),
            })
            
            # 코퍼스 로드
            corpus_dir = corpus.get('udp_seeds', './corpus/udp')
            if os.path.exists(corpus_dir):
                self.fuzzers['udp'].load_corpus(corpus_dir)
        
        # HTTP Fuzzer
        if fuzzers_config.get('http', {}).get('enabled', False):
            http_config = fuzzers_config['http']
            self.fuzzers['http'] = HTTPFuzzer({
                'name': 'HTTP',
                'target_host': target_host,
                'target_port': http_config.get('port', 80),
                'timeout': http_config.get('timeout', 10.0),
                'max_iterations': http_config.get('max_iterations', 10000),
                'delay': http_config.get('delay', 0.05),
                'crash_dir': monitoring.get('crash_dir', './reports/crashes'),
                'log_dir': monitoring.get('log_dir', './reports/logs'),
            })
            
            corpus_dir = corpus.get('http_seeds', './corpus/http')
            if os.path.exists(corpus_dir):
                self.fuzzers['http'].load_corpus(corpus_dir)
        
        # UPnP Fuzzer
        if fuzzers_config.get('upnp', {}).get('enabled', False):
            upnp_config = fuzzers_config['upnp']
            self.fuzzers['upnp'] = UPnPFuzzer({
                'name': 'UPnP',
                'target_host': target_host,
                'upnp_http_port': upnp_config.get('http_port', 5000),
                'timeout': upnp_config.get('timeout', 5.0),
                'max_iterations': upnp_config.get('max_iterations', 5000),
                'delay': upnp_config.get('delay', 0.02),
                'crash_dir': monitoring.get('crash_dir', './reports/crashes'),
                'log_dir': monitoring.get('log_dir', './reports/logs'),
            })
            
            corpus_dir = corpus.get('upnp_seeds', './corpus/upnp')
            if os.path.exists(corpus_dir):
                self.fuzzers['upnp'].load_corpus(corpus_dir)
    
    def _run_fuzzer(self, name: str, fuzzer: BaseFuzzer):
        """개별 퍼저 실행 (스레드)"""
        try:
            fuzzer.run()
        except Exception as e:
            print(f"\n[!] {name} fuzzer error: {e}")
    
    def start(self, parallel: bool = True):
        """
        퍼징 시작
        
        Args:
            parallel: True이면 멀티스레드로 동시 실행
        """
        self.setup_fuzzers()
        self.running = True
        self.start_time = time.time()
        
        self._print_banner()
        
        if not self.fuzzers:
            print("[!] No fuzzers enabled. Check configuration.")
            return
        
        print(f"[*] Starting fuzzing campaign with {len(self.fuzzers)} fuzzer(s)")
        print(f"[*] Target: {self.config['target']['host']}")
        print()
        
        if parallel:
            # 멀티스레드 실행
            for name, fuzzer in self.fuzzers.items():
                thread = threading.Thread(
                    target=self._run_fuzzer,
                    args=(name, fuzzer),
                    name=f"Fuzzer-{name}"
                )
                thread.daemon = True
                thread.start()
                self.threads.append(thread)
            
            # 메인 스레드에서 통계 모니터링
            try:
                while self.running:
                    time.sleep(5)
                    self._print_global_stats()
                    
                    # 모든 스레드가 종료되었는지 확인
                    if all(not t.is_alive() for t in self.threads):
                        break
                        
            except KeyboardInterrupt:
                pass
        else:
            # 순차 실행
            for name, fuzzer in self.fuzzers.items():
                if not self.running:
                    break
                fuzzer.run()
        
        self.stop()
        self._print_final_report()
    
    def stop(self):
        """모든 퍼저 중지"""
        self.running = False
        for fuzzer in self.fuzzers.values():
            fuzzer.stop()
    
    def _print_banner(self):
        """배너 출력"""
        banner = """
===============================================================
                                                               
   _______  _______  _______  _______  _______                 
  |       ||       ||       ||       ||       |                
  |_     _||    _  ||_     _||_     _||    _  |                
    |   |  |   |_| |  |   |    |   |  |   |_| |                
    |   |  |    ___|  |   |    |   |  |    ___|                
    |___|  |___|      |___|    |___|  |___|                    
                                                               
                 Firmware Fuzzer Framework v1.0                
                                                               
===============================================================
"""
        print(banner)
    
    def _print_global_stats(self):
        """전체 통계 출력"""
        elapsed = time.time() - self.start_time
        
        print("\n" + "=" * 65)
        print(f" FUZZING STATISTICS (Elapsed: {elapsed:.0f}s)")
        print("=" * 65)
        
        total_cases = 0
        total_crashes = 0
        total_interesting = 0
        
        for name, fuzzer in self.fuzzers.items():
            stats = fuzzer.stats
            total_cases += stats['total_cases']
            total_crashes += stats['unique_crashes']
            total_interesting += stats['interesting']
            
            rate = stats['total_cases'] / elapsed if elapsed > 0 else 0
            
            print(f"\n [{name.upper()}]")
            print(f"   Cases: {stats['total_cases']:,}  |  "
                  f"Crashes: {stats['unique_crashes']}  |  "
                  f"Interesting: {stats['interesting']}  |  "
                  f"Rate: {rate:.1f}/s")
        
        print("\n" + "-" * 65)
        total_rate = total_cases / elapsed if elapsed > 0 else 0
        print(f" TOTAL: {total_cases:,} cases  |  "
              f"{total_crashes} crashes  |  "
              f"{total_interesting} interesting  |  "
              f"{total_rate:.1f}/s")
        print("=" * 65)
    
    def _print_final_report(self):
        """최종 리포트 출력"""
        elapsed = time.time() - self.start_time
        
        print("\n")
        print("╔" + "═" * 63 + "╗")
        print("║" + " FINAL FUZZING REPORT".center(63) + "║")
        print("╠" + "═" * 63 + "╣")
        
        total_cases = 0
        total_crashes = 0
        
        for name, fuzzer in self.fuzzers.items():
            stats = fuzzer.stats
            total_cases += stats['total_cases']
            total_crashes += stats['unique_crashes']
            
            print(f"║ {name.upper():8} │ Cases: {stats['total_cases']:>8,} │ "
                  f"Crashes: {stats['unique_crashes']:>3} │ "
                  f"Interesting: {stats['interesting']:>3} ║")
        
        print("╠" + "═" * 63 + "╣")
        print(f"║ {'TOTAL':8} │ Cases: {total_cases:>8,} │ "
              f"Crashes: {total_crashes:>3} │ "
              f"Time: {elapsed:>6.0f}s     ║")
        print("╚" + "═" * 63 + "╝")
        
        if total_crashes > 0:
            print(f"\n[!] Crash reports saved to: {self.config['monitoring']['crash_dir']}")


def main():
    """메인 함수"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ipTIME Firmware Fuzzer')
    parser.add_argument('-c', '--config', type=str, help='Config file path')
    parser.add_argument('-t', '--target', type=str, help='Target host')
    parser.add_argument('--udp-only', action='store_true', help='Run UDP fuzzer only')
    parser.add_argument('--http-only', action='store_true', help='Run HTTP fuzzer only')
    parser.add_argument('--upnp-only', action='store_true', help='Run UPnP fuzzer only')
    parser.add_argument('-n', '--iterations', type=int, default=10000,
                        help='Max iterations per fuzzer')
    parser.add_argument('--sequential', action='store_true',
                        help='Run fuzzers sequentially instead of parallel')
    
    args = parser.parse_args()
    
    # 컨트롤러 생성
    controller = FuzzerController(args.config)
    
    # 커맨드라인 인자로 설정 오버라이드
    if args.target:
        controller.config['target']['host'] = args.target
    
    if args.iterations:
        for fuzzer_config in controller.config['fuzzers'].values():
            fuzzer_config['max_iterations'] = args.iterations
    
    if args.udp_only:
        controller.config['fuzzers']['http']['enabled'] = False
        controller.config['fuzzers']['upnp']['enabled'] = False
    elif args.http_only:
        controller.config['fuzzers']['udp']['enabled'] = False
        controller.config['fuzzers']['upnp']['enabled'] = False
    elif args.upnp_only:
        controller.config['fuzzers']['udp']['enabled'] = False
        controller.config['fuzzers']['http']['enabled'] = False
    
    # 퍼징 시작
    controller.start(parallel=not args.sequential)


if __name__ == '__main__':
    main()
