"""
ipTIME Firmware Fuzzer v2.0 - QEMU System Harness
QEMU 시스템 모드 기반 펌웨어 에뮬레이션 하네스

ipTIME 펌웨어를 QEMU로 에뮬레이션하여
네트워크로 퍼징 입력을 전송하고 크래시를 감지.
"""

import os
import time
import socket
import subprocess
import threading
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass, field


@dataclass
class QEMUConfig:
    """QEMU 설정"""
    # 바이너리 경로
    qemu_system: str = "qemu-system-mipsel"
    kernel: str = ""           # -kernel
    rootfs: str = ""           # -hda 또는 -drive
    dtb: str = ""              # -dtb
    
    # 하드웨어
    machine: str = "malta"     # -M
    cpu: str = "24Kf"          # -cpu
    memory: str = "256M"       # -m
    
    # 네트워크
    network_mode: str = "user"  # user, tap, bridge
    host_fwd_ports: Dict[int, int] = field(default_factory=dict)  # guest:host
    
    # 기타
    snapshot: bool = True       # -snapshot
    nographic: bool = True      # -nographic
    monitor_socket: str = ""    # QEMU monitor 소켓
    serial_socket: str = ""     # 시리얼 콘솔 소켓
    extra_args: List[str] = field(default_factory=list)


class QEMUSystemHarness:
    """
    QEMU 시스템 모드 하네스
    
    ipTIME 펌웨어를 QEMU에서 실행하고,
    네트워크를 통해 퍼징 입력을 전송.
    """
    
    def __init__(self, config: QEMUConfig = None):
        self.config = config or QEMUConfig()
        
        # 상태
        self.process: Optional[subprocess.Popen] = None
        self.running = False
        self.boot_complete = False
        
        # 임시 파일
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="qemu_harness_"))
        self.monitor_path = str(self.tmp_dir / "monitor.sock")
        self.serial_path = str(self.tmp_dir / "serial.sock")
        
        # 로그
        self.stdout_log = []
        self.stderr_log = []
        
        # 스레드
        self._log_thread = None
        
        # 네트워크
        self.ssh_port = 2222     # 기본 SSH 포워딩 포트
        self.web_port = 8080     # 기본 HTTP 포워딩 포트
        self.udp_port = 9999     # 기본 UDP 포워딩 포트
        
    def _build_command(self) -> List[str]:
        """QEMU 명령어 구성"""
        cmd = [self.config.qemu_system]
        
        # 머신
        if self.config.machine:
            cmd.extend(['-M', self.config.machine])
        if self.config.cpu:
            cmd.extend(['-cpu', self.config.cpu])
        if self.config.memory:
            cmd.extend(['-m', self.config.memory])
        
        # 커널/디스크
        if self.config.kernel:
            cmd.extend(['-kernel', self.config.kernel])
        if self.config.rootfs:
            cmd.extend(['-hda', self.config.rootfs])
        if self.config.dtb:
            cmd.extend(['-dtb', self.config.dtb])
        
        # 네트워크
        if self.config.network_mode == "user":
            # 유저 모드 네트워크 + 포트 포워딩
            net_opts = "user,id=net0"
            
            # 포트 포워딩
            for guest_port, host_port in self.config.host_fwd_ports.items():
                net_opts += f",hostfwd=tcp::{host_port}-:{guest_port}"
            
            # 기본 포워딩
            net_opts += f",hostfwd=tcp::{self.web_port}-:80"
            net_opts += f",hostfwd=tcp::{self.ssh_port}-:22"
            net_opts += f",hostfwd=udp::{self.udp_port}-:9999"
            
            cmd.extend(['-netdev', net_opts])
            cmd.extend(['-device', 'e1000,netdev=net0'])
        
        # 스냅샷
        if self.config.snapshot:
            cmd.append('-snapshot')
        
        # nographic
        if self.config.nographic:
            cmd.append('-nographic')
        
        # Monitor 소켓
        cmd.extend(['-monitor', f'unix:{self.monitor_path},server,nowait'])
        
        # Serial 소켓
        cmd.extend(['-serial', f'unix:{self.serial_path},server,nowait'])
        
        # 추가 인자
        cmd.extend(self.config.extra_args)
        
        return cmd
    
    def start(self, wait_for_boot: bool = True, timeout: float = 60.0) -> bool:
        """
        QEMU 시작
        
        Args:
            wait_for_boot: 부팅 완료까지 대기
            timeout: 부팅 타임아웃 (초)
            
        Returns:
            성공 여부
        """
        if self.running:
            return True
        
        cmd = self._build_command()
        print(f"[*] Starting QEMU: {' '.join(cmd)}")
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
            self.running = True
            
            # 로그 스레드 시작
            self._start_log_thread()
            
            if wait_for_boot:
                return self._wait_for_boot(timeout)
            
            return True
            
        except Exception as e:
            print(f"[!] QEMU start failed: {e}")
            return False
    
    def _start_log_thread(self):
        """로그 수집 스레드"""
        def collect_logs():
            while self.running and self.process:
                try:
                    line = self.process.stdout.readline()
                    if line:
                        self.stdout_log.append(line.decode('utf-8', errors='replace'))
                except:
                    break
        
        self._log_thread = threading.Thread(target=collect_logs, daemon=True)
        self._log_thread.start()
    
    def _wait_for_boot(self, timeout: float) -> bool:
        """부팅 완료 대기"""
        print(f"[*] Waiting for QEMU boot (timeout: {timeout}s)...")
        
        start = time.time()
        
        # 부팅 완료 표시자
        boot_indicators = [
            b'login:',
            b'Welcome',
            b'#',
            b'$',
        ]
        
        while time.time() - start < timeout:
            if not self.running or not self.process:
                return False
            
            # 로그에서 부팅 완료 확인
            for log in self.stdout_log[-10:]:
                if any(ind.decode() in log for ind in boot_indicators):
                    print(f"[*] Boot complete after {time.time() - start:.1f}s")
                    self.boot_complete = True
                    return True
            
            # 포트 응답 확인
            if self._check_port_alive(self.web_port, timeout=1.0):
                print(f"[*] HTTP port responding after {time.time() - start:.1f}s")
                self.boot_complete = True
                return True
            
            time.sleep(1)
        
        print("[!] Boot timeout")
        return False
    
    def _check_port_alive(self, port: int, timeout: float = 1.0) -> bool:
        """포트 응답 확인"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except:
            return False
    
    def stop(self):
        """QEMU 중지"""
        if not self.running:
            return
        
        self.running = False
        
        # QEMU 모니터로 종료 명령
        try:
            self.send_monitor_command("quit")
        except:
            pass
        
        # 프로세스 종료
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except:
                self.process.kill()
            
            self.process = None
        
        self.boot_complete = False
    
    def send_monitor_command(self, command: str) -> str:
        """QEMU 모니터 명령어 전송"""
        if not os.path.exists(self.monitor_path):
            return ""
        
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(self.monitor_path)
            
            # 프롬프트 읽기
            sock.recv(1024)
            
            # 명령어 전송
            sock.sendall(f"{command}\n".encode())
            
            # 응답 읽기
            response = sock.recv(4096)
            sock.close()
            
            return response.decode('utf-8', errors='replace')
        except:
            return ""
    
    def savevm(self, name: str = "fuzz_snapshot") -> bool:
        """VM 스냅샷 저장"""
        response = self.send_monitor_command(f"savevm {name}")
        return "Error" not in response
    
    def loadvm(self, name: str = "fuzz_snapshot") -> bool:
        """VM 스냅샷 로드"""
        response = self.send_monitor_command(f"loadvm {name}")
        return "Error" not in response
    
    def reset(self):
        """VM 리셋"""
        self.send_monitor_command("system_reset")
        time.sleep(2)  # 리셋 대기
    
    def is_alive(self) -> bool:
        """VM 상태 확인"""
        if not self.running or not self.process:
            return False
        
        return self.process.poll() is None
    
    def send_to_guest(self, 
                      protocol: str,
                      data: bytes,
                      timeout: float = 5.0) -> Tuple[Optional[bytes], str]:
        """
        게스트 VM으로 데이터 전송
        
        Args:
            protocol: 'tcp', 'udp', 'http'
            data: 전송할 데이터
            timeout: 타임아웃
            
        Returns:
            (응답, 에러메시지)
        """
        if not self.boot_complete:
            return None, "VM not booted"
        
        try:
            if protocol in ('tcp', 'http'):
                return self._send_tcp(data, self.web_port, timeout)
            elif protocol == 'udp':
                return self._send_udp(data, self.udp_port, timeout)
            else:
                return None, f"Unknown protocol: {protocol}"
        except Exception as e:
            return None, str(e)
    
    def _send_tcp(self, data: bytes, port: int, timeout: float) -> Tuple[bytes, str]:
        """TCP 전송"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            sock.connect(('127.0.0.1', port))
            sock.sendall(data)
            
            response = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            
            return response, ""
        except socket.timeout:
            return None, "timeout"
        except Exception as e:
            return None, str(e)
        finally:
            sock.close()
    
    def _send_udp(self, data: bytes, port: int, timeout: float) -> Tuple[bytes, str]:
        """UDP 전송"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        try:
            sock.sendto(data, ('127.0.0.1', port))
            response, addr = sock.recvfrom(4096)
            return response, ""
        except socket.timeout:
            return None, "timeout"
        except Exception as e:
            return None, str(e)
        finally:
            sock.close()
    
    def fuzz_one(self, 
                 protocol: str,
                 data: bytes,
                 check_alive: bool = True) -> Dict[str, Any]:
        """
        단일 퍼징 실행
        
        Args:
            protocol: 프로토콜
            data: 퍼징 데이터
            check_alive: 크래시 후 VM 상태 확인
            
        Returns:
            {'response': bytes, 'error': str, 'crashed': bool, 'timing': float}
        """
        start = time.time()
        response, error = self.send_to_guest(protocol, data)
        timing = time.time() - start
        
        crashed = False
        
        if check_alive and error:
            # 크래시 확인
            if not self._check_port_alive(self.web_port, timeout=2.0):
                crashed = True
        
        return {
            'response': response,
            'error': error,
            'crashed': crashed,
            'timing': timing
        }
    
    def cleanup(self):
        """정리"""
        self.stop()
        
        try:
            shutil.rmtree(self.tmp_dir)
        except:
            pass


class FirmwareExtractor:
    """펌웨어 추출 유틸리티"""
    
    def __init__(self, firmware_path: str, output_dir: str = None):
        self.firmware_path = Path(firmware_path)
        self.output_dir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp())
    
    def extract(self) -> Optional[Path]:
        """
        펌웨어 추출
        
        binwalk를 사용하여 펌웨어에서 파일시스템 추출.
        
        Returns:
            추출된 루트 경로
        """
        try:
            result = subprocess.run(
                ['binwalk', '-e', '-C', str(self.output_dir), str(self.firmware_path)],
                capture_output=True,
                timeout=120
            )
            
            # 추출된 디렉토리 찾기
            for item in self.output_dir.iterdir():
                if item.is_dir() and item.name.startswith('_'):
                    # squashfs-root 찾기
                    for subitem in item.rglob('squashfs-root'):
                        if subitem.is_dir():
                            return subitem
                    return item
            
            return None
        except Exception as e:
            print(f"[!] Extraction failed: {e}")
            return None
    
    def find_binaries(self, rootfs: Path) -> Dict[str, Path]:
        """주요 바이너리 찾기"""
        binaries = {}
        
        targets = [
            'bin/UDPserver',
            'sbin/httpd',
            'bin/upnpd',
            'bin/pptpd',
        ]
        
        for target in targets:
            path = rootfs / target
            if path.exists():
                binaries[target] = path
        
        return binaries


# 팩토리 함수
def create_harness(qemu_path: str = None,
                   kernel: str = None,
                   rootfs: str = None,
                   **kwargs) -> QEMUSystemHarness:
    """QEMU 하네스 생성"""
    config = QEMUConfig(
        qemu_system=qemu_path or "qemu-system-mipsel",
        kernel=kernel or "",
        rootfs=rootfs or "",
        **kwargs
    )
    
    return QEMUSystemHarness(config)
