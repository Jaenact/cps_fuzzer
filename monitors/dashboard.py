"""
ipTIME Firmware Fuzzer v2.0 - Web Dashboard
실시간 퍼징 모니터링 대시보드

Flask + WebSocket으로 실시간 통계, 크래시 타임라인,
코퍼스 진화 등을 시각화.
"""

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from flask import Flask, jsonify, render_template_string, request
    from flask_socketio import SocketIO, emit

    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


# ============================================================
# 통계 데이터 모델
# ============================================================


@dataclass
class FuzzerStats:
    """퍼저 통계"""

    name: str
    total_cases: int = 0
    unique_crashes: int = 0
    total_crashes: int = 0
    interesting: int = 0
    timeouts: int = 0
    corpus_size: int = 0
    exec_per_sec: float = 0.0
    last_crash_time: Optional[float] = None
    last_interesting_time: Optional[float] = None


@dataclass
class GlobalStats:
    """전체 통계"""

    start_time: float = field(default_factory=time.time)
    total_cases: int = 0
    total_crashes: int = 0
    total_interesting: int = 0
    total_corpus: int = 0
    fuzzers: Dict[str, FuzzerStats] = field(default_factory=dict)

    # 타임라인 데이터
    crash_timeline: List[Dict[str, Any]] = field(default_factory=list)
    coverage_timeline: List[Dict[str, Any]] = field(default_factory=list)
    exec_timeline: List[Dict[str, Any]] = field(default_factory=list)


# ============================================================
# HTML 템플릿
# ============================================================

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>ipTIME Fuzzer Dashboard v2.0</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            min-height: 100vh;
        }
        .header {
            background: rgba(0,0,0,0.3);
            padding: 20px;
            text-align: center;
            border-bottom: 1px solid #333;
        }
        .header h1 {
            font-size: 2em;
            color: #00ff88;
            text-shadow: 0 0 10px #00ff8855;
        }
        .header .subtitle { color: #888; margin-top: 5px; }
        
        .container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            padding: 20px;
            max-width: 1600px;
            margin: 0 auto;
        }
        
        .card {
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
        }
        .card h2 {
            color: #00ff88;
            font-size: 1.2em;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card h2::before {
            content: '';
            width: 8px;
            height: 8px;
            background: #00ff88;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
        }
        .stat-item {
            text-align: center;
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #fff;
        }
        .stat-label {
            color: #888;
            font-size: 0.9em;
            margin-top: 5px;
        }
        .stat-value.crash { color: #ff6b6b; }
        .stat-value.interesting { color: #ffd93d; }
        .stat-value.speed { color: #6bcb77; }
        
        .fuzzer-list { list-style: none; }
        .fuzzer-item {
            padding: 12px;
            margin: 8px 0;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .fuzzer-name {
            font-weight: bold;
            color: #00ff88;
        }
        .fuzzer-stats { display: flex; gap: 20px; }
        .fuzzer-stat { text-align: center; }
        .fuzzer-stat span { display: block; }
        .fuzzer-stat .value { font-size: 1.2em; font-weight: bold; }
        .fuzzer-stat .label { font-size: 0.8em; color: #888; }
        
        .crash-list {
            max-height: 300px;
            overflow-y: auto;
        }
        .crash-item {
            padding: 10px;
            margin: 5px 0;
            background: rgba(255,0,0,0.1);
            border-left: 3px solid #ff6b6b;
            border-radius: 4px;
        }
        .crash-time { color: #888; font-size: 0.8em; }
        .crash-protocol { color: #ffd93d; }
        .crash-hash { font-family: monospace; color: #6bcb77; }
        
        .chart-container {
            height: 200px;
            position: relative;
        }
        
        .status-bar {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(0,0,0,0.8);
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.9em;
        }
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #00ff88;
            animation: pulse 1s infinite;
        }
        .status-dot.error { background: #ff6b6b; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 ipTIME Fuzzer Dashboard</h1>
        <div class="subtitle">Real-time Fuzzing Monitor v2.0</div>
    </div>
    
    <div class="container">
        <!-- Global Stats -->
        <div class="card">
            <h2>Global Statistics</h2>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-value" id="total-cases">0</div>
                    <div class="stat-label">Total Cases</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value speed" id="exec-rate">0</div>
                    <div class="stat-label">exec/sec</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value crash" id="total-crashes">0</div>
                    <div class="stat-label">Crashes</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value interesting" id="total-interesting">0</div>
                    <div class="stat-label">Interesting</div>
                </div>
            </div>
        </div>
        
        <!-- Fuzzer Status -->
        <div class="card">
            <h2>Fuzzer Status</h2>
            <ul class="fuzzer-list" id="fuzzer-list"></ul>
        </div>
        
        <!-- Execution Rate Chart -->
        <div class="card">
            <h2>Execution Rate</h2>
            <div class="chart-container">
                <canvas id="exec-chart"></canvas>
            </div>
        </div>
        
        <!-- Coverage Chart -->
        <div class="card">
            <h2>Coverage Progress</h2>
            <div class="chart-container">
                <canvas id="coverage-chart"></canvas>
            </div>
        </div>
        
        <!-- Recent Crashes -->
        <div class="card" style="grid-column: span 2;">
            <h2>Recent Crashes</h2>
            <div class="crash-list" id="crash-list"></div>
        </div>
    </div>
    
    <div class="status-bar">
        <div class="status-indicator">
            <div class="status-dot" id="connection-status"></div>
            <span id="status-text">Connected</span>
        </div>
        <div id="elapsed-time">Elapsed: 00:00:00</div>
        <div id="last-update">Last update: --</div>
    </div>
    
    <script>
        const socket = io();
        let execChart, coverageChart;
        let startTime = Date.now();
        
        // 차트 초기화
        function initCharts() {
            const execCtx = document.getElementById('exec-chart').getContext('2d');
            execChart = new Chart(execCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'exec/sec',
                        data: [],
                        borderColor: '#00ff88',
                        backgroundColor: 'rgba(0,255,136,0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, grid: { color: '#333' } },
                        x: { grid: { color: '#333' } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
            
            const covCtx = document.getElementById('coverage-chart').getContext('2d');
            coverageChart = new Chart(covCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Corpus Size',
                        data: [],
                        borderColor: '#ffd93d',
                        backgroundColor: 'rgba(255,217,61,0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, grid: { color: '#333' } },
                        x: { grid: { color: '#333' } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }
        
        // 통계 업데이트
        socket.on('stats_update', (data) => {
            document.getElementById('total-cases').textContent = 
                data.total_cases.toLocaleString();
            document.getElementById('total-crashes').textContent = 
                data.total_crashes;
            document.getElementById('total-interesting').textContent = 
                data.total_interesting;
            
            // exec/sec 계산
            const elapsed = (Date.now() - startTime) / 1000;
            const rate = (data.total_cases / elapsed).toFixed(1);
            document.getElementById('exec-rate').textContent = rate;
            
            // 퍼저 목록 업데이트
            const fuzzerList = document.getElementById('fuzzer-list');
            fuzzerList.innerHTML = '';
            for (const [name, stats] of Object.entries(data.fuzzers || {})) {
                const item = document.createElement('li');
                item.className = 'fuzzer-item';
                item.innerHTML = `
                    <span class="fuzzer-name">${name}</span>
                    <div class="fuzzer-stats">
                        <div class="fuzzer-stat">
                            <span class="value">${stats.total_cases.toLocaleString()}</span>
                            <span class="label">cases</span>
                        </div>
                        <div class="fuzzer-stat">
                            <span class="value" style="color:#ff6b6b">${stats.unique_crashes}</span>
                            <span class="label">crashes</span>
                        </div>
                        <div class="fuzzer-stat">
                            <span class="value" style="color:#6bcb77">${stats.exec_per_sec.toFixed(1)}</span>
                            <span class="label">exec/s</span>
                        </div>
                    </div>
                `;
                fuzzerList.appendChild(item);
            }
            
            // 차트 업데이트
            const now = new Date().toLocaleTimeString();
            execChart.data.labels.push(now);
            execChart.data.datasets[0].data.push(parseFloat(rate));
            if (execChart.data.labels.length > 60) {
                execChart.data.labels.shift();
                execChart.data.datasets[0].data.shift();
            }
            execChart.update('none');
            
            coverageChart.data.labels.push(now);
            coverageChart.data.datasets[0].data.push(data.total_corpus);
            if (coverageChart.data.labels.length > 60) {
                coverageChart.data.labels.shift();
                coverageChart.data.datasets[0].data.shift();
            }
            coverageChart.update('none');
            
            document.getElementById('last-update').textContent = 
                'Last update: ' + now;
        });
        
        // 크래시 알림
        socket.on('crash', (data) => {
            const crashList = document.getElementById('crash-list');
            const item = document.createElement('div');
            item.className = 'crash-item';
            item.innerHTML = `
                <div class="crash-time">${new Date().toLocaleTimeString()}</div>
                <span class="crash-protocol">[${data.protocol}]</span>
                <span class="crash-hash">${data.hash}</span>
                <div>${data.description || ''}</div>
            `;
            crashList.insertBefore(item, crashList.firstChild);
            
            // 최대 50개 유지
            while (crashList.children.length > 50) {
                crashList.removeChild(crashList.lastChild);
            }
        });
        
        // 연결 상태
        socket.on('connect', () => {
            document.getElementById('connection-status').classList.remove('error');
            document.getElementById('status-text').textContent = 'Connected';
        });
        
        socket.on('disconnect', () => {
            document.getElementById('connection-status').classList.add('error');
            document.getElementById('status-text').textContent = 'Disconnected';
        });
        
        // 경과 시간
        setInterval(() => {
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            const h = Math.floor(elapsed / 3600);
            const m = Math.floor((elapsed % 3600) / 60);
            const s = elapsed % 60;
            document.getElementById('elapsed-time').textContent = 
                `Elapsed: ${h.toString().padStart(2,'0')}:${m.toString().padStart(2,'0')}:${s.toString().padStart(2,'0')}`;
        }, 1000);
        
        // 초기화
        initCharts();
    </script>
</body>
</html>
"""


# ============================================================
# 대시보드 서버
# ============================================================


class WebDashboard:
    """
    실시간 웹 대시보드

    Flask + SocketIO 기반 실시간 모니터링.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8888):
        if not FLASK_AVAILABLE:
            raise ImportError("Flask and Flask-SocketIO required. Install with: pip install flask flask-socketio")

        self.host = host
        self.port = port
        self.stats = GlobalStats()

        # Flask 앱 설정
        self.app = Flask(__name__)
        self.app.config["SECRET_KEY"] = "fuzzer_dashboard_secret"
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")

        self._setup_routes()
        self._running = False
        self._thread = None

    def _setup_routes(self):
        """라우트 설정"""

        @self.app.route("/")
        def index():
            return render_template_string(DASHBOARD_TEMPLATE)

        @self.app.route("/api/stats")
        def api_stats():
            return jsonify(
                {
                    "total_cases": self.stats.total_cases,
                    "total_crashes": self.stats.total_crashes,
                    "total_interesting": self.stats.total_interesting,
                    "total_corpus": self.stats.total_corpus,
                    "elapsed": time.time() - self.stats.start_time,
                    "fuzzers": {name: asdict(stats) for name, stats in self.stats.fuzzers.items()},
                }
            )

        @self.app.route("/api/crashes")
        def api_crashes():
            return jsonify(self.stats.crash_timeline[-100:])

        @self.socketio.on("connect")
        def handle_connect():
            # 현재 상태 전송
            emit("stats_update", self._get_stats_dict())

    def _get_stats_dict(self) -> Dict[str, Any]:
        """통계 딕셔너리 반환"""
        return {
            "total_cases": self.stats.total_cases,
            "total_crashes": self.stats.total_crashes,
            "total_interesting": self.stats.total_interesting,
            "total_corpus": self.stats.total_corpus,
            "fuzzers": {name: asdict(stats) for name, stats in self.stats.fuzzers.items()},
        }

    def update_stats(
        self,
        fuzzer_name: str,
        total_cases: int = 0,
        unique_crashes: int = 0,
        interesting: int = 0,
        corpus_size: int = 0,
        exec_per_sec: float = 0.0,
    ):
        """퍼저 통계 업데이트"""
        if fuzzer_name not in self.stats.fuzzers:
            self.stats.fuzzers[fuzzer_name] = FuzzerStats(name=fuzzer_name)

        fs = self.stats.fuzzers[fuzzer_name]
        fs.total_cases = total_cases
        fs.unique_crashes = unique_crashes
        fs.interesting = interesting
        fs.corpus_size = corpus_size
        fs.exec_per_sec = exec_per_sec

        # 전체 통계 업데이트
        self.stats.total_cases = sum(f.total_cases for f in self.stats.fuzzers.values())
        self.stats.total_crashes = sum(f.unique_crashes for f in self.stats.fuzzers.values())
        self.stats.total_interesting = sum(f.interesting for f in self.stats.fuzzers.values())
        self.stats.total_corpus = sum(f.corpus_size for f in self.stats.fuzzers.values())

        # WebSocket으로 브로드캐스트
        if self._running:
            self.socketio.emit("stats_update", self._get_stats_dict())

    def report_crash(self, protocol: str, crash_hash: str, description: str = ""):
        """크래시 리포트"""
        crash_data = {
            "timestamp": time.time(),
            "protocol": protocol,
            "hash": crash_hash,
            "description": description,
        }

        self.stats.crash_timeline.append(crash_data)

        # WebSocket으로 알림
        if self._running:
            self.socketio.emit("crash", crash_data)

    def start(self, threaded: bool = True):
        """대시보드 시작"""
        self._running = True

        if threaded:
            self._thread = threading.Thread(
                target=lambda: self.socketio.run(
                    self.app, host=self.host, port=self.port, debug=False, use_reloader=False, log_output=False
                ),
                daemon=True,
            )
            self._thread.start()
            print(f"[*] Dashboard started at http://{self.host}:{self.port}")
        else:
            self.socketio.run(self.app, host=self.host, port=self.port, debug=False)

    def stop(self):
        """대시보드 중지"""
        self._running = False


# ============================================================
# 콘솔 대시보드 (Flask 없을 때 대체)
# ============================================================


class ConsoleDashboard:
    """콘솔 기반 대시보드 (Flask 없을 때)"""

    def __init__(self):
        self.stats = GlobalStats()
        self._running = False

    def update_stats(self, fuzzer_name: str, **kwargs):
        """통계 업데이트"""
        if fuzzer_name not in self.stats.fuzzers:
            self.stats.fuzzers[fuzzer_name] = FuzzerStats(name=fuzzer_name)

        fs = self.stats.fuzzers[fuzzer_name]
        for key, value in kwargs.items():
            if hasattr(fs, key):
                setattr(fs, key, value)

        self.stats.total_cases = sum(f.total_cases for f in self.stats.fuzzers.values())
        self.stats.total_crashes = sum(f.unique_crashes for f in self.stats.fuzzers.values())

    def report_crash(self, protocol: str, crash_hash: str, description: str = ""):
        """크래시 리포트"""
        print(f"\n[!] CRASH: [{protocol}] {crash_hash} - {description}")

    def print_stats(self):
        """통계 출력"""
        elapsed = time.time() - self.stats.start_time
        rate = self.stats.total_cases / elapsed if elapsed > 0 else 0

        print(
            f"\r[STATS] Cases: {self.stats.total_cases:,} | "
            f"Crashes: {self.stats.total_crashes} | "
            f"Rate: {rate:.1f}/s",
            end="",
            flush=True,
        )

    def start(self, threaded: bool = True):
        self._running = True

    def stop(self):
        self._running = False


# 팩토리 함수
def create_dashboard(web: bool = True, host: str = "127.0.0.1", port: int = 8888):
    """대시보드 생성"""
    if web and FLASK_AVAILABLE:
        return WebDashboard(host, port)
    else:
        return ConsoleDashboard()
