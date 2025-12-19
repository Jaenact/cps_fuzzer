"""
ipTIME Firmware Fuzzer v2.0 - Distributed Fuzzing
Redis 기반 분산 퍼징 코디네이션

여러 퍼징 노드를 동기화하여 코퍼스 공유,
크래시 수집, 작업 분배 등을 수행.
"""

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


@dataclass
class NodeInfo:
    """퍼징 노드 정보"""

    node_id: str
    hostname: str
    start_time: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)

    # 상태
    status: str = "idle"  # idle, running, paused, stopped
    current_protocol: str = ""

    # 통계
    total_cases: int = 0
    unique_crashes: int = 0
    interesting: int = 0
    corpus_size: int = 0
    exec_per_sec: float = 0.0


@dataclass
class SharedCrash:
    """공유 크래시 정보"""

    crash_id: str
    protocol: str
    payload_hash: str
    payload_b64: str  # Base64 인코딩된 페이로드
    crash_type: str
    severity: str
    description: str
    discovered_by: str
    timestamp: float = field(default_factory=time.time)


class RedisCoordinator:
    """
    Redis 기반 분산 코디네이터

    여러 퍼징 노드 간 동기화:
    - 코퍼스 공유
    - 크래시 공유
    - 태스크 분배
    - 통계 집계
    """

    # Redis 키 접두사
    KEY_NODES = "fuzzer:nodes"
    KEY_CORPUS = "fuzzer:corpus"
    KEY_CRASHES = "fuzzer:crashes"
    KEY_STATS = "fuzzer:stats"
    KEY_TASKS = "fuzzer:tasks"
    KEY_CONFIG = "fuzzer:config"

    def __init__(self, redis_url: str = "redis://localhost:6379", node_id: str = None, namespace: str = "iptime"):
        """
        Args:
            redis_url: Redis 연결 URL
            node_id: 노드 식별자 (None이면 자동 생성)
            namespace: 키 네임스페이스
        """
        if not REDIS_AVAILABLE:
            raise ImportError("Redis required. Install with: pip install redis")

        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.redis_binary = redis.from_url(redis_url, decode_responses=False)

        self.namespace = namespace
        self.node_id = node_id or self._generate_node_id()

        import socket

        self.node_info = NodeInfo(node_id=self.node_id, hostname=socket.gethostname())

        # 이벤트 콜백
        self._callbacks: Dict[str, List[Callable]] = {
            "new_corpus": [],
            "new_crash": [],
            "config_update": [],
        }

        # Heartbeat 스레드
        self._running = False
        self._heartbeat_thread = None
        self._sync_thread = None

    def _generate_node_id(self) -> str:
        """노드 ID 생성"""
        import socket

        hostname = socket.gethostname()
        return f"{hostname}_{int(time.time() * 1000) % 100000}"

    def _key(self, suffix: str) -> str:
        """네임스페이스 적용 키"""
        return f"{self.namespace}:{suffix}"

    # ========== 노드 관리 ==========

    def register_node(self):
        """노드 등록"""
        self.node_info.status = "running"
        self.node_info.last_heartbeat = time.time()

        self.redis.hset(self._key(self.KEY_NODES), self.node_id, json.dumps(asdict(self.node_info)))

    def unregister_node(self):
        """노드 등록 해제"""
        self.redis.hdel(self._key(self.KEY_NODES), self.node_id)

    def update_heartbeat(self):
        """Heartbeat 업데이트"""
        self.node_info.last_heartbeat = time.time()
        self.redis.hset(self._key(self.KEY_NODES), self.node_id, json.dumps(asdict(self.node_info)))

    def get_active_nodes(self, timeout: float = 30.0) -> List[NodeInfo]:
        """활성 노드 목록"""
        nodes = []
        now = time.time()

        all_nodes = self.redis.hgetall(self._key(self.KEY_NODES))
        for node_id, node_json in all_nodes.items():
            try:
                data = json.loads(node_json)
                if now - data.get("last_heartbeat", 0) < timeout:
                    nodes.append(NodeInfo(**data))
            except:
                pass

        return nodes

    def update_stats(self, **stats):
        """노드 통계 업데이트"""
        for key, value in stats.items():
            if hasattr(self.node_info, key):
                setattr(self.node_info, key, value)

        self.update_heartbeat()

    # ========== 코퍼스 동기화 ==========

    def share_corpus(self, data: bytes, protocol: str = "", metadata: Dict[str, Any] = None) -> str:
        """코퍼스 공유"""
        corpus_hash = hashlib.sha256(data).hexdigest()[:16]

        import base64

        entry = {
            "hash": corpus_hash,
            "data_b64": base64.b64encode(data).decode(),
            "protocol": protocol,
            "size": len(data),
            "shared_by": self.node_id,
            "timestamp": time.time(),
            "metadata": metadata or {},
        }

        # 중복 확인
        if not self.redis.hexists(self._key(self.KEY_CORPUS), corpus_hash):
            self.redis.hset(self._key(self.KEY_CORPUS), corpus_hash, json.dumps(entry))

            # 새 코퍼스 알림 발행
            self.redis.publish(self._key("events:corpus"), json.dumps({"hash": corpus_hash, "protocol": protocol}))

        return corpus_hash

    def get_corpus(self, protocol: str = None, limit: int = None) -> List[bytes]:
        """공유된 코퍼스 가져오기"""
        import base64

        corpus = []
        all_entries = self.redis.hgetall(self._key(self.KEY_CORPUS))

        for entry_json in all_entries.values():
            try:
                entry = json.loads(entry_json)
                if protocol and entry.get("protocol") != protocol:
                    continue

                data = base64.b64decode(entry["data_b64"])
                corpus.append(data)

                if limit and len(corpus) >= limit:
                    break
            except:
                pass

        return corpus

    def sync_corpus(self, local_corpus: List[bytes], protocol: str = "") -> List[bytes]:
        """
        로컬 코퍼스와 동기화

        Returns:
            새로 추가된 코퍼스 항목
        """
        import base64

        # 로컬 해시 계산
        local_hashes = {hashlib.sha256(d).hexdigest()[:16] for d in local_corpus}

        # 원격 코퍼스 확인
        remote_entries = self.redis.hgetall(self._key(self.KEY_CORPUS))
        new_items = []

        for entry_json in remote_entries.values():
            try:
                entry = json.loads(entry_json)
                if protocol and entry.get("protocol") != protocol:
                    continue

                if entry["hash"] not in local_hashes:
                    data = base64.b64decode(entry["data_b64"])
                    new_items.append(data)
            except:
                pass

        # 로컬 코퍼스 공유
        for data in local_corpus:
            self.share_corpus(data, protocol)

        return new_items

    # ========== 크래시 공유 ==========

    def share_crash(
        self, payload: bytes, protocol: str, crash_type: str = "", severity: str = "unknown", description: str = ""
    ) -> str:
        """크래시 공유"""
        import base64

        payload_hash = hashlib.sha256(payload).hexdigest()[:16]
        crash_id = f"{protocol}_{payload_hash}_{int(time.time())}"

        crash = SharedCrash(
            crash_id=crash_id,
            protocol=protocol,
            payload_hash=payload_hash,
            payload_b64=base64.b64encode(payload).decode(),
            crash_type=crash_type,
            severity=severity,
            description=description,
            discovered_by=self.node_id,
        )

        self.redis.hset(self._key(self.KEY_CRASHES), crash_id, json.dumps(asdict(crash)))

        # 크래시 알림 발행
        self.redis.publish(
            self._key("events:crash"), json.dumps({"crash_id": crash_id, "protocol": protocol, "severity": severity})
        )

        return crash_id

    def get_crashes(self, protocol: str = None, limit: int = 100) -> List[SharedCrash]:
        """공유된 크래시 가져오기"""
        crashes = []
        all_crashes = self.redis.hgetall(self._key(self.KEY_CRASHES))

        for crash_json in all_crashes.values():
            try:
                crash_data = json.loads(crash_json)
                if protocol and crash_data.get("protocol") != protocol:
                    continue

                crashes.append(SharedCrash(**crash_data))

                if len(crashes) >= limit:
                    break
            except:
                pass

        # 시간순 정렬
        crashes.sort(key=lambda c: c.timestamp, reverse=True)
        return crashes

    # ========== 태스크 분배 ==========

    def push_task(self, task_type: str, task_data: Dict[str, Any]) -> str:
        """태스크 추가"""
        task_id = f"{task_type}_{int(time.time() * 1000)}"
        task = {
            "id": task_id,
            "type": task_type,
            "data": task_data,
            "status": "pending",
            "created_at": time.time(),
            "assigned_to": None,
        }

        self.redis.lpush(self._key(self.KEY_TASKS), json.dumps(task))

        return task_id

    def pop_task(self, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """태스크 가져오기 (블로킹)"""
        result = self.redis.brpop(self._key(self.KEY_TASKS), timeout=timeout)
        if result:
            return json.loads(result[1])
        return None

    # ========== 이벤트 처리 ==========

    def on(self, event: str, callback: Callable):
        """이벤트 콜백 등록"""
        if event in self._callbacks:
            self._callbacks[event].append(callback)

    def _event_loop(self):
        """이벤트 처리 루프"""
        pubsub = self.redis.pubsub()
        pubsub.subscribe(self._key("events:corpus"), self._key("events:crash"), self._key("events:config"))

        for message in pubsub.listen():
            if not self._running:
                break

            if message["type"] == "message":
                channel = message["channel"]
                data = json.loads(message["data"])

                if "corpus" in channel:
                    for cb in self._callbacks["new_corpus"]:
                        cb(data)
                elif "crash" in channel:
                    for cb in self._callbacks["new_crash"]:
                        cb(data)
                elif "config" in channel:
                    for cb in self._callbacks["config_update"]:
                        cb(data)

    def _heartbeat_loop(self):
        """Heartbeat 루프"""
        while self._running:
            try:
                self.update_heartbeat()
            except:
                pass
            time.sleep(5)

    # ========== 전체 통계 ==========

    def get_global_stats(self) -> Dict[str, Any]:
        """전체 클러스터 통계"""
        nodes = self.get_active_nodes()

        total_cases = sum(n.total_cases for n in nodes)
        total_crashes = sum(n.unique_crashes for n in nodes)
        total_interesting = sum(n.interesting for n in nodes)
        total_rate = sum(n.exec_per_sec for n in nodes)

        corpus_size = self.redis.hlen(self._key(self.KEY_CORPUS))
        crash_count = self.redis.hlen(self._key(self.KEY_CRASHES))

        return {
            "active_nodes": len(nodes),
            "total_cases": total_cases,
            "total_crashes": total_crashes,
            "total_interesting": total_interesting,
            "total_exec_rate": total_rate,
            "shared_corpus_size": corpus_size,
            "shared_crash_count": crash_count,
            "nodes": [asdict(n) for n in nodes],
        }

    # ========== 생명주기 ==========

    def start(self):
        """코디네이터 시작"""
        self._running = True
        self.register_node()

        # Heartbeat 스레드
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        # 이벤트 루프 스레드
        self._sync_thread = threading.Thread(target=self._event_loop, daemon=True)
        self._sync_thread.start()

    def stop(self):
        """코디네이터 중지"""
        self._running = False
        self.unregister_node()


class LocalCoordinator:
    """로컬 (비분산) 코디네이터 (Redis 없을 때)"""

    def __init__(self, node_id: str = "local"):
        self.node_id = node_id
        self.corpus: Dict[str, bytes] = {}
        self.crashes: List[SharedCrash] = []
        self._running = False

    def share_corpus(self, data: bytes, protocol: str = "", **kwargs) -> str:
        corpus_hash = hashlib.sha256(data).hexdigest()[:16]
        self.corpus[corpus_hash] = data
        return corpus_hash

    def get_corpus(self, protocol: str = None, limit: int = None) -> List[bytes]:
        corpus = list(self.corpus.values())
        return corpus[:limit] if limit else corpus

    def sync_corpus(self, local_corpus: List[bytes], protocol: str = "") -> List[bytes]:
        for data in local_corpus:
            self.share_corpus(data, protocol)
        return []

    def share_crash(self, payload: bytes, protocol: str, **kwargs) -> str:
        import base64

        payload_hash = hashlib.sha256(payload).hexdigest()[:16]
        crash = SharedCrash(
            crash_id=f"{protocol}_{payload_hash}",
            protocol=protocol,
            payload_hash=payload_hash,
            payload_b64=base64.b64encode(payload).decode(),
            crash_type=kwargs.get("crash_type", ""),
            severity=kwargs.get("severity", "unknown"),
            description=kwargs.get("description", ""),
            discovered_by=self.node_id,
        )
        self.crashes.append(crash)
        return crash.crash_id

    def get_crashes(self, **kwargs) -> List[SharedCrash]:
        return self.crashes

    def get_global_stats(self) -> Dict[str, Any]:
        return {"active_nodes": 1, "shared_corpus_size": len(self.corpus), "shared_crash_count": len(self.crashes)}

    def update_stats(self, **kwargs):
        pass

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def on(self, event: str, callback: Callable):
        pass


# 팩토리 함수
def create_coordinator(redis_url: str = None, node_id: str = None, namespace: str = "iptime"):
    """코디네이터 생성"""
    if redis_url and REDIS_AVAILABLE:
        try:
            coord = RedisCoordinator(redis_url, node_id, namespace)
            # 연결 테스트
            coord.redis.ping()
            return coord
        except:
            pass

    return LocalCoordinator(node_id or "local")
