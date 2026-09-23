"""事件总线：内存环形缓冲 + JSONL 落盘 + 订阅回调。

仪表盘要"实时事件流"，所以需要一个能被多个消费者同时读的东西；
同时每一次判定都必须留痕，所以还要落盘。
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable

from .config import DATA_DIR

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Event:
    ts: float
    kind: str                 # finding / action / state / error / notice
    severity: str = "info"
    code: str = ""
    title: str = ""
    detail: str = ""
    pid: int = 0
    process: str = ""
    exe: str = ""
    local: str = ""
    remote: str = ""
    proto: str = ""
    reason: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))
        return d


class LogBus:
    """事件总线。线程安全。"""

    def __init__(self, capacity: int = 4000, path: Path | None = None,
                 max_bytes: int = 32 * 1024 * 1024):
        self._lock = threading.RLock()
        self._buf: deque[Event] = deque(maxlen=capacity)
        self._subs: list[Callable[[Event], None]] = []
        self._seq = 0
        self.path = Path(path) if path else (DATA_DIR / "events.jsonl")
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = None

    # ---- 写入 ---------------------------------------------------------

    def emit(self, kind: str, **kw) -> Event:
        ev = Event(ts=time.time(), kind=kind, **kw)
        with self._lock:
            self._seq += 1
            ev.extra.setdefault("seq", self._seq)
            self._buf.append(ev)
            subs = list(self._subs)
        self._append_file(ev)
        for cb in subs:
            try:
                cb(ev)
            except Exception:
                pass
        return ev

    def finding(self, **kw) -> Event:
        return self.emit("finding", **kw)

    def action(self, **kw) -> Event:
        return self.emit("action", **kw)

    def state(self, **kw) -> Event:
        return self.emit("state", **kw)

    def error(self, **kw) -> Event:
        return self.emit("error", **kw)

    def notice(self, **kw) -> Event:
        return self.emit("notice", **kw)

    # ---- 落盘 ---------------------------------------------------------

    def _append_file(self, ev: Event) -> None:
        try:
            if self._fh is None:
                self._rotate_if_needed()
                self._fh = self.path.open("a", encoding="utf-8")
            self._fh.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
            self._fh.flush()
        except Exception:
            pass

    def _rotate_if_needed(self) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                bak = self.path.with_suffix(".jsonl.1")
                if bak.exists():
                    bak.unlink()
                self.path.rename(bak)
        except Exception:
            pass

    def close(self) -> None:
        with self._lock:
            if self._fh:
                try:
                    self._fh.close()
                except Exception:
                    pass
                self._fh = None

    # ---- 读取 ---------------------------------------------------------

    def tail(self, n: int = 200, min_severity: str = "info",
             kinds: list[str] | None = None) -> list[dict]:
        floor = SEV_ORDER.get(min_severity, 0)
        with self._lock:
            items = list(self._buf)
        out = []
        for ev in reversed(items):
            if SEV_ORDER.get(ev.severity, 0) < floor:
                continue
            if kinds and ev.kind not in kinds:
                continue
            out.append(ev.to_dict())
            if len(out) >= n:
                break
        out.reverse()
        return out

    def since(self, seq: int, limit: int = 500) -> list[dict]:
        with self._lock:
            items = list(self._buf)
        return [e.to_dict() for e in items if e.extra.get("seq", 0) > seq][:limit]

    def stats(self) -> dict:
        with self._lock:
            items = list(self._buf)
        by_sev: dict[str, int] = {}
        by_code: dict[str, int] = {}
        for e in items:
            by_sev[e.severity] = by_sev.get(e.severity, 0) + 1
            if e.code:
                by_code[e.code] = by_code.get(e.code, 0) + 1
        return {
            "buffered": len(items),
            "total": self._seq,
            "by_severity": by_sev,
            "by_code": dict(sorted(by_code.items(), key=lambda x: -x[1])[:20]),
            "file": str(self.path),
        }

    # ---- 订阅 ---------------------------------------------------------

    def subscribe(self, cb: Callable[[Event], None]) -> Callable[[], None]:
        with self._lock:
            self._subs.append(cb)

        def unsub():
            with self._lock:
                if cb in self._subs:
                    self._subs.remove(cb)
        return unsub


BUS = LogBus()


def emit_any(kind: str, **kw) -> Event:
    return BUS.emit(kind, **kw)
