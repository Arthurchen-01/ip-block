"""配置读写。所有可变行为都在这里，代码里不藏策略。

路径注意：ROOT / DATA_DIR 一律走 eg.paths，**不要**用 __file__ 自己推。
PyInstaller 冻结后 __file__ 指向 %TEMP%\\_MEIxxxxx（进程退出就删），
配置和日志建在那里等于每次重启都丢。
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import threading
from pathlib import Path

from .paths import app_root, data_dir

ROOT = app_root()
DATA_DIR = data_dir()
CONFIG_PATH = DATA_DIR / "config.json"

# 隧道自身的进程：必须放行，否则 kill switch 会把 VPN 自己掐死，
# 然后本机就彻底断网了（这是所有 kill switch 实现最常见的自杀方式）。
DEFAULT_ALLOW_PROCESSES = [
    "iKuuuVPNCore.exe",
    "iKuuuVPN.exe",
    "iKuuuVPNHelperService.exe",
    "crashpad_handler.exe",
]

DEFAULT_CONFIG: dict = {
    "version": 1,

    # ---- 总开关 -------------------------------------------------------
    # 默认关闭 + 默认演练模式。第一次装上不会动你任何东西，
    # 你先看仪表盘跑一阵、确认判定符合预期，再真正启用。
    "enabled": False,
    "dry_run": True,

    # ---- 处置动作 -----------------------------------------------------
    # "notify_only"      只记录 + 通知，不动连接（演练模式强制此档）
    # "block_new"        封杀该程序到该目标的后续连接，已建立连接不动
    # "block_and_kill"   上面 + 强杀已建立的违规连接（推荐）
    # "block_kill_proc"  上面全部 + 终结违规进程（最狠）
    "action": "block_and_kill",
    "kill_established": True,
    "kill_process": False,
    "quarantine_minutes": 30,      # 违规程序被隔离多久（0=直到手动解除）

    # 隔离粒度：默认「程序 → 目标」，不是「程序」。
    #
    # 为什么：python.exe / java.exe / node.exe / svchost.exe 这类**共用宿主**
    # 一个 exe 承载无数互不相干的程序。按程序封杀会让
    # "某个 python 脚本裸奔" 变成 "这台机器上所有 python 程序断网"。
    #
    # 同一个程序被封的目标数达到下面这个阈值，才升级成整程序封杀（惯犯）。
    # 共用宿主（python.exe 等）与工具自身**永不升级**，见 enforce.SHARED_HOST_EXES。
    "target_block_escalate_threshold": 8,

    # ---- 结构性泄漏自动修复（v1.1.0 新增）----------------------------
    #
    # 为什么必须有这个：IPv6 旁路和非隧道 DNS 是**常驻状态**，不是一次性事件。
    # 它们不会自己消失 —— 换张网卡、路由器重新通告、VPN 客户端重装，
    # 泄漏就回来了。原来只"报告"，用户不点仪表盘上的按钮就一直在漏。
    #
    # 实测佐证：本机在 20 分钟内出现过「以太网 2」这块新网卡，
    # 它和 WLAN 3 同时带着公网 IPv6（2408:896e:1:1fb6::/64），
    # 而两块网卡的 DNS 都是 192.168.0.1（国内）。
    # 没有人会盯着仪表盘等这个，所以必须自动处理。
    #
    # 修复动作都记录在 data/remediation.json，可以一键回滚。
    "auto_remediate": True,
    "auto_remediate_ipv6": True,     # 物理网卡上出现全局 IPv6 -> 封杀
    "auto_remediate_dns": True,      # 物理网卡用了非隧道 DNS -> 改指隧道 DNS
    "remediate_cooldown_s": 300,     # 同一项多久内不重复修（防抖）

    # ---- 引导到隧道 ---------------------------------------------------
    # EgressGuard **做不到**把一条已经建立的连接改道进隧道 ——
    # 那条连接显式绑定了物理网卡，根本不进 TUN，用户态无法重定向它。
    # 但可以做两件真正有用的"引导"：
    #   1. 掐断 → 逼它重连：重连时若不显式 bind 物理网卡，就会走 TUN（自然进隧道）
    #   2. 把系统代理指向隧道端口：支持系统代理的程序（浏览器等）会主动走隧道
    "guide_to_tunnel": True,
    "system_proxy": {
        "enabled": False,          # 是否在装规则时顺手把系统代理指向隧道
        "server": "",              # 留空=自动探测（127.0.0.1:7890 之类）
    },

    # ---- 隧道识别 -----------------------------------------------------
    "tunnel_interfaces": [],                   # 显式指定，留空则自动识别
    "tunnel_cidrs": ["198.18.0.0/15"],         # TUN 假地址段惯例

    # ---- 放行 ---------------------------------------------------------
    "allow_processes": list(DEFAULT_ALLOW_PROCESSES),
    "allow_remote_cidrs": [
        "127.0.0.0/8",
        "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",   # 内网
        "169.254.0.0/16",                                   # 链路本地
        "224.0.0.0/4", "255.255.255.255/32",                # 组播/广播
        "::1/128", "fe80::/10", "ff00::/8",
    ],
    "allow_ports": [53, 67, 68, 123],          # 基础服务（仅当目标在白名单网段时）

    # ---- 泄漏判据 -----------------------------------------------------
    "blocked_ips": [],                          # 标定出的本机真实出口，精确封杀
    "blocked_cidrs": [
        # 云南三大运营商公开分配段（快速预筛；权威判据是地理查询）
        "222.172.0.0/16", "220.163.0.0/16", "116.52.0.0/14", "182.240.0.0/13",
        "106.56.0.0/14", "113.16.0.0/13", "218.62.0.0/16", "61.166.0.0/16",
        "112.112.0.0/14", "183.224.0.0/12", "39.128.0.0/12",
        "42.242.0.0/15", "119.62.0.0/16", "116.248.0.0/14", "27.40.0.0/13",
        "218.194.0.0/16", "219.221.0.0/16",
        # 大陆运营商 IPv6 大段
        "2408:8000::/20", "240e::/20", "2409::/20",
    ],
    "blocked_countries": ["CN"],
    # 匹配的是地理库返回的 regionName + city 字段（拼起来做小写包含匹配）。
    # 中英文都留着是**防御性**的：ip-api 对国内地址常返回中文省市名，
    # 而 ipwho.is / api.ip.sb 可能返回英文。少写一个就会出现"判定漏了"。
    "blocked_regions": ["yunnan", "kunming", "云南", "昆明"],
    "require_foreign_egress": True,             # 出口必须落在境外

    # ---- 检测项开关 ---------------------------------------------------
    "check_physical_egress": True,      # 连接绑定物理网卡
    "check_egress_ip": True,            # 出口 IP 落在昆明/大陆/真实出口
    "check_ipv6": True,                 # 非隧道网卡上的全局 IPv6
    "check_dns": True,                  # DNS 发往非隧道解析器
    "check_fingerprint_channels": True, # NetBIOS/mDNS/LLMNR/SMB/SSDP
    "check_fingerprint_payload": True,  # 出站内容含主机名/MAC/GUID/用户名

    # ---- 节奏 ---------------------------------------------------------
    "poll_interval_ms": 250,
    # 网卡态势刷新间隔。刷新要起一次 PowerShell（实测约 5~6 秒，主要是
    # PowerShell 自身启动 + 网络 CIM 模块加载的成本，不是命令条数的问题）。
    # 所以这个值不能太小：设成 8 秒的话，刷新线程 70% 时间都在忙。
    # 网络拓扑本身极少变化，20 秒完全够用。
    # 关键点：刷新跑在**独立线程**里，无论多慢都不会阻塞 250ms 的热循环。
    "adapter_refresh_s": 20,
    "probe_interval_s": 60,
    "probe_timeout_s": 6,
    "reannounce_s": 60,          # 同一条判定多久重新播报一次（防刷屏）

    # ---- 指纹 ---------------------------------------------------------
    "fingerprint_needles": [],   # 留空则自动从本机取：主机名/MAC/MachineGuid/用户名/SID
    "auto_fingerprint_needles": True,
    "dhcp_hostname_neutralize": False,   # 把 DHCP 主机名改成中性名（要管理员）

    # ---- 清洗代理 -----------------------------------------------------
    "guard_proxy": {
        "enabled": False,
        "host": "127.0.0.1",
        "port": 47830,
        "scrub_headers": True,       # 改写 User-Agent / 删除 X-Forwarded-For 等
        "block_on_fingerprint": True,
        "upstream": "",              # 留空 = 直连；可填 "http://127.0.0.1:7890"
    },

    # ---- 本地 API（供被掐断的程序来问"为什么"）------------------------
    "api": {
        "host": "127.0.0.1",
        "port": 47821,
        "token": "",
        "pipe": "EgressGuard",
    },

    # ---- 通知 ---------------------------------------------------------
    "notify": {
        "log_file": True,
        "console": True,        # 往目标进程控制台写红字
        "messagebox": True,     # 在目标进程窗口上弹框
        "eventlog": True,
        "toast": True,
        "desktop_file": True,   # 往桌面写一张"原因卡"
    },
    "notify_cooldown_s": 20,    # 同一程序同一原因多久内不重复弹

    # ---- 严格模式（全局默认拒绝 + 白名单放行）------------------------
    # 打开后防火墙默认出站策略变 Block。这是真正的 kill switch，
    # 但一旦白名单漏了东西，你会直接断网。默认关。
    "strict_kill_switch": False,
    "strict_allow_svchost": True,

    # ---- 隧道断开自动熔断（推荐开）------------------------------------
    # 隧道在的时候正常跑；隧道一断，立刻把出站默认策略切成 Block，
    # 只放行隧道程序（好让它重连）+ 本工具自身。
    # 这才是 kill switch 真正有价值的用法：消灭"VPN 掉了、流量裸奔"那个窗口。
    # 隧道恢复后自动解除。默认开，但只在 enabled=true 时才动作。
    "fail_closed_on_tunnel_loss": True,

    # ---- 自测模式 -----------------------------------------------------
    # 打开后所有通知和事件都会带「【自测流量，不是真实泄漏】」前缀。
    # 验收测试会打开它 —— 因为实测出现过"别的工具撞上闸门正在跑验收测试"
    # 的窗口期，那几分钟里 python.exe 被真封杀，对方完全没法联网、
    # 也不知道是谁干的。标出来至少能让人一眼看懂。
    "selftest_mode": False,

    "autostart": False,
    "dashboard_autostart": False,
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class Config:
    """线程安全的配置对象，落盘为 data/config.json。"""

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else CONFIG_PATH
        self._lock = threading.RLock()
        self._data = copy.deepcopy(DEFAULT_CONFIG)
        self.load()

    # ---- 读写 ---------------------------------------------------------

    def load(self) -> dict:
        with self._lock:
            if self.path.exists():
                try:
                    raw = json.loads(self.path.read_text(encoding="utf-8"))
                    self._data = _deep_merge(DEFAULT_CONFIG, raw)
                except Exception:
                    self._data = copy.deepcopy(DEFAULT_CONFIG)
            else:
                self._data = copy.deepcopy(DEFAULT_CONFIG)
            if not self._data["api"]["token"]:
                self._data["api"]["token"] = secrets.token_hex(16)
                self._save_locked()
            return copy.deepcopy(self._data)

    def save(self) -> None:
        with self._lock:
            self._save_locked()

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    # ---- 访问 ---------------------------------------------------------

    def get(self, key: str, default=None):
        with self._lock:
            return copy.deepcopy(self._data.get(key, default))

    def set(self, key: str, value) -> None:
        with self._lock:
            self._data[key] = value

    def update(self, patch: dict) -> dict:
        with self._lock:
            self._data = _deep_merge(self._data, patch)
            self._save_locked()
            return copy.deepcopy(self._data)

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._data)

    # ---- 便捷属性 -----------------------------------------------------

    @property
    def enabled(self) -> bool:
        return bool(self.get("enabled"))

    @property
    def dry_run(self) -> bool:
        return bool(self.get("dry_run"))

    @property
    def effective_action(self) -> str:
        """演练模式下永远只通知不动手。"""
        if self.dry_run:
            return "notify_only"
        return str(self.get("action", "block_and_kill"))

    @property
    def api_token(self) -> str:
        return str(self.get("api", {}).get("token", ""))


def ensure_dirs() -> None:
    for sub in ("", "notices", "reports"):
        (DATA_DIR / sub).mkdir(parents=True, exist_ok=True)
