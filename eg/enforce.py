"""执行层：真正把泄漏掐断。

四个动作原语
------------
1. 强杀单条连接   SetTcpEntry(DELETE_TCB) —— 立刻复位一条已建立的 TCP 连接
2. 封杀「程序→目标」  防火墙出站 Block 规则（按 Program + RemoteAddress）
                     **默认隔离粒度**。只封"这个程序连这个目标"，
                     不封这个程序的所有连接 —— 见下面关于连坐的说明
3. 隔离整个程序   防火墙出站 Block 规则（只按 Program）
                     仅用于"惯犯"升级，且共用宿主与自身永不使用
4. 全局闸门       防火墙默认出站策略 = Block + 白名单放行（严格 kill switch）

⚠ 为什么默认粒度是「程序→目标」而不是「程序」
-----------------------------------------------
这是被真实反馈打回来重做的。

原来的做法是发现一次泄漏就按 exe 路径封杀整个程序。对单一用途的程序没问题，
但对**共用宿主**是灾难：

    python.exe / java.exe / node.exe / powershell.exe / svchost.exe ...
    一个 exe 承载着无数互不相干的程序。

于是"某个 python 脚本裸奔" 会变成 "这台机器上所有 python 程序一起断网"。
更糟的是：**源码形态下守护自己就是 python.exe，它会把自己封杀** ——
实测用户就是这么遇到"源码模式跑不动"的。

把粒度降到 (Program, RemoteAddress) 之后：
    某个 python 脚本连 1.2.3.4 裸奔 → 只封 "python.exe 连 1.2.3.4"
    别的 python 程序连别的目标 → 完全不受影响

对惯犯仍然可以升级到按程序封杀，但共用宿主与自身**永不升级**。

权限
----
1 需要管理员；2、3、4 需要管理员。没有管理员时本模块的所有操作会
明确返回"权限不足"，而不是静默失败——静默失败是这类工具最危险的 bug。

编码
----
所有 PowerShell 调用一律走 -EncodedCommand（UTF-16LE base64），
彻底绕开中文/引号/换行在命令行里被 GBK 撕碎的问题。
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from . import winapi as W
from .config import Config
from .logbus import LogBus
from .policy import Finding

GROUP = "EgressGuard"
RULE_PREFIX = "EgressGuard::"
_PS = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]

# 指纹信道端口（出站）
FP_TCP_PORTS = [139, 445]
FP_UDP_PORTS = [137, 138, 1900, 3702, 5353, 5355]

# --------------------------------------------------------------------------
# 共用宿主（一个 exe 承载无数互不相干的程序）
#
# 对这些 exe **永不**做"按程序封杀"——那会把无关的程序一起打死。
# 只做「程序→目标」粒度的封杀，加上反复掐断。
# --------------------------------------------------------------------------
SHARED_HOST_EXES: frozenset[str] = frozenset(x.lower() for x in (
    # 解释器 / 脚本宿主
    "python.exe", "pythonw.exe", "py.exe", "pyw.exe",
    "java.exe", "javaw.exe", "jre.exe",
    "node.exe", "nodejs.exe",
    "perl.exe", "ruby.exe", "php.exe", "lua.exe", "Rscript.exe",
    "git.exe", "bash.exe", "sh.exe", "wsl.exe", "wslhost.exe",
    # Windows 自带的脚本 / 通用宿主
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "installutil.exe",
    "conhost.exe", "dllhost.exe", "svchost.exe", "RuntimeBroker.exe",
    "explorer.exe", "SearchHost.exe", "StartMenuExperienceHost.exe",
    "backgroundTaskHost.exe", "WmiPrvSE.exe", "taskhostw.exe",
    # 容器 / 虚拟化宿主
    "docker.exe", "wslservice.exe",
))


def _run_ps(script: str, timeout: float = 30.0) -> tuple[bool, str, str]:
    """跑一段 PowerShell，返回 (成功, stdout, stderr)。

    编码坑（实测踩到）：PowerShell 往管道写非 ASCII 时用的是**控制台代码页**
    （中文系统上是 936/GBK），不是 UTF-8。Python 侧按 UTF-8 解码就会把
    所有中文变成乱码 —— 规则名、程序路径、错误信息全毁。
    所以每个脚本前面强制注入 OutputEncoding/InputEncoding = UTF-8，
    让 PowerShell 自己把中文按 UTF-8 吐出来。
    """
    prologue = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
                "$OutputEncoding=[System.Text.Encoding]::UTF8;"
                "$ProgressPreference='SilentlyContinue';")
    enc = base64.b64encode((prologue + script).encode("utf-16-le")).decode("ascii")
    try:
        p = subprocess.run(
            _PS + ["-EncodedCommand", enc],
            capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = (p.stdout or b"").decode("utf-8", "replace").strip()
        err = (p.stderr or b"").decode("utf-8", "replace").strip()
        return (p.returncode == 0, out, err)
    except subprocess.TimeoutExpired:
        return (False, "", f"PowerShell 超时（{timeout}s）")
    except Exception as e:
        return (False, "", f"PowerShell 调用失败：{e}")


@dataclass
class ActionResult:
    ok: bool
    kind: str
    target: str = ""
    detail: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "kind": self.kind, "target": self.target,
                "detail": self.detail, "extra": self.extra}


class Enforcer:
    def __init__(self, cfg: Config, bus: LogBus):
        self.cfg = cfg
        self.bus = bus
        self._lock = threading.RLock()
        self._admin = W.is_admin()
        self._created: set[str] = set()
        # exe(小写) -> 已被封杀的目标 IP 集合。用于判断要不要升级成整程序封杀。
        self._target_hits: dict[str, set[str]] = {}
        self._profiles_enabled_by_us = False
        self._default_outbound_flipped = False
        self._strict_allow: list[str] = []

    # ---- 权限 ---------------------------------------------------------

    @property
    def is_admin(self) -> bool:
        return self._admin

    def recheck_admin(self) -> bool:
        self._admin = W.is_admin()
        return self._admin

    def _guard(self) -> tuple[bool, str]:
        if not self._admin:
            return (False, "权限不足：该操作需要管理员。请运行『安装_右键管理员运行.bat』"
                           "装好提权守护进程，或右键以管理员身份启动。")
        return (True, "")

    def ensure_firewall_enabled(self) -> tuple[bool, str]:
        """**任何写防火墙规则之前必须先过这一关。**

        实测踩到的坑：本机三个配置文件的防火墙原本都是关闭的。
        此时 New-NetFirewallRule 照样能成功建出规则、Get-NetFirewallRule
        也照样能查到它（Action=Block、Enabled=True），
        但**规则完全不生效** —— 因为防火墙本身没开。
        结果就是"隔离成功了"却什么都没挡住，是最危险的那种静默失败。

        所以每个写规则的方法入口都强制调这个，并且把"顺手开了防火墙"
        这件事明确记进事件流，不偷偷做。
        """
        ok, why = self._guard()
        if not ok:
            return (False, why)
        st = self.firewall_state()
        vals = [v for v in st.values() if isinstance(v, dict)]
        if vals and all(v.get("enabled") for v in vals):
            return (True, "防火墙已是启用状态")
        r = self.enable_firewall()
        if r.ok:
            return (True, "防火墙原本是关闭的，已自动启用（否则规则不会生效）")
        return (False, f"规则需要防火墙开启，但自动启用失败：{r.detail}")

    # ---- 掐断单条连接 -------------------------------------------------

    def kill_connection(self, f: Finding) -> ActionResult:
        if f.proto != "tcp":
            return ActionResult(False, "kill_connection", f"{f.proto} {f.remote}",
                                "UDP 无连接，无法强杀；已通过防火墙规则阻断该程序")
        if ":" in f.local.split(":")[0]:
            return ActionResult(False, "kill_connection", f.remote,
                                "IPv6 连接不支持 SetTcpEntry 强杀；已通过防火墙规则阻断")
        try:
            lip, lport = f.local.rsplit(":", 1)
            rip, rport = f.remote.rsplit(":", 1)
        except ValueError:
            return ActionResult(False, "kill_connection", f.remote, "地址格式无法解析")

        ok, msg = W.kill_tcp_connection(lip, int(lport), rip, int(rport))
        return ActionResult(ok, "kill_connection", f"{f.process} {f.remote}", msg)

    # ---- 隔离程序 -----------------------------------------------------

    @staticmethod
    def _rule_name(kind: str, target: str) -> str:
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in target)
        return f"{RULE_PREFIX}{kind}::{safe}"[:255]

    # ---- 共用宿主 / 自我保护 -------------------------------------------

    @staticmethod
    def is_shared_host(exe_or_name: str) -> bool:
        """这个可执行文件是不是"一个 exe 承载无数程序"的共用宿主？

        判定只看文件名，因为：
          - 同名宿主（python.exe）不管装在哪个路径，连坐风险一样
          - 拿不到全路径时（提权进程）也只有名字可用
        """
        if not exe_or_name:
            return False
        return os.path.basename(exe_or_name).lower() in SHARED_HOST_EXES

    def self_paths(self) -> set[str]:
        """本工具自己的可执行文件全路径（小写）。**永不允许被封杀。**"""
        out = set()
        for p in self._self_programs():
            try:
                out.add(os.path.abspath(p).lower())
            except Exception:
                continue
        return out

    def is_self(self, exe: str) -> bool:
        """这个 exe 是不是本工具自己（或它赖以运行的解释器）？"""
        if not exe:
            return False
        try:
            e = os.path.abspath(exe).lower()
        except Exception:
            return False
        if e in self.self_paths():
            return True
        # 源码形态下守护跑在 python.exe 里，而 _self_programs() 返回的就是
        # 那个 python.exe 的绝对路径，上面已经覆盖。
        # 这里再兜一层：同名的 python.exe 也一律不封（可能路径写法不同）。
        try:
            if os.path.basename(e) in {os.path.basename(p)
                                       for p in self.self_paths()}:
                return True
        except Exception:
            pass
        return False

    # ---- 「程序→目标」粒度封杀（默认隔离动作）--------------------------

    @staticmethod
    def _target_rule_name(exe: str, ip: str) -> str:
        base = os.path.basename(exe or "unknown")
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in base)
        ipart = ip.replace(":", "-").replace(".", "_")
        return f"{RULE_PREFIX}TARGET::{safe}::{ipart}"[:255]

    def block_target(self, exe: str, remote_ip: str, reason: str = "",
                     port: int = 0, proto: str = "tcp") -> ActionResult:
        """封杀「这个程序 → 这个目标」。

        这是**默认隔离粒度**。相比封杀整个程序，它把连坐面从
        "所有 python 程序" 缩小到 "所有 python 程序连这一个目标"，
        而后者在绝大多数场景下等于零影响。

        port=0 表示不限端口（只按目标 IP 封）。
        port>0 时必须同时给 proto —— 实测踩过：只给 -RemotePort 不给 -Protocol，
        PowerShell 会报「协议特定的选项与所选协议不匹配」。
        """
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "block_target", exe, why)
        if not exe or "\\" not in exe:
            return ActionResult(False, "block_target", exe or "?",
                                "拿不到 exe 全路径，无法建精确封杀规则")
        if not remote_ip:
            return ActionResult(False, "block_target", exe, "没有远端地址，无法建精确规则")

        # ⚠ 这里**不**做 is_self 拒绝，和 quarantine_program 刻意不同。
        #
        # 区别在于连坐面：
        #   quarantine_program(self)   = 封杀"这个 exe 的所有连接"
        #                                -> 源码形态下守护自己就是 python.exe，等于自杀，必须拒
        #   block_target(self, ip)     = 封杀"这个 exe 连这一个目标"
        #                                -> 守护自己只连本机 API 和几个回显服务，
        #                                   而它自己的连接本来就在 allow_runtime 白名单里、
        #                                   根本不会被判成泄漏。
        #                                   所以这条规则只会挡住"另一个 python 进程连这个目标"，
        #                                   对守护几乎无影响，保护却继续有效。
        # 一句话：整程序封杀对自身是致命的，目标级封杀不是。
        okf, fmsg = self.ensure_firewall_enabled()
        if not okf:
            return ActionResult(False, "block_target", exe, fmsg)

        rn = self._target_rule_name(exe, remote_ip)
        # -RemotePort 必须配 -Protocol，否则报「协议特定的选项与所选协议不匹配」
        if port:
            p = (proto or "tcp").lower()
            p = "TCP" if p == "tcp" else ("UDP" if p == "udp" else "TCP")
            port_arg = f"-Protocol {p} -RemotePort {port}"
        else:
            port_arg = ""
        script = (
            f"Remove-NetFirewallRule -Name '{rn}' -ErrorAction SilentlyContinue;"
            f"New-NetFirewallRule -Name '{rn}' "
            f"-DisplayName '{GROUP} 封杀 {os.path.basename(exe)} -> {remote_ip}"
            f"{':' + str(port) if port else ''}' "
            f"-Group '{GROUP}' -Direction Outbound -Action Block "
            f"-Program '{exe}' -RemoteAddress '{remote_ip}' {port_arg} "
            f"-Profile Any -Enabled True -ErrorAction Stop | Out-Null;"
            f"Write-Output 'OK'"
        )
        ok, out, err = _run_ps(script)
        if ok and "OK" in out:
            with self._lock:
                self._created.add(rn)
                self._target_hits.setdefault(exe.lower(), set()).add(remote_ip)
            n = len(self._target_hits.get(exe.lower(), ()))
            self.bus.action(
                severity="high", code="BLOCK_TARGET",
                title=f"已封杀 {os.path.basename(exe)} → {remote_ip}",
                detail=(f"只封这一个目标，不影响该程序连别的地址。"
                        f"该程序累计被封目标数 {n}。原因：{reason}"),
                process=os.path.basename(exe), exe=exe, remote=remote_ip,
                reason=reason, extra={"targets": n})
            return ActionResult(True, "block_target", f"{exe} -> {remote_ip}",
                                f"已封杀 {os.path.basename(exe)} 连 {remote_ip}"
                                f"（只封这一个目标，不连坐）；{fmsg}")
        return ActionResult(False, "block_target", exe,
                            f"精确规则创建失败：{(err or out)[:300]}")

    def target_count(self, exe: str) -> int:
        """这个程序已经被封了多少个目标。用于判断要不要升级成整程序封杀。"""
        with self._lock:
            return len(self._target_hits.get((exe or "").lower(), ()))

    def should_escalate(self, exe: str) -> tuple[bool, str]:
        """要不要把「程序→目标」升级成「整程序封杀」？

        三个条件同时满足才升级：
          1. 不是共用宿主（否则连坐灾难）
          2. 不是本工具自身
          3. 被封目标数已达阈值（说明是惯犯，不是偶发）
        """
        if not exe or "\\" not in exe:
            return False, "拿不到 exe 全路径"
        if self.is_self(exe):
            return False, "是本工具自身，永不升级"
        if self.is_shared_host(exe):
            return False, (f"是共用宿主（一个 exe 承载多个程序），"
                           f"按程序封杀会连坐，永不升级")
        thr = int(self.cfg.get("target_block_escalate_threshold", 8) or 8)
        n = self.target_count(exe)
        if n < thr:
            return False, f"被封目标数 {n} < 阈值 {thr}，暂不升级"
        return True, f"被封目标数 {n} ≥ 阈值 {thr}，判定为惯犯，升级为整程序封杀"

    # ---- 整程序隔离（仅用于惯犯升级）----------------------------------

    def quarantine_program(self, exe: str, reason: str = "") -> ActionResult:
        """按可执行文件路径封杀该程序的所有出站流量。

        ⚠ **这是重手段，不要当默认动作。**
        默认应该用 block_target（程序→目标粒度）。
        这里只在 should_escalate() 判定为惯犯时才用，而且：
          - 共用宿主（python.exe / svchost.exe ...）永不进入这里
          - 本工具自身永不进入这里

        为什么按 exe 而不是按 PID：PID 会变、会重启，规则要能活过重启。
        """
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "quarantine", exe, why)

        if exe and ("\\" in exe or "/" in exe):
            if self.is_self(exe):
                return ActionResult(
                    False, "quarantine", exe,
                    "拒绝：这是本工具自身（或它赖以运行的解释器）。"
                    "封了它，守护进程会把自己一起封死，然后整机失去防护。"
                    "已改为只掐连接不封程序。")
            if self.is_shared_host(exe):
                return ActionResult(
                    False, "quarantine", exe,
                    f"拒绝：{os.path.basename(exe)} 是共用宿主，"
                    f"按程序封杀会把无关程序一起打死（连坐）。"
                    f"已改为「程序→目标」粒度封杀 + 持续掐连接。")
            match = f"-Program '{exe}'"
        else:
            name = (exe or "").strip() or "unknown"
            return ActionResult(
                False, "quarantine", name,
                f"拿不到 {name} 的完整路径（多为提权进程）。"
                "请在仪表盘里手动填写该程序的 exe 全路径后重试。")

        okf, fmsg = self.ensure_firewall_enabled()
        if not okf:
            return ActionResult(False, "quarantine", exe, fmsg)

        rn = self._rule_name("QUARANTINE", exe)
        script = (
            f"Remove-NetFirewallRule -Name '{rn}' -ErrorAction SilentlyContinue;"
            f"New-NetFirewallRule -Name '{rn}' -DisplayName '{GROUP} 隔离 {exe}' "
            f"-Group '{GROUP}' -Direction Outbound -Action Block {match} "
            f"-Profile Any -Enabled True -ErrorAction Stop | Out-Null;"
            f"Write-Output 'OK'"
        )
        ok, out, err = _run_ps(script)
        if ok and "OK" in out:
            with self._lock:
                self._created.add(rn)
            self.bus.action(severity="high", code="QUARANTINE",
                            title="已隔离程序（整程序封杀）",
                            detail=f"已封杀 {exe} 的全部出站流量（{fmsg}）。原因：{reason}",
                            process=exe, exe=exe, reason=reason)
            return ActionResult(True, "quarantine", exe,
                                f"已封杀 {exe} 的出站流量；{fmsg}")
        return ActionResult(False, "quarantine", exe, f"规则创建失败：{err or out}")

    def release_program(self, exe: str) -> ActionResult:
        """解除对某个程序的全部封杀：整程序规则 + 所有「程序→目标」规则。"""
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "release", exe, why)
        rn = self._rule_name("QUARANTINE", exe)
        base = os.path.basename(exe or "unknown")
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in base)
        script = (
            f"Remove-NetFirewallRule -Name '{rn}' -ErrorAction SilentlyContinue;"
            f"Get-NetFirewallRule -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.Name -like '{RULE_PREFIX}TARGET::{safe}::*' }} | "
            f"Remove-NetFirewallRule -ErrorAction SilentlyContinue;"
            f"Write-Output 'OK'")
        ok, out, err = _run_ps(script)
        with self._lock:
            self._created.discard(rn)
            self._target_hits.pop((exe or "").lower(), None)
        self.bus.action(severity="info", code="RELEASE", title="已解除封杀",
                        detail=f"已放行 {exe}（含它的所有目标级规则）",
                        process=base, exe=exe)
        return ActionResult(ok, "release", exe, "已解除隔离" if ok else f"失败：{err}")

    # ---- 静态防护规则 -------------------------------------------------

    def install_static_rules(self, physical_aliases: list[str]) -> list[ActionResult]:
        """装两条常备规则：
             IPv6 全封（在物理网卡上）—— 堵死旁路通道
             指纹信道封杀（在物理网卡上）—— 堵死主机名广播
        这两条不需要"发现违规"才生效，属于常备工事。
        """
        res: list[ActionResult] = []
        okp, why = self._guard()
        if not okp:
            return [ActionResult(False, "static_rules", "", why)]
        okf, fmsg = self.ensure_firewall_enabled()
        if not okf:
            return [ActionResult(False, "static_rules", "", fmsg)]

        # ⚠ IPv6 那条规则**故意不绑接口**。
        #   绑接口的话，一旦出现新网卡（实测：这台机器上冒出过一块「以太网 2」），
        #   新网卡上的 IPv6 就不在规则覆盖范围内，旁路重新打开。
        #   隧道不承载 IPv6，所以"全局封 IPv6 全球单播"是安全的，也自动覆盖新网卡。
        alias_arg = ",".join(f"'{a}'" for a in physical_aliases) if physical_aliases else ""
        iface = f"-InterfaceAlias @({alias_arg})" if alias_arg else ""

        # --- IPv6 全封 ---
        #
        # ⚠ 实测踩坑记录：封 IPv6 不能用 -Protocol IPv6，也不能用 -RemoteAddress '::/0'
        #      -Protocol IPv6        -> "The protocol is invalid."（IPv6 不是合法协议名）
        #      -Protocol 41          -> 能建规则，但 41 是"IPv6 封装(6in4)"，只封隧道不封 IPv6
        #      -RemoteAddress '::/0' -> "一个或多个地址前缀无效"（Windows 拒绝全零前缀）
        #   实测可行：::/1 + 8000::/1 覆盖整个 IPv6 空间。
        #
        # ⚠ 但"覆盖整个空间"是错的，会把本地链路的必需流量也一起封掉：
        #   邻居发现（ICMPv6 NS/NA）、路由器通告（RA）、DHCPv6（UDP 546/547）
        #   全是 IPv6。封了它们，网卡可能拿不到/续不上地址，
        #   公网 IPv6 地址会掉，而用户看到的现象是"装完这个工具我 IPv6 没了"。
        #
        #   正确做法：只封**全球单播**（2000::/3，即 2000:: 到 3fff::），
        #   也就是"真正的互联网"。fe80::/10（链路本地）、fc00::/7（ULA）、
        #   ff00::/8（组播）都不在这个范围里，因此邻居发现与 DHCPv6 不受影响。
        rn = self._rule_name("STATIC", "BLOCK_IPV6")
        script = (
            f"Remove-NetFirewallRule -Name '{rn}' -ErrorAction SilentlyContinue;"
            f"New-NetFirewallRule -Name '{rn}' "
            f"-DisplayName '{GROUP} 阻断物理网卡 IPv6 出站' "
            f"-Group '{GROUP}' -Direction Outbound -Action Block -Protocol Any "
            f"-RemoteAddress @('2000::/3') "
            f"-Profile Any -Enabled True -ErrorAction Stop | Out-Null;"
            f"Write-Output 'OK'"
        )
        ok, out, err = _run_ps(script)
        if ok:
            with self._lock:
                self._created.add(rn)
        res.append(ActionResult(ok, "rule_ipv6", "物理网卡 IPv6",
                                ("已封杀全部 IPv6 全球单播出站"
                                 "（2000::/3，即真正的 IPv6 互联网）；"
                                 "链路本地/组播/DHCPv6 不受影响，"
                                 f"网卡仍能正常做邻居发现与地址续期。{fmsg}")
                                if ok else f"失败：{(err or out)[:300]}"))
        self.bus.action(severity="medium" if ok else "high", code="RULE_IPV6",
                        title="IPv6 旁路封堵", detail=res[-1].detail)

        # --- 指纹信道 ---
        rn2 = self._rule_name("STATIC", "BLOCK_FINGERPRINT")
        tcp_arg = ",".join(str(p) for p in FP_TCP_PORTS)
        udp_arg = ",".join(str(p) for p in FP_UDP_PORTS)
        script2 = (
            f"Remove-NetFirewallRule -Name '{rn2}' -ErrorAction SilentlyContinue;"
            f"New-NetFirewallRule -Name '{rn2}' -DisplayName '{GROUP} 阻断指纹信道(TCP)' "
            f"-Group '{GROUP}' -Direction Outbound -Action Block -Protocol TCP "
            f"-RemotePort @({tcp_arg}) {iface} -Profile Any -Enabled True -ErrorAction Stop | Out-Null;"
            f"Remove-NetFirewallRule -Name '{rn2}U' -ErrorAction SilentlyContinue;"
            f"New-NetFirewallRule -Name '{rn2}U' -DisplayName '{GROUP} 阻断指纹信道(UDP)' "
            f"-Group '{GROUP}' -Direction Outbound -Action Block -Protocol UDP "
            f"-RemotePort @({udp_arg}) {iface} -Profile Any -Enabled True -ErrorAction Stop | Out-Null;"
            f"Write-Output 'OK'"
        )
        ok2, out2, err2 = _run_ps(script2)
        with self._lock:
            if ok2:
                self._created.add(rn2)
                self._created.add(rn2 + "U")
        res.append(ActionResult(ok2, "rule_fingerprint", "指纹信道",
                                "已封杀 NetBIOS/mDNS/LLMNR/SMB/SSDP 在物理网卡上的出站"
                                if ok2 else f"失败：{(err2 or out2)[:300]}"))
        self.bus.action(severity="medium" if ok2 else "high", code="RULE_FINGERPRINT",
                        title="指纹信道封堵", detail=res[-1].detail)
        return res

    # ---- 防火墙开关 ---------------------------------------------------

    def enable_firewall(self) -> ActionResult:
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "enable_firewall", "", why)
        ok, out, err = _run_ps(
            "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True "
            "-ErrorAction Stop; Write-Output 'OK'")
        if ok:
            self._profiles_enabled_by_us = True
        self.bus.action(severity="medium" if ok else "high", code="FW_ENABLE",
                        title="启用 Windows 防火墙",
                        detail="已启用全部三个配置文件的防火墙" if ok else f"失败：{err or out}")
        return ActionResult(ok, "enable_firewall", "所有配置文件",
                            "防火墙已启用" if ok else f"失败：{err or out}")

    def firewall_state(self) -> dict:
        """防火墙状态。Action 一律转成字符串。

        为什么必须转字符串：`Get-NetFirewallProfile` 返回的
        DefaultOutboundAction 是枚举，`ConvertTo-Json` 会把它序列化成整数
        （Allow=2 / Block=4 / NotConfigured=0）。整数进了 JSON 之后，
        仪表盘和任何消费方都得靠猜，极容易把 4 当成"未配置"而不是"阻断"。
        实测就是因为这个，验收脚本把一次成功的严格闸门误判成了失败。
        """
        ok, out, err = _run_ps(
            "Get-NetFirewallProfile | ForEach-Object { "
            "[PSCustomObject]@{ Name=$_.Name; Enabled=[bool]$_.Enabled; "
            "DefaultOutboundAction=$_.DefaultOutboundAction.ToString() } } | "
            "ConvertTo-Json -Compress", timeout=20)
        if not ok:
            return {"error": err or out}
        try:
            d = json.loads(out)
            if isinstance(d, dict):
                d = [d]
            return {x["Name"]: {"enabled": bool(x["Enabled"]),
                                "default_outbound": x.get("DefaultOutboundAction")}
                    for x in d}
        except Exception:
            return {"raw": out}

    # ---- 严格 kill switch ---------------------------------------------

    def _self_programs(self) -> list[str]:
        """本工具自己的可执行文件，严格模式下必须自动放行。

        实测踩到的坑：严格模式（出站默认 Block）一开，仪表盘自己的出口探测
        立刻就断了 —— 因为探测进程自己不在白名单里。
        用户装的是"闸门"，不是"把自己的网也掐了"。
        所以守护进程、仪表盘、当前解释器一律自动加入放行名单。
        """
        out: list[str] = []
        try:
            out.append(os.path.abspath(sys.executable))
        except Exception:
            pass
        try:
            out.append(os.path.abspath(sys.argv[0]))
        except Exception:
            pass
        try:
            from .paths import app_root, is_frozen
            if is_frozen():
                for n in ("EgressGuardCore.exe", "EgressGuard.exe"):
                    p = app_root() / n
                    if p.exists():
                        out.append(str(p))
        except Exception:
            pass
        seen, uniq = set(), []
        for p in out:
            if p and p.lower() not in seen and os.path.exists(p):
                seen.add(p.lower())
                uniq.append(p)
        return uniq

    def strict_kill_switch(self, on: bool,
                           allow_programs: list[str]) -> ActionResult:
        """全局默认拒绝 + 白名单放行。

        ⚠ 这是唯一一个能把整机网络搞断的操作。两条纪律：
        1. 顺序：打开时先建好全部放行规则，最后才翻默认策略；
           关闭时先恢复默认策略，再删规则。反过来做会有一段全断窗口。
        2. 白名单里必须包含：隧道程序 + 本工具自己。
           少任何一个，都会出现"闸门把自己或 VPN 掐死"的后果。
        """
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "strict_kill_switch", "", why)
        okf, fmsg = self.ensure_firewall_enabled()
        if not okf:
            return ActionResult(False, "strict_kill_switch", "", fmsg)

        allow_progs = [p for p in allow_programs if p and ("\\" in p)]
        self_progs = self._self_programs()
        for p in self_progs:
            if p not in allow_progs:
                allow_progs.append(p)

        if on:
            script_parts = [f"Remove-NetFirewallRule -Group '{GROUP}_STRICT_ALLOW' "
                            f"-ErrorAction SilentlyContinue;"]
            for i, p in enumerate(allow_progs):
                rn = self._rule_name("STRICT_ALLOW", f"{i}_{p}")
                script_parts.append(
                    f"New-NetFirewallRule -Name '{rn}' -DisplayName '{GROUP} 严格模式放行 {p}' "
                    f"-Group '{GROUP}_STRICT_ALLOW' -Direction Outbound -Action Allow "
                    f"-Program '{p}' -Profile Any -Enabled True -ErrorAction SilentlyContinue "
                    f"| Out-Null;")
            if self.cfg.get("strict_allow_svchost", True):
                for svc in ("svchost.exe", "lsass.exe", "services.exe", "svchost.exe"):
                    rn = self._rule_name("STRICT_ALLOW", f"sys_{svc}")
                    script_parts.append(
                        f"New-NetFirewallRule -Name '{rn}' -DisplayName '{GROUP} 严格模式放行系统 {svc}' "
                        f"-Group '{GROUP}_STRICT_ALLOW' -Direction Outbound -Action Allow "
                        f"-Program \"$env:SystemRoot\\System32\\{svc}\" -Profile Any "
                        f"-Enabled True -ErrorAction SilentlyContinue | Out-Null;")
            # 最后才翻默认策略
            script_parts.append(
                "Set-NetFirewallProfile -Profile Domain,Private,Public "
                "-DefaultOutboundAction Block -ErrorAction Stop;")
            script_parts.append("Write-Output 'OK'")
            ok, out, err = _run_ps("\n".join(script_parts), timeout=90)
            if ok:
                self._default_outbound_flipped = True
                self._strict_allow = allow_progs
            self.bus.action(
                severity="critical", code="STRICT_ON", title="严格闸门已开启",
                detail=(f"出站默认策略已改为 Block，仅白名单放行。"
                        f"白名单 {len(allow_progs)} 个程序"
                        f"（含本工具自身 {len(self_progs)} 个）+ 系统进程。"
                        f"注意：不在白名单里的程序会全部断网。")
                if ok else f"失败：{(err or out)[:300]}")
            return ActionResult(ok, "strict_kill_switch", "全局",
                                (f"严格闸门已开启（默认拒绝）。放行 {len(allow_progs)} 个程序"
                                 f"（含本工具自身）。不在名单里的程序会断网。")
                                if ok else f"失败：{(err or out)[:300]}")

        # 关闭：先恢复默认策略，再删放行规则
        script = (
            "Set-NetFirewallProfile -Profile Domain,Private,Public "
            "-DefaultOutboundAction Allow -ErrorAction SilentlyContinue;"
            f"Remove-NetFirewallRule -Group '{GROUP}_STRICT_ALLOW' -ErrorAction SilentlyContinue;"
            "Write-Output 'OK'")
        ok, out, err = _run_ps(script, timeout=60)
        if ok:
            self._default_outbound_flipped = False
        self.bus.action(severity="medium", code="STRICT_OFF", title="严格闸门已关闭",
                        detail="出站默认策略已恢复为 Allow" if ok else f"失败：{err or out}")
        return ActionResult(ok, "strict_kill_switch", "全局",
                            "已恢复默认放行" if ok else f"失败：{err or out}")

    def fail_closed(self, on: bool, allow_programs: list[str]) -> ActionResult:
        """隧道断开时的自动熔断。

        这是比"手动严格模式"更有价值的用法：隧道在的时候正常跑，
        隧道一断，立刻把出站默认策略切成 Block，只放行隧道程序
        （好让它能重连），这样就不会出现"VPN 掉了、流量裸奔"的窗口。

        与手动严格模式的区别：白名单只有隧道程序 + 本工具，
        不试图给用户的所有程序开口子 —— 因为它的语义就是"宁可全断，不许裸奔"。
        """
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "fail_closed", "", why)
        okf, fmsg = self.ensure_firewall_enabled()
        if not okf:
            return ActionResult(False, "fail_closed", "", fmsg)

        allow = [p for p in allow_programs if p and "\\" in p] + self._self_programs()
        allow = list(dict.fromkeys(allow))

        if on:
            parts = [f"Remove-NetFirewallRule -Group '{GROUP}_FAILCLOSED' -ErrorAction SilentlyContinue;"]
            for i, p in enumerate(allow):
                rn = self._rule_name("FAILCLOSED", f"{i}_{p}")
                parts.append(
                    f"New-NetFirewallRule -Name '{rn}' -DisplayName '{GROUP} 熔断放行 {p}' "
                    f"-Group '{GROUP}_FAILCLOSED' -Direction Outbound -Action Allow "
                    f"-Program '{p}' -Profile Any -Enabled True -ErrorAction SilentlyContinue "
                    f"| Out-Null;")
            parts.append("Set-NetFirewallProfile -Profile Domain,Private,Public "
                         "-DefaultOutboundAction Block -ErrorAction Stop;")
            parts.append("Write-Output 'OK'")
            ok, out, err = _run_ps("\n".join(parts), timeout=90)
            self.bus.action(
                severity="critical", code="FAILCLOSED_ON",
                title="隧道断开 → 已熔断（全断，防裸奔）",
                detail=(f"出站默认策略已切为 Block，仅放行隧道程序 {len(allow)} 个。"
                        f"隧道恢复后会自动解除。") if ok else f"失败：{(err or out)[:300]}")
            return ActionResult(ok, "fail_closed", "全局",
                                "已熔断：只放行隧道程序，其余全部阻断" if ok
                                else f"失败：{(err or out)[:300]}")

        script = (
            "Set-NetFirewallProfile -Profile Domain,Private,Public "
            "-DefaultOutboundAction Allow -ErrorAction SilentlyContinue;"
            f"Remove-NetFirewallRule -Group '{GROUP}_FAILCLOSED' -ErrorAction SilentlyContinue;"
            "Write-Output 'OK'")
        ok, out, err = _run_ps(script, timeout=60)
        self.bus.action(severity="medium", code="FAILCLOSED_OFF",
                        title="隧道恢复 → 熔断已解除",
                        detail="出站默认策略已恢复 Allow" if ok else f"失败：{err or out}")
        return ActionResult(ok, "fail_closed", "全局",
                            "已解除熔断" if ok else f"失败：{err or out}")

    # ---- 清理 ---------------------------------------------------------

    def list_rules(self) -> list[dict]:
        ok, out, err = _run_ps(
            f"Get-NetFirewallRule -Group '{GROUP}','{GROUP}_STRICT_ALLOW' -ErrorAction SilentlyContinue | "
            "Select-Object Name,DisplayName,Enabled,Direction,Action | ConvertTo-Json -Compress",
            timeout=30)
        if not ok or not out:
            return []
        try:
            d = json.loads(out)
            return d if isinstance(d, list) else [d]
        except Exception:
            return []

    def remove_all_rules(self) -> ActionResult:
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "remove_all", "", why)
        script = (
            "Set-NetFirewallProfile -Profile Domain,Private,Public "
            "-DefaultOutboundAction Allow -ErrorAction SilentlyContinue;"
            f"Remove-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue;"
            f"Remove-NetFirewallRule -Group '{GROUP}_STRICT_ALLOW' -ErrorAction SilentlyContinue;"
            f"Remove-NetFirewallRule -Group '{GROUP}_FAILCLOSED' -ErrorAction SilentlyContinue;"
            "Get-NetFirewallRule -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Name -like 'EgressGuard::*' } | "
            "Remove-NetFirewallRule -ErrorAction SilentlyContinue;"
            "Write-Output 'OK'")
        ok, out, err = _run_ps(script, timeout=90)
        with self._lock:
            self._created.clear()
            self._target_hits.clear()
        self._default_outbound_flipped = False
        self.bus.action(severity="medium", code="RULES_CLEARED", title="已清除全部闸门规则",
                        detail="防火墙默认策略恢复 Allow，EgressGuard 规则全部删除")
        return ActionResult(ok, "remove_all", "全部规则",
                            "已清除" if ok else f"失败：{err or out}")

    def panic_restore(self) -> ActionResult:
        """紧急恢复：把网络无条件还回来。仪表盘上的红色按钮调这个。"""
        return self.remove_all_rules()

    # ---- 进程终结 -----------------------------------------------------

    def kill_process(self, pid: int, reason: str = "") -> ActionResult:
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "kill_process", str(pid), why)
        try:
            p = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                               capture_output=True, timeout=15,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            ok = p.returncode == 0
            msg = (p.stdout or b"").decode("gbk", "replace").strip() or \
                  (p.stderr or b"").decode("gbk", "replace").strip()
            self.bus.action(severity="high", code="KILL_PROC", title="已终结违规进程",
                            detail=f"PID {pid} 已终结。原因：{reason}", pid=pid, reason=reason)
            return ActionResult(ok, "kill_process", str(pid), msg)
        except Exception as e:
            return ActionResult(False, "kill_process", str(pid), f"失败：{e}")

    # ---- 网络设置微调 -------------------------------------------------

    def neutralize_dhcp_hostname(self, neutral: str = "HOST") -> ActionResult:
        """把 DHCP 主机名改成中性名，避免每次拿 IP 时把主机名递给路由器/ISP。"""
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "dhcp_hostname", "", why)
        script = (
            "$k='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters';"
            f"Set-ItemProperty -Path $k -Name 'NV Hostname' -Value '{neutral}' -ErrorAction SilentlyContinue;"
            f"Set-ItemProperty -Path $k -Name 'Hostname' -Value '{neutral}' -ErrorAction SilentlyContinue;"
            "Write-Output 'OK'")
        ok, out, err = _run_ps(script)
        return ActionResult(ok, "dhcp_hostname", neutral,
                            f"DHCP 主机名已改为 {neutral}（重启网卡或重启系统后生效）"
                            if ok else f"失败：{err or out}")

    def disable_ipv6_on_adapter(self, alias: str) -> ActionResult:
        """直接在物理网卡上关掉 IPv6 协议绑定——比防火墙规则更彻底。"""
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "disable_ipv6", alias, why)
        ok, out, err = _run_ps(
            f"Disable-NetAdapterBinding -Name '{alias}' -ComponentID ms_tcpip6 "
            f"-ErrorAction Stop; Write-Output 'OK'", timeout=40)
        self.bus.action(severity="medium" if ok else "high", code="IPV6_OFF",
                        title=f"关闭 {alias} 的 IPv6",
                        detail="已关闭 IPv6 协议绑定" if ok else f"失败：{err or out}")
        return ActionResult(ok, "disable_ipv6", alias,
                            f"已关闭 {alias} 的 IPv6" if ok else f"失败：{err or out}")

    def restore_ipv6_on_adapter(self, alias: str) -> ActionResult:
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "enable_ipv6", alias, why)
        ok, out, err = _run_ps(
            f"Enable-NetAdapterBinding -Name '{alias}' -ComponentID ms_tcpip6 "
            f"-ErrorAction Stop; Write-Output 'OK'", timeout=40)
        return ActionResult(ok, "enable_ipv6", alias,
                            f"已恢复 {alias} 的 IPv6" if ok else f"失败：{err or out}")

    def set_adapter_dns(self, alias: str, servers: list[str] | None) -> ActionResult:
        """设置/清空网卡 DNS。清空后该网卡不再自行解析，减少 DNS 泄漏面。"""
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "set_dns", alias, why)
        if servers:
            arg = ",".join(f"'{s}'" for s in servers)
            body = (f"Set-DnsClientServerAddress -InterfaceAlias '{alias}' "
                    f"-ServerAddresses @({arg}) -ErrorAction Stop")
        else:
            body = (f"Set-DnsClientServerAddress -InterfaceAlias '{alias}' "
                    f"-ResetServerAddresses -ErrorAction Stop")
        ok, out, err = _run_ps(body + "; Write-Output 'OK'", timeout=40)
        return ActionResult(ok, "set_dns", alias,
                            f"{alias} 的 DNS 已更新" if ok else f"失败：{err or out}")

    # ---- 结构性泄漏自动修复（v1.1.0）-----------------------------------

    def _remediation_path(self):
        from .config import DATA_DIR
        return DATA_DIR / "remediation.json"

    def _load_remediation(self) -> dict:
        try:
            import json as _j
            p = self._remediation_path()
            if p.exists():
                return _j.loads(p.read_text(encoding="utf-8-sig"))
        except Exception:
            pass
        return {}

    def _save_remediation(self, d: dict) -> None:
        try:
            import json as _j
            p = self._remediation_path()
            tmp = p.with_name("remediation.json.tmp")
            tmp.write_text(_j.dumps(d, ensure_ascii=False, indent=2),
                           encoding="utf-8")
            os.replace(tmp, p)
        except Exception:
            pass

    def remediate_ipv6(self, physical_aliases: list[str]) -> ActionResult:
        """物理网卡上出现全局 IPv6 -> 装规则封掉它的全球单播出站。

        为什么用防火墙规则而不是直接关 IPv6 协议绑定：
        关绑定更彻底，但会让用户"上不了 IPv6 的网"这件事变得不可见
        （网卡属性里 IPv6 直接消失，用户不知道为什么）。
        装规则的话，仪表盘上能看到"有一条规则在挡 IPv6"，
        而且随时可以一键恢复。
        """
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "remediate_ipv6", "", why)
        if not physical_aliases:
            return ActionResult(False, "remediate_ipv6", "", "没有物理网卡")
        res = [r for r in self.install_static_rules(physical_aliases)
               if r.kind == "rule_ipv6"]
        r = res[0] if res else ActionResult(False, "remediate_ipv6", "", "未产生规则")
        if r.ok:
            d = self._load_remediation()
            d["ipv6"] = {"ts": time.time(),
                         "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                         "aliases": list(physical_aliases),
                         "how": "防火墙规则封杀 IPv6 全球单播 (2000::/3)"}
            self._save_remediation(d)
        return r

    def remediate_dns(self, alias: str, tunnel_dns: str,
                      current: list[str] | None = None) -> ActionResult:
        """把物理网卡的 DNS 指向隧道解析器。

        为什么指向隧道 DNS 而不是置空：
        置空会让该网卡完全没有解析能力，隧道一断就连名字都解析不了，
        用户会觉得"网络坏了"却看不出原因。
        指向隧道 DNS（198.18.0.2）的话：
          - 隧道在 -> 正常解析，且查询走隧道，不泄漏
          - 隧道断 -> 解析失败，这正是我们要的 fail-closed
        原值会记进 remediation.json，可一键恢复。
        """
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "remediate_dns", alias, why)
        if not tunnel_dns:
            return ActionResult(False, "remediate_dns", alias,
                                "没有可用的隧道 DNS，跳过（宁可不改，也不乱指）")
        r = self.set_adapter_dns(alias, [tunnel_dns])
        if r.ok:
            d = self._load_remediation()
            prev = d.get("dns", {})
            prev[alias] = {"ts": time.time(),
                           "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                           "original": list(current or []),
                           "now": [tunnel_dns]}
            d["dns"] = prev
            self._save_remediation(d)
            self.bus.action(
                severity="medium", code="REMEDIATE_DNS",
                title=f"已把 {alias} 的 DNS 指向隧道",
                detail=f"原值 {current or '（空）'} -> {tunnel_dns}。"
                       f"隧道在就正常解析且不泄漏；隧道断则解析失败（fail-closed）。"
                       f"原值已记录，可在仪表盘一键恢复。")
        return r

    def rollback_remediation(self) -> ActionResult:
        """把自动修复过的东西恢复原状。"""
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "rollback", "", why)
        d = self._load_remediation()
        msgs = []
        for alias, info in (d.get("dns") or {}).items():
            orig = info.get("original") or []
            r = self.set_adapter_dns(alias, orig if orig else None)
            msgs.append(f"{alias} DNS -> {orig or '（恢复为自动获取）'}："
                        f"{'成功' if r.ok else r.detail}")
        if d.get("ipv6"):
            r = self.remove_all_rules()
            msgs.append(f"清除 IPv6 封堵规则：{'成功' if r.ok else r.detail}")
        self._save_remediation({})
        self.bus.action(severity="medium", code="REMEDIATE_ROLLBACK",
                        title="已回滚自动修复", detail="；".join(msgs) or "没有需要回滚的项")
        return ActionResult(True, "rollback", "", "；".join(msgs) or "没有需要回滚的项")

    # ---- 引导到隧道 ---------------------------------------------------

    def list_bypass_routes(self, tunnel_if_indexes: list[int] | None = None
                           ) -> list[dict]:
        """列出所有"绕过隧道"的具体主机路由。

        这是"把流量导回 VPN 出口"唯一在用户态可行的抓手。

        实测结论（tests/exp_guide_to_tunnel.py）：
          - 程序**按路由表走**时，路由指向哪个接口，源地址就是哪个接口的地址。
            删掉那条指向物理网卡的主机路由，它重连就自动进隧道了 —— 实测有效。
          - 程序**显式 bind 了物理网卡地址**时，路由改不改都没用，源地址不变。
            这种只能掐断。

        所以：把"绕过路由"清掉，能让 A 类程序回到隧道；B 类靠掐断。
        两者合起来就是能做的全部。
        """
        okp, why = self._guard()
        if not okp:
            return []
        # 只挑"具体主机路由 + 下一跳不是 0.0.0.0 + 目标是公网"的那些。
        # 默认路由（0.0.0.0/0）、内网路由、链路本地都不算"绕过"。
        script = (
            "$tun = @(" + ",".join(str(i) for i in (tunnel_if_indexes or [])) + ");"
            "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object { "
            "  $_.NextHop -ne '0.0.0.0' -and "
            "  ($tun.Count -eq 0 -or $tun -notcontains $_.InterfaceIndex) -and "
            "  $_.DestinationPrefix -notmatch "
            "    '^(0\\.0\\.0\\.0/0|127\\.|10\\.|192\\.168\\.|169\\.254\\.|"
            "224\\.|240\\.|255\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)' "
            "} | ForEach-Object { [PSCustomObject]@{ "
            "  Dest=$_.DestinationPrefix; NextHop=$_.NextHop; "
            "  IfIndex=$_.InterfaceIndex; Alias=$_.InterfaceAlias; "
            "  Metric=$_.RouteMetric } } | ConvertTo-Json -Compress"
        )
        ok, out, err = _run_ps(script, timeout=40)
        if not ok or not out.strip():
            return []
        try:
            d = json.loads(out)
            return d if isinstance(d, list) else [d]
        except Exception:
            return []

    def remove_bypass_route(self, dest_prefix: str) -> ActionResult:
        """删掉一条绕过隧道的路由。

        删掉之后，那个目标的流量会重新落回默认路由 —— 也就是 TUN。
        对"按路由表走"的程序，这等于把它**导回 VPN 出口**。
        """
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "remove_bypass_route", dest_prefix, why)
        ip = (dest_prefix or "").split("/")[0]
        if not ip:
            return ActionResult(False, "remove_bypass_route", dest_prefix, "目标为空")
        ok, out, err = _run_ps(
            f"route delete {ip} 2>$null | Out-Null; Write-Output 'OK'", timeout=25)
        if ok:
            self.bus.action(
                severity="medium", code="ROUTE_REMOVED",
                title=f"已删除绕过隧道的路由：{dest_prefix}",
                detail="删掉之后该目标的流量会重新走默认路由（即 TUN）。"
                       "对按路由表走的程序，这等于把它导回了 VPN 出口。",
                remote=ip)
            return ActionResult(True, "remove_bypass_route", dest_prefix,
                                f"已删除 {dest_prefix}，该目标流量将重新走隧道")
        return ActionResult(False, "remove_bypass_route", dest_prefix,
                            f"删除失败：{err or out}")

    def guide_target_to_tunnel(self, remote_ip: str,
                               tunnel_if_indexes: list[int] | None = None
                               ) -> ActionResult:
        """把某个目标"导回隧道"：删掉所有指向该目标、且绕过隧道的路由。

        实测有效（见 list_bypass_routes 的说明）：
        删掉路由后，不显式 bind 的程序重连时源地址会变成隧道地址（198.18.x.x）。
        显式 bind 的程序不受影响 —— 那种只能靠掐断。
        """
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "guide_target", remote_ip, why)
        routes = [r for r in self.list_bypass_routes(tunnel_if_indexes)
                  if (r.get("Dest") or "").split("/")[0] == remote_ip]
        if not routes:
            return ActionResult(True, "guide_target", remote_ip,
                                f"{remote_ip} 没有绕过隧道的路由 —— "
                                f"它的流量本来就该走 TUN。"
                                f"如果它仍在裸奔，说明是程序显式绑定了物理网卡，"
                                f"这种情况用户态无法改道，只能掐断。")
        msgs = []
        for r in routes:
            res = self.remove_bypass_route(r.get("Dest") or "")
            msgs.append(f"{r.get('Dest')}（下一跳 {r.get('NextHop')} / "
                        f"{r.get('Alias')}）：{'成功' if res.ok else res.detail}")
        return ActionResult(True, "guide_target", remote_ip,
                            f"已删除 {len(routes)} 条绕过路由：" + "；".join(msgs))

    def remove_all_bypass_routes(self, tunnel_if_indexes: list[int] | None = None
                                 ) -> ActionResult:
        """一键清掉所有绕过隧道的具体主机路由。"""
        routes = self.list_bypass_routes(tunnel_if_indexes)
        if not routes:
            return ActionResult(True, "remove_all_bypass",
                                "全部", "没有发现绕过隧道的路由")
        okn = 0
        for r in routes:
            if self.remove_bypass_route(r.get("Dest") or "").ok:
                okn += 1
        self.bus.action(severity="medium", code="ROUTES_CLEARED",
                        title=f"已清理 {okn}/{len(routes)} 条绕过隧道的路由",
                        detail="清理后，原本被这些路由带出隧道的流量会重新走 TUN。")
        return ActionResult(okn > 0, "remove_all_bypass", "全部",
                            f"已删除 {okn}/{len(routes)} 条绕过路由")

    def detect_tunnel_proxy(self) -> str | None:
        """探测本机隧道客户端提供的本地代理端口。

        常见约定：clash/mihomo 7890(混合) / 7891(http) / 7897，v2ray 10808/10809，
        v2rayN 10809，sing-box 2080，ss 1080。取第一个能连上的。
        """
        import socket
        cands = [(7890, "混合"), (7897, "混合"), (7891, "HTTP"), (10809, "HTTP"),
                 (10808, "SOCKS"), (1080, "SOCKS"), (2080, "混合"), (8080, "HTTP")]
        for port, kind in cands:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.35)
            try:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    return f"127.0.0.1:{port}"
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        return None

    def set_system_proxy(self, server: str | None = None) -> ActionResult:
        """把系统代理（WinINET）指向隧道客户端的本地端口。

        ⚠ 这**不是**"把已建立的泄漏连接改道进隧道" —— 那件事在用户态做不到：
           一条显式绑定了物理网卡的连接根本不进 TUN，没有 API 能把它转进去。
           真正的"引导"是两件事：
             1. 掐断 → 逼它重连（重连时不显式 bind 就会走 TUN，自然进隧道）
             2. 把系统代理指向隧道端口，让支持系统代理的程序主动走隧道

        这个方法做的是第 2 件。生效范围：浏览器、以及任何读 WinINET 设置的程序。
        不生效：自己管网络栈的程序（多数国产 IM、游戏、以及显式绑网卡的程序）。
        """
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "set_system_proxy", "", why)

        if not server:
            server = self.detect_tunnel_proxy()
        if not server:
            return ActionResult(False, "set_system_proxy", "",
                                "没探测到隧道客户端的本地代理端口"
                                "（试过 7890/7897/7891/10809/10808/1080/2080）。"
                                "iKuuu 若是纯 TUN 模式可能不开本地端口，"
                                "这种情况系统代理这条路走不通。")

        script = (
            "$k='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';"
            f"Set-ItemProperty -Path $k -Name 'ProxyServer' -Value '{server}' -ErrorAction Stop;"
            "Set-ItemProperty -Path $k -Name 'ProxyEnable' -Value 1 -Type DWord -ErrorAction Stop;"
            # 通知 WinINET 设置已变，否则已启动的程序不会重新读取
            "try {"
            "  $sig='[DllImport(\"wininet.dll\")] public static extern bool "
            "InternetSetOption(IntPtr h, int o, IntPtr b, int l);';"
            "  $t=Add-Type -MemberDefinition $sig -Name WI -Namespace EG -PassThru;"
            "  [void]$t::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0);"
            "  [void]$t::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0);"
            "} catch {};"
            "Write-Output 'OK'")
        ok, out, err = _run_ps(script, timeout=40)
        self.bus.action(severity="medium" if ok else "high", code="SYS_PROXY",
                        title="系统代理指向隧道" if ok else "系统代理设置失败",
                        detail=(f"已把系统代理设为 {server}。"
                                f"浏览器等读系统代理的程序会走隧道；"
                                f"自己管网络栈的程序不受影响。")
                        if ok else f"失败：{err or out}")
        return ActionResult(ok, "set_system_proxy", server,
                            f"系统代理已指向 {server}（浏览器等会走隧道）" if ok
                            else f"失败：{err or out}")

    def clear_system_proxy(self) -> ActionResult:
        okp, why = self._guard()
        if not okp:
            return ActionResult(False, "clear_system_proxy", "", why)
        script = (
            "$k='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';"
            "Set-ItemProperty -Path $k -Name 'ProxyEnable' -Value 0 -Type DWord "
            "-ErrorAction SilentlyContinue;"
            "try {"
            "  $sig='[DllImport(\"wininet.dll\")] public static extern bool "
            "InternetSetOption(IntPtr h, int o, IntPtr b, int l);';"
            "  $t=Add-Type -MemberDefinition $sig -Name WI2 -Namespace EG2 -PassThru;"
            "  [void]$t::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0);"
            "} catch {};"
            "Write-Output 'OK'")
        ok, out, err = _run_ps(script, timeout=40)
        return ActionResult(ok, "clear_system_proxy", "",
                            "系统代理已关闭" if ok else f"失败：{err or out}")

    # ---- 状态 ---------------------------------------------------------

    def status(self) -> dict:
        return {
            "is_admin": self._admin,
            "rules_created": sorted(self._created),
            "default_outbound_flipped": self._default_outbound_flipped,
            "firewall": self.firewall_state(),
        }
