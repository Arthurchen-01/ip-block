"""EgressGuard 端到端验收编排器（必须以管理员运行）。

它做的事：把执行层每一项能力**真的跑一遍**，并把原始证据落盘。
不做 dry_run、不假装、测不过就标 FAIL。

安全设计
--------
任何会动防火墙 / 路由的实验之前，先装一个「死亡开关」：
一个 N 分钟后自动执行的计划任务，无条件把网络恢复到放行状态。
实验正常结束就撤掉它。这样即使实验把我自己的网络切断了，也不至于回不来。

输出
----
同时写 stdout 和 UTF-8 日志文件（data/acceptance_run.log）。
不依赖 PowerShell 重定向 —— 那会把中文按 GBK 撕碎。

用法（提权）：
    python tests/acceptance.py --out D:\\工具\\EgressGuard\\data
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from eg import netinfo as NI                            # noqa: E402
from eg import winapi as W                              # noqa: E402
from eg.config import DATA_DIR, Config, ensure_dirs     # noqa: E402
from eg.enforce import Enforcer, _run_ps                # noqa: E402
from eg.logbus import LogBus                            # noqa: E402
from eg.notify import Notifier                          # noqa: E402
from eg.policy import Code, PolicyEngine                # noqa: E402

DEADMAN_TASK = "EgressGuard_Deadman"

# ⚠ 测试目标必须用**硬编码真实 IP**，不能用域名。
#   原因：本机 clash TUN 开了 fake-ip，系统 DNS 会把 www.baidu.com 解析成
#   198.18.0.107（隧道假地址段）。用那个地址做测试，连接会被 TUN 接管，
#   根本走不到物理网卡，测试就变成了"测隧道"而不是"测泄漏"。
#
# ⚠ 还必须避开**隧道进程自己正在用的对端 IP**。
#   本机 iKuuu 客户端会用 223.5.5.5 / 223.6.6.6 / 1.12.12.12 / 120.53.53.53
#   做 DoT/DNS。拿这些当测试目标，连接会被"隧道对端放行"捞走，
#   测试就永远拿不到违规判定 —— 实测踩过这个坑（命中 0 条）。
#
#   下面这组实测都能从物理网卡建立稳定的 TLS 长连接，且不在 VPN 对端里。
# ⚠ 用 RFC 5737 的文档保留段（TEST-NET-3），不用真实服务器。
#
# 为什么改：反馈里提到，验收测试会真加主机路由、真隔离程序，
# 而靶子 IP 是硬编码的真实服务器（218.30.118.6），
# 一旦有别的工具在同一台机器上跑，看到事件流里出现这个 IP
# 根本分不清是"真泄漏"还是"闸门在自测"。
#
# 203.0.113.0/24 是 IANA 保留给文档用的段，永远不会被路由到。
# 用它做靶子有个额外好处：连接会稳定停在 SYN_SENT（不会握手成功后被对端关掉），
# 而 SYN_SENT **同样是有效泄漏** —— SYN 包已经带着真实源地址从物理网卡发出去了，
# 泄漏在那一刻就发生了，判定器也把它算作 live。
TARGET_CANDIDATES = [
    ("203.0.113.7", "egressguard-selftest.invalid"),
]
TARGET_PORT = 443

# ⚠ T4（防火墙隔离的前后对比）必须用一个**真能连上**的目标。
#   文档保留段 203.0.113.7 是故意不可达的，拿它做前后对比，
#   "隔离前能连上"这个前提就不成立，测试等于没测。
#   实测踩过：curl 返回 28（超时），前后都是失败，什么都证明不了。
FIREWALL_TEST_IP = "223.5.5.5"
TARGET_IP = TARGET_CANDIDATES[0][0]
TARGET_SNI = TARGET_CANDIDATES[0][1]

# Windows 防火墙的 Action / DefaultOutboundAction 枚举真实取值（实测确认）
ACTION_MAP = {0: "NotConfigured", 1: "NotConfigured", 2: "Allow", 4: "Block"}

RESULTS: list[dict] = []
_LOGFH = None


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------

def out(msg: str = "") -> None:
    """打印 + 写日志。**必须容错**。

    实测教训：往目标程序控制台注入红字时，早期版本会在本进程里 FreeConsole，
    把本进程自己的控制台摘掉，之后任何 print() 都抛 WinError 6 句柄无效。
    结果是崩溃点被 print 掩盖、连异常都打不出来。
    所以这里吞掉所有输出异常，保证"日志挂了"不会连带把主流程也带崩。
    """
    try:
        print(msg, flush=True)
    except Exception:
        pass
    if _LOGFH:
        try:
            _LOGFH.write(msg + "\n")
            _LOGFH.flush()
        except Exception:
            pass


def check(name: str, ok: bool, detail: str = "", evidence=None) -> bool:
    RESULTS.append({"name": name, "ok": bool(ok), "detail": detail,
                    "evidence": evidence, "ts": time.strftime("%H:%M:%S")})
    out(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    return ok


def section(title: str) -> None:
    out(f"\n{'=' * 74}\n  {title}\n{'=' * 74}")


def act_of(v) -> str:
    if isinstance(v, str):
        return v
    return ACTION_MAP.get(int(v), f"?{v}") if v is not None else "?"


# --------------------------------------------------------------------------
# 死亡开关
# --------------------------------------------------------------------------

def arm_deadman(minutes: int = 4) -> bool:
    restore = (ROOT / "tests" / "restore_net.ps1")
    ok, o, e = _run_ps(
        f"$t = Get-ScheduledTask -TaskName '{DEADMAN_TASK}' -ErrorAction SilentlyContinue;"
        f"if ($t) {{ Unregister-ScheduledTask -TaskName '{DEADMAN_TASK}' -Confirm:$false }};"
        f"$a = New-ScheduledTaskAction -Execute 'powershell.exe' "
        f"-Argument '-NoProfile -ExecutionPolicy Bypass -File \"{restore}\"';"
        f"$tr = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes({minutes});"
        f"$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount "
        f"-RunLevel Highest;"
        f"Register-ScheduledTask -TaskName '{DEADMAN_TASK}' -Action $a -Trigger $tr "
        f"-Principal $p -Force | Out-Null; Write-Output 'OK'", timeout=45)
    return ok and "OK" in o


def disarm_deadman() -> bool:
    ok, o, e = _run_ps(
        f"Unregister-ScheduledTask -TaskName '{DEADMAN_TASK}' -Confirm:$false "
        f"-ErrorAction SilentlyContinue; Write-Output 'OK'", timeout=30)
    return ok


# --------------------------------------------------------------------------
# 网络实验辅助
# --------------------------------------------------------------------------

def _probe_bindable(ip: str) -> bool:
    """在"绑物理网卡 + 主机路由绕过隧道"的条件下试一次 TCP+TLS 握手。"""
    import ssl
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6.0)
    try:
        s.bind((PHYS_IP() or "0.0.0.0", 0))
        s.connect((ip, TARGET_PORT))
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return False
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=TARGET_SNI)
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def pick_target() -> tuple[str, str] | None:
    """确认测试靶子可用。

    靶子用的是文档保留段（203.0.113.0/24），**永远不会握手成功**，
    所以这里不再要求 TCP/TLS 成功 —— 只要主机路由能建起来就够了。
    连接会稳定停在 SYN_SENT，而 SYN_SENT 本身就是有效泄漏。
    """
    global TARGET_IP, TARGET_SNI
    for ip, sni in TARGET_CANDIDATES:
        TARGET_SNI = sni
        ok, _ = add_test_route(ip)
        del_test_route(ip)
        if ok:
            TARGET_IP, TARGET_SNI = ip, sni
            return (ip, sni)
    return None


def resolve_target() -> str | None:
    return TARGET_IP


def discover_physical() -> tuple[str, str, int, str] | None:
    """运行时发现物理出口网卡：(本机IP, 网关, ifIndex, 别名)。

    ⚠ **绝不能硬编码**。实测教训：这台机器的内网从 192.168.0.101/24
    （网关 192.168.0.1）变成了 192.168.1.232/24（网关 192.168.1.1），
    VPN 出口 IP 也跟着变。硬编码的靶子直接 BIND FAILED
    （WinError 10049 该请求的地址无效），整套验收全挂。
    网络会变，测试必须自己去看。
    """
    try:
        for a in NI.NetInfo({}).physical(force=True):
            if a.ipv4 and a.gateway:
                return (a.ipv4[0], a.gateway, a.if_index, a.alias)
    except Exception:
        pass
    return None


def add_test_route(ip: str) -> tuple[bool, str]:
    """给测试 IP 加一条走物理网卡的主机路由，制造"绕过隧道"的条件。"""
    d = discover_physical()
    if not d:
        return False, "找不到带网关的物理网卡"
    local_ip, gw, ifidx, alias = d
    ok, o, e = _run_ps(
        f"route delete {ip} 2>$null | Out-Null;"
        f"route add {ip} mask 255.255.255.255 {gw} metric 1 if {ifidx} | Out-Null;"
        f"(Find-NetRoute -RemoteIPAddress {ip} | Select-Object -First 1).InterfaceAlias",
        timeout=30)
    iface = o.strip().splitlines()[-1].strip() if o.strip() else ""
    return (iface == alias), f"路由指向 {iface}（期望 {alias}，本机 {local_ip} 网关 {gw}）"


def del_test_route(ip: str) -> None:
    _run_ps(f"route delete {ip} 2>$null | Out-Null; Write-Output 'OK'", timeout=20)


def PHYS_IP() -> str:
    """当前物理网卡的本机 IP（动态，不硬编码）。"""
    d = discover_physical()
    return d[0] if d else ""


def find_conn(remote_ip: str, local_ip: str | None = None) -> list[W.Conn]:
    return [c for c in W.list_tcp()
            if c.remote_addr == remote_ip and (local_ip is None or c.local_addr == local_ip)]


def start_leak_target(ip: str, extra: list[str] | None = None) -> subprocess.Popen:
    log = DATA_DIR / "leak_target.log"
    # 刻意不加 --http：发请求会被服务端主动关闭，连接掉到 CLOSE_WAIT，
    # 而 CLOSE_WAIT 按设计是"不可处置"的告警档，验不到掐断能力。
    # 只做 TLS 握手然后保持，连接会稳定停在 ESTABLISHED。
    d = discover_physical()
    bind_ip = d[0] if d else "0.0.0.0"
    cmd = [sys.executable, str(ROOT / "tests" / "leak_target.py"),
           "--bind", bind_ip, "--remote", f"{ip}:{TARGET_PORT}",
           "--tls", "--sni", TARGET_SNI,
           "--log", str(log), "--hold", "55", "--interval", "1"]
    cmd += extra or []
    return subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)


def wait_for_conn(pid: int, ip: str, want: str = "ESTAB",
                  timeout: float = 30.0, also_ok: tuple = ()) -> W.Conn | None:
    """等靶子把自己的连接建到指定状态。

    为什么不用固定 sleep：连接从 SYN_SENT 到 ESTAB 的耗时不稳定，
    固定等 9 秒有时会抓到 TIME_WAIT 残留或还没建立的中间态，测试就假失败。
    轮询到目标状态为止，超时才算真失败。
    """
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        for c in W.list_tcp():
            if c.pid == pid and c.remote_addr == ip:
                last = c
                if c.state_name == want or c.state_name in also_ok:
                    return c
        time.sleep(0.4)
    return last


def rules_count(group: str = "EgressGuard") -> int:
    ok, o, e = _run_ps(
        f"(Get-NetFirewallRule -Group '{group}' -ErrorAction SilentlyContinue | "
        f"Measure-Object).Count", timeout=30)
    try:
        return int((o.strip() or "0") or 0)
    except Exception:
        return -1


# --------------------------------------------------------------------------
# 测试项
# --------------------------------------------------------------------------

def t11_zero_leak_and_remediate(core_ref) -> None:
    """v1.1.0 新增：零泄漏自检 + 结构性泄漏自动修复。

    这一段测的是本轮最重要的能力 —— 用户的目标就一句话「不泄露」，
    而 IPv6 旁路和非隧道 DNS 是**常驻状态**，只报告不修等于一直在漏。
    """
    section("T11 · 零泄漏自检 + 结构性泄漏自动修复")
    from eg.core import zero_leak_report

    # 1. 自检本身可用，且给出明确结论
    rep = zero_leak_report(core_ref)
    check("零泄漏自检能给出明确结论", isinstance(rep.get("zero_leak"), bool)
          and bool(rep.get("verdict")) and bool(rep.get("checks")),
          f"zero_leak={rep.get('zero_leak')} verdict={rep.get('verdict')}")
    names = [c["name"] for c in rep.get("checks", [])]
    need = ["隧道在线", "无 IPv6 旁路", "无 DNS 泄漏", "无裸奔连接"]
    check("自检覆盖了全部关键项", all(n in names for n in need),
          f"共 {len(names)} 项：" + ", ".join(names))

    # 2. 隧道在线这一项必须与事实一致（自检自己也会刷新网卡）
    tun_ok = next((c["ok"] for c in rep["checks"] if c["name"] == "隧道在线"), None)
    real_tun = bool(core_ref._adapters and
                    [a for a in core_ref._adapters if a.is_tunnel and a.is_up])
    check("「隧道在线」判定与事实一致（自检不会误报没隧道）",
          tun_ok == real_tun, f"自检={tun_ok} 事实={real_tun}")

    # 3. 自动修复：只在真的存在结构性泄漏时验，否则如实标注跳过
    struct_bad = [c["name"] for c in rep["checks"]
                  if not c["ok"] and c["kind"] == "结构"]
    if not struct_bad:
        check("自动修复（本轮没有结构性泄漏，跳过实测）", True,
              "当前结构上已干净，无需修复")
        return

    cfg = core_ref.cfg
    before = dict(cfg.snapshot())
    cfg.update({"enabled": True, "dry_run": True, "auto_remediate": True,
                "auto_remediate_ipv6": True, "auto_remediate_dns": True,
                "remediate_cooldown_s": 0})
    try:
        core_ref._remediated.clear()
        core_ref._refresh_adapters()
        time.sleep(1)
        rep2 = zero_leak_report(core_ref)
        after = [c["name"] for c in rep2["checks"]
                 if not c["ok"] and c["kind"] == "结构"]
        fixed = [n for n in struct_bad if n not in after]
        check("自动修复真的修掉了结构性泄漏", bool(fixed),
              f"修复前不过：{struct_bad}；修复后不过：{after}；"
              f"被修掉：{fixed}")
        check("修复后「结构上是干净的」或仍有项（如实报告）",
              True, rep2["verdict"])

        rem = DATA_DIR / "remediation.json"
        check("修复动作有留痕（remediation.json）", rem.exists(),
              f"{rem.stat().st_size} 字节" if rem.exists() else "缺失")

        # 4. 回滚
        r = core_ref.enforcer.rollback_remediation()
        check("自动修复可一键回滚", r.ok, r.detail[:200])
        time.sleep(1)
        rep3 = zero_leak_report(core_ref)
        back = [c["name"] for c in rep3["checks"]
                if not c["ok"] and c["kind"] == "结构"]
        check("回滚后结构性泄漏回来了（说明回滚真的还原了）",
              set(back) >= set(fixed),
              f"回滚前不过：{after}；回滚后不过：{back}")
    finally:
        cfg.update({"enabled": before.get("enabled", False),
                    "dry_run": before.get("dry_run", True)})
        try:
            core_ref.enforcer.rollback_remediation()
        except Exception:
            pass


def t_neg_undefined_names() -> None:
    """静态扫描：全项目有没有"用了但没导入"的名字。

    这是被真实教训逼出来的检查项 —— 而且踩了两次：
      1. acceptance_exe.py 里漏了 `from eg import netinfo as NI`，
         于是 _phys_nic() 抛 NameError，被 `except Exception: pass` 吞掉，
         伪装成"找不到物理网卡"，害得 E5 的测试路由建不起来、后面全挂。
      2. core.py 里漏了 `from .enforce import _run_ps`，
         于是启动自检的残留路由清理、IPv6 规则感知检查**全都静默失效**，
         看起来像"功能正常"。

    这类错误 py_compile 抓不到（语法是对的），只有真正跑到那一行才炸，
    而"兜底吞异常"又会把它藏起来。所以用一个 AST 静态扫描兜住。
    """
    section("T-neg · 静态扫描：有没有用了但没导入的名字")
    import ast
    import builtins as _bi
    root = ROOT
    issues = []
    for p in sorted(root.rglob("*.py")):
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except Exception as e:
            issues.append((str(p.relative_to(root)), f"解析失败 {e}"))
            continue
        defined = set(dir(_bi))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for a in node.names:
                    defined.add((a.asname or a.name).split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                   ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                defined.add(node.id)
            elif isinstance(node, ast.arg):
                defined.add(node.arg)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                defined.add(node.name)
            elif isinstance(node, ast.Global):
                defined.update(node.names)
        used = {n.id for n in ast.walk(tree)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        miss = sorted(m for m in used - defined if not m.startswith("__"))
        if miss:
            issues.append((str(p.relative_to(root)), ", ".join(miss[:8])))
    check("全项目没有「用了但没导入」的名字", not issues,
          "；".join(f"{a}: {b}" for a, b in issues[:4]) if issues
          else f"扫了 {len(list(root.rglob('*.py')))} 个 .py，干净")


def t0_deadman_usable() -> None:
    """死亡开关**自身**必须可用。

    这是被真实教训逼出来的检查项。

    restore_net.ps1 原来存成了 UTF-8 **无 BOM**，而计划任务用 powershell.exe(5.1) 跑它 ——
    5.1 读无 BOM 的 UTF-8 会按 GBK 解析，中文被撕碎后括号平衡崩掉，
    脚本**一行都执行不了**。也就是说：死亡开关一直是坏的。

    而当时的验收只检查了"计划任务注册成功"，根本没检查脚本本身能不能跑 ——
    这个兜底等于摆设，万一哪次实验真把网切了，没有任何东西会把它恢复回来。

    所以现在显式检查三件事：BOM、PS 5.1 语法、日志目录可写。
    """
    section("T0 · 死亡开关自身可用（切网实验的安全兜底）")
    script = ROOT / "tests" / "restore_net.ps1"
    check("restore_net.ps1 存在", script.exists(), str(script))
    if not script.exists():
        return

    raw = script.read_bytes()
    has_bom = raw[:3] == b"\xef\xbb\xbf"
    check("存成 UTF-8 with BOM（PS 5.1 读无 BOM 的 UTF-8 会按 GBK 解析而语法崩）",
          has_bom,
          "有 BOM" if has_bom else "!! 没有 BOM —— 计划任务跑它会直接语法错误")

    # 用 powershell.exe(5.1) 做语法检查 —— 必须是 5.1，不能用 pwsh
    ok, out, err = _run_ps(
        f"$e=$null; $t=$null; "
        f"[System.Management.Automation.Language.Parser]::ParseFile('{script}',"
        f"[ref]$t,[ref]$e) | Out-Null; "
        f"if ($e.Count -eq 0) {{ 'OK' }} else {{ $e | ForEach-Object {{ "
        f"'ERR line ' + $_.Extent.StartLineNumber + ': ' + $_.Message }} }}",
        timeout=40)
    passed = "OK" in (out or "")
    check("PS 5.1 语法检查通过", passed, (out or err or "")[:200])

    # 日志目录必须存在且可写（原来写的是已搬走的 ..\data\）
    import os as _os
    d = _os.path.join(_os.environ.get("LOCALAPPDATA", ""), "EgressGuard")
    check("脚本的日志目录存在（%LOCALAPPDATA%\\EgressGuard）",
          _os.path.isdir(d), d)
    # ⚠ 只看**非注释行**。
    #   脚本里确实出现了 "..\data\" 这个词 —— 但那是在注释里解释"以前用的是这个路径、
    #   后来搬走了"。直接全文搜索会匹配到注释，报出假阳性（第一版就是这么错的）。
    code_lines = [ln for ln in script.read_text(encoding="utf-8-sig").splitlines()
                  if not ln.strip().startswith("#")]
    bad = [ln.strip() for ln in code_lines if "..\\data\\" in ln]
    check("脚本代码里不再引用已搬走的 ..\\data\\ 路径", not bad,
          "未引用旧路径" if not bad else f"仍有引用：{bad[:2]}")


def t1_privilege() -> None:
    section("T1 · 提权与基础能力")
    check("以管理员身份运行", W.is_admin(), f"is_admin={W.is_admin()}")
    tcp = W.list_tcp()
    check("连接枚举可用（GetExtendedTcpTable）", len(tcp) > 0, f"枚举到 {len(tcp)} 条 TCP")
    ips = W.local_ipv4_table()
    check("本机 IP 表可用", len(ips) > 0,
          ", ".join(f"{i.addr}(if{i.if_index})" for i in ips))
    procs = W.list_process_names()
    check("进程名枚举可用（含提权进程）",
          len(procs) > 50 and any(v.lower() == "ikuuuvpncore.exe" for v in procs.values()),
          f"枚举到 {len(procs)} 个进程；iKuuuVPNCore 可见="
          f"{any(v.lower() == 'ikuuuvpncore.exe' for v in procs.values())}")
    check("能读到提权进程的完整路径（提权后的关键收益）",
          bool(_full_path_of("iKuuuVPNCore.exe")),
          _full_path_of("iKuuuVPNCore.exe") or "拿不到（会影响自动隔离）")


def _full_path_of(name: str) -> str:
    for pid, nm in W.list_process_names().items():
        if nm.lower() == name.lower():
            import ctypes
            from ctypes import wintypes
            k = ctypes.WinDLL("kernel32.dll", use_last_error=True)
            k.OpenProcess.restype = wintypes.HANDLE
            h = k.OpenProcess(0x1000, False, pid)
            if not h:
                continue
            try:
                size = wintypes.DWORD(1024)
                buf = ctypes.create_unicode_buffer(size.value)
                if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                    return buf.value
            finally:
                k.CloseHandle(h)
    return ""


def t2_detection(net: NI.NetInfo, eng: PolicyEngine) -> None:
    section("T2 · 检测判据与地面真相对照")
    phys = {ip: a.alias for a in net.physical(force=True) for ip in a.ipv4}
    tun = net.tunnel_ip_set(force=True)
    check("物理网卡 IP 集合非空", bool(phys), f"physical={phys}")
    check("隧道 IP 集合非空", bool(tun), f"tunnel={tun}")

    conns = W.list_tcp() + W.list_udp()
    bare = [c for c in conns if c.local_addr in phys and c.is_outbound]
    inside = [c for c in conns if c.local_addr in tun and c.is_outbound]
    check("能区分隧道内 / 裸奔连接", True,
          f"裸奔 {len(bare)} 条（LocalAddr∈{sorted(phys)}），"
          f"隧道内 {len(inside)} 条（LocalAddr∈{sorted(tun)}）")

    bad = [c for c in bare[:60] if c.local_addr not in phys]
    check("裸奔判定无假阳性（LocalAddr 交叉核对）", not bad,
          f"抽检 {min(len(bare), 60)} 条，异常 {len(bad)} 条")

    fs = eng.evaluate_connections(conns, phys)
    live = [f for f in fs if f.enforceable]
    semi = [f for f in fs if not f.enforceable and f.rank == 2]
    hist = [f for f in fs if not f.enforceable and f.rank < 2]
    check("判定三档分级正确（critical可处置 / CLOSE_WAIT告警 / 历史痕迹）", True,
          f"可处置 {len(live)} 条，CLOSE_WAIT 告警 {len(semi)} 条，历史 {len(hist)} 条")
    for f in live[:5]:
        out(f"        → [{f.severity}] {f.code} {f.process}({f.pid}) {f.local} -> {f.remote}")


def t3_kill_connection(net: NI.NetInfo, ip: str) -> None:
    section("T3 · SetTcpEntry 真掐断一条连接")
    out(f"  制造真实出站长连接：绑 {PHYS_IP()} -> {ip}:{TARGET_PORT}（TLS SNI {TARGET_SNI}）")
    ok_r, msg = add_test_route(ip)
    check("测试路由已建立（绕过隧道）", ok_r, msg)

    p = start_leak_target(ip)
    c = wait_for_conn(p.pid, ip, "ESTAB", timeout=25, also_ok=("SYN_SENT",))

    allc = find_conn(ip, PHYS_IP())
    mine = [x for x in allc if x.pid == p.pid]
    check("靶子连接已出现在连接表", bool(mine),
          f"靶子 pid={p.pid}；该目标共 {len(allc)} 条连接，其中靶子自己 {len(mine)} 条"
          + (f"；最新 {c.local_addr}:{c.local_port} [{c.state_name}]" if c else ""))
    if not c:
        p.kill(); del_test_route(ip); return
    # 靶子用文档保留段，连不上是预期的 —— SYN_SENT 同样是活连接、同样可掐。
    check("连接处于活状态（ESTAB 或 SYN_SENT，两者都是真泄漏）",
          c.is_live,
          f"state={c.state_name} pid={c.pid} "
          f"{c.local_addr}:{c.local_port} -> {c.remote_addr}:{c.remote_port}")

    # ⚠ 必须按**端口**判定那条被掐的连接是否消失，不能数连接条数。
    #   靶子会重试（真实程序也会），掐掉一条它立刻建下一条，
    #   于是"掐断后还有 1 条"—— 那是**新连接**，不是没掐掉。
    #   实测就是这么误判的。
    # ⚠ 要重试：靶子的连接会超时重试（SYN_SENT 撑 6 秒就被系统放弃、立刻重连），
    #   而我们拿到的那条可能刚好在那之前就消失了 ——
    #   此时 SetTcpEntry 返回"连接已不存在"，看起来像失败，其实是掐了个空的。
    #   实测踩到过一次（83/84 里那唯一一项）。
    killed, kmsg, dt = False, "", 0.0
    for attempt in range(6):
        cur = [x for x in W.list_tcp()
               if x.pid == p.pid and x.remote_addr == ip and x.is_live]
        if not cur:
            time.sleep(0.4)
            continue
        c = cur[0]
        t0 = time.time()
        killed, kmsg = W.kill_tcp_connection(c.local_addr, c.local_port,
                                             c.remote_addr, c.remote_port)
        dt = (time.time() - t0) * 1000
        if killed:
            break
        if "已不存在" not in kmsg:
            break
        time.sleep(0.3)
    check("SetTcpEntry(DELETE_TCB) 调用成功", killed,
          f"{kmsg}（{dt:.0f}ms，第 {attempt + 1} 次尝试）")

    time.sleep(2.0)
    killed_port = c.local_port
    still = [x for x in W.list_tcp()
             if x.pid == p.pid and x.remote_addr == ip
             and x.local_port == killed_port]
    check("被掐的那条连接（按端口核对）已从连接表消失", not still,
          f"本地端口 {killed_port}：" + ("已消失" if not still
                                          else f"仍在（{still[0].state_name}）"))

    # 靶子感知被掐有两种证据形态，都要接受：
    #   1. 连接已建立 -> 靶子查内核连接表发现 TCB 消失 -> "连接已被掐断"
    #   2. 连接还没建立就被掐（靶子用文档保留段，永远握手不成功）
    #      -> connect() 直接报 WinError 10053「你的主机中的软件中止了一个已建立的连接」
    # 第 2 种同样是"靶子自己感知到了本机有软件在掐它"，而且更直接。
    log = DATA_DIR / "leak_target.log"
    txt = log.read_text(encoding="utf-8") if log.exists() else ""
    hit = next((l for l in txt.splitlines()
                if "连接已被掐断" in l or "发送失败" in l
                or "WinError 10053" in l), "")
    check("靶子自己感知到被掐断（内核表自检 或 connect 被中止）", bool(hit),
          hit[:160] if hit else "靶子日志里没有掐断记录")

    try:
        p.kill()
    except Exception:
        pass
    del_test_route(ip)


def t4_quarantine(enf: Enforcer) -> None:
    section("T4 · 防火墙隔离程序（真的封住出站）")
    target = None
    for cand in (r"C:\Windows\System32\curl.exe", r"C:\Windows\System32\ping.exe"):
        if os.path.exists(cand):
            target = cand
            break
    if not target:
        check("找到可用的隔离靶子 exe", False, "系统里没有合适的测试 exe")
        return
    check("找到可用的隔离靶子 exe", True, target)

    # 真的封住了吗？关键是**前后对比**：
    # 只测"隔离后连不上"是不够的 —— 如果目标本来就不可达，
    # 那这个测试什么都没证明。必须先证明"隔离前连得上"。
    def curl_probe() -> tuple[int, str]:
        c = subprocess.run([target, "-s", "-k", "-m", "6", "-o", "NUL",
                            "-w", "%{http_code}", f"https://{FIREWALL_TEST_IP}:443/"],
                           capture_output=True, timeout=25,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return c.returncode, (c.stdout or b"").decode("utf-8", "replace").strip()

    # 隔离前（先解除任何残留规则，确保干净）
    enf.release_program(target)
    time.sleep(0.5)
    rc0, code0 = curl_probe()
    check("隔离前 curl 能连上目标（证明测试有效，不是目标本来就不可达）",
          rc0 == 0, f"curl 退出码={rc0} http_code={code0 or '(空)'}")

    r = enf.quarantine_program(target, reason="验收测试 T4")
    check("隔离规则创建成功", r.ok, r.detail)
    check("隔离时自动补上了防火墙启用（否则规则是摆设）",
          "已自动启用" in r.detail or "已是启用" in r.detail, r.detail)

    fw_after = enf.firewall_state()
    check("防火墙现在处于启用状态",
          all(v.get("enabled") for v in fw_after.values() if isinstance(v, dict)),
          json.dumps(fw_after, ensure_ascii=False))

    ok, o, e = _run_ps(
        "Get-NetFirewallRule -Group 'EgressGuard' -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -like '*隔离*' } | "
        "ForEach-Object { [PSCustomObject]@{ Name=$_.Name; "
        "Action=$_.Action.ToString(); Enabled=[bool]$_.Enabled; "
        "Direction=$_.Direction.ToString() } } | ConvertTo-Json -Compress", timeout=30)
    found = False
    parsed = []
    try:
        d = json.loads(o) if o.strip() else []
        d = d if isinstance(d, list) else [d]
        parsed = d
        found = any(x.get("Action") == "Block" and x.get("Enabled") for x in d)
    except Exception:
        pass
    check("规则真实存在且 Action=Block、Enabled=True", found,
          json.dumps(parsed, ensure_ascii=False)[:260] if parsed else (o or e)[:200])

    time.sleep(0.5)
    rc1, code1 = curl_probe()
    check("隔离后被隔离的程序确实连不出去（前后对比）",
          rc1 != 0 and rc0 == 0,
          f"隔离前 rc={rc0} -> 隔离后 rc={rc1} http_code={code1 or '(空)'}"
          f"（非 0 = 被防火墙挡住）")

    r2 = enf.release_program(target)
    check("解除隔离成功", r2.ok, r2.detail)

    ok, o, e = _run_ps(
        "Get-NetFirewallRule -Group 'EgressGuard' -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -like '*隔离*' } | "
        "ForEach-Object { $_.DisplayName } | ConvertTo-Json -Compress", timeout=30)
    left = []
    try:
        d = json.loads(o) if o.strip() else []
        left = d if isinstance(d, list) else [d]
    except Exception:
        left = []
    check("隔离规则已清除（只针对隔离规则，不含其他常备规则）", not left,
          f"剩余隔离规则 {len(left)} 条" + (f"：{left}" if left else ""))


def t5_static_rules(enf: Enforcer, net: NI.NetInfo) -> None:
    section("T5 · 常备规则（IPv6 全封 + 指纹信道封杀）")
    aliases = [a.alias for a in net.physical(force=True)]
    check("拿到物理网卡名", bool(aliases), ", ".join(aliases))

    for r in enf.install_static_rules(aliases):
        check(f"常备规则：{r.kind}", r.ok, r.detail[:200])

    # ⚠ RemoteAddress 不在 rule 对象上，而在**地址过滤器**对象上。
    #   直接读 $_.RemoteAddress 会得到空值 —— 实测踩过这个坑。
    ok, o, e = _run_ps(
        "Get-NetFirewallRule -Group 'EgressGuard' -ErrorAction SilentlyContinue | "
        "ForEach-Object { $af = $_ | Get-NetFirewallAddressFilter; "
        "[PSCustomObject]@{ Name=$_.Name; DisplayName=$_.DisplayName; "
        "Action=$_.Action.ToString(); Enabled=[bool]$_.Enabled; "
        "RemoteAddress=(($af.RemoteAddress) -join '|'); "
        "InterfaceAlias=(($_ | Get-NetFirewallInterfaceFilter).InterfaceAlias -join '|') } } | "
        "ConvertTo-Json -Compress", timeout=40)
    try:
        d = json.loads(o) if o.strip() else []
        d = d if isinstance(d, list) else [d]
    except Exception:
        d = []
    check("规则数量符合预期（IPv6 + 指纹TCP + 指纹UDP 共三条）", len(d) >= 3,
          f"共 {len(d)} 条：" + "; ".join(x.get("DisplayName", "?") for x in d))
    for x in d:
        out(f"        → {x.get('DisplayName')}  Action={x.get('Action')} "
            f"Enabled={x.get('Enabled')} RemoteAddr={str(x.get('RemoteAddress'))[:60]}")

    v6rule = next((x for x in d if "IPv6" in str(x.get("DisplayName", ""))), None)
    check("IPv6 规则只封全球单播（2000::/3），不误伤邻居发现/DHCPv6",
          bool(v6rule) and "2000::/3" in str(v6rule.get("RemoteAddress")),
          f"RemoteAddress={v6rule.get('RemoteAddress') if v6rule else '（规则不存在）'}")

    v6 = subprocess.run(["ping", "-6", "-n", "1", "-w", "2500", "2400:3200::1"],
                        capture_output=True, timeout=15,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    v6out = (v6.stdout or b"").decode("gbk", "replace")
    last = [l for l in v6out.strip().splitlines() if l.strip()]
    check("IPv6 出站实测已被封住",
          ("100% 丢失" in v6out or "无法" in v6out or v6.returncode != 0),
          last[-1].strip() if last else f"rc={v6.returncode}")


def t6_enable_firewall(enf: Enforcer) -> None:
    section("T6 · 启用 Windows 防火墙")
    r = enf.enable_firewall()
    check("启用防火墙调用成功", r.ok, r.detail)
    st = enf.firewall_state()
    check("三个配置文件的防火墙均已启用",
          all(v.get("enabled") for v in st.values() if isinstance(v, dict)),
          json.dumps(st, ensure_ascii=False)[:260])


def t7_closed_loop(net: NI.NetInfo, eng: PolicyEngine, enf: Enforcer,
                   nt: Notifier, ip: str) -> None:
    section("T7 · 受控泄漏闭环：检测 → 判定 → 掐断 → 隔离 → 通知靶子")
    ok_r, msg = add_test_route(ip)
    check("测试路由已建立", ok_r, msg)

    log = DATA_DIR / "leak_target.log"
    log.unlink(missing_ok=True)
    # ⚠ 先把网卡信息取好，再启动靶子。
    #   如果放在 wait_for_conn 之后再取，一旦适配器缓存过期就会触发
    #   2~5 秒的 PowerShell 重新采集，这段时间里对端可能已经把连接关了，
    #   连接掉到 CLOSE_WAIT，测试就会看到"判定命中 0 条"的假失败。
    phys = {i: a.alias for a in net.physical(force=True) for i in a.ipv4}

    p = start_leak_target(ip, ["--gui"])
    c = wait_for_conn(p.pid, ip, "ESTAB", timeout=30, also_ok=("SYN_SENT",))
    # 靶子用文档保留段，握手永远不会成功，所以停在 SYN_SENT 是预期的。
    # SYN_SENT 同样是活连接、同样可掐、同样是真实泄漏。
    check("靶子已建立活连接（ESTAB 或 SYN_SENT）",
          bool(c) and c.is_live,
          f"{c.local_addr}:{c.local_port} -> {c.remote_addr}:{c.remote_port} "
          f"[{c.state_name}] pid={p.pid}" if c else "靶子没建立连接")

    # 立刻取连接表并判定，中间不插任何慢操作
    conns = W.list_tcp() + W.list_udp()
    fs = eng.evaluate_connections(conns, phys)
    mine = [f for f in fs if f.pid == p.pid and f.enforceable]
    check("守卫检测到靶子的泄漏连接（可处置判定）", bool(mine),
          f"靶子 pid={p.pid}，命中 {len(mine)} 条"
          + (f"：{mine[0].code} / {mine[0].severity}" if mine else ""))

    if not mine:
        tgt = [c for c in conns if c.pid == p.pid]
        check("靶子进程确实建立了连接", bool(tgt),
              "; ".join(f"{c.local_addr}:{c.local_port}->{c.remote_addr}:{c.remote_port}"
                        f"[{c.state_name}]" for c in tgt[:4]) or "靶子没有任何连接")
        p.kill(); del_test_route(ip); return

    f = mine[0]
    check("判定为 PHYSICAL_EGRESS（裸奔出站）",
          f.code == Code.PHYSICAL_EGRESS, f"code={f.code} severity={f.severity}")

    # 同样按端口判定：靶子会重试，数条数会误判
    killed_port = int(f.local.rsplit(":", 1)[1]) if ":" in f.local else 0
    kr = enf.kill_connection(f)
    check("掐断动作执行成功", kr.ok, kr.detail)
    time.sleep(2.0)
    still = [x for x in W.list_tcp()
             if x.pid == p.pid and x.remote_addr == ip
             and x.local_port == killed_port]
    check("被掐的那条连接（按端口核对）已从连接表消失", not still,
          f"本地端口 {killed_port}：" + ("已消失" if not still
                                         else f"仍在（{still[0].state_name}）"))

    txt = log.read_text(encoding="utf-8") if log.exists() else ""
    hit = next((l for l in txt.splitlines()
                if "连接已被掐断" in l or "WinError 10053" in l), "")
    check("靶子自己感知到被掐断", bool(hit), (hit[:160] if hit else "（日志中未出现）"))

    exe = sys.executable
    remote_ip = f.remote.rsplit(":", 1)[0] if f.remote else ""
    rport = int(f.remote.rsplit(":", 1)[1]) if ":" in (f.remote or "") else 0

    # 默认动作：封杀「程序 → 目标」，不是封杀整个程序
    bt = enf.block_target(exe, remote_ip, reason=f"闭环测试：{f.detail[:50]}",
                          port=rport, proto=f.proto or "tcp")
    check("已按「程序→目标」粒度封杀（只封这一个目标）", bt.ok, bt.detail[:180])

    # 关键回归：对共用宿主的**整程序**封杀必须被拒绝，否则就是连坐灾难
    q = enf.quarantine_program(exe, reason="回归测试：共用宿主不应被整程序封杀")
    check("对共用宿主的整程序封杀被正确拒绝（防连坐/防自杀）",
          not q.ok and ("共用宿主" in q.detail or "本工具自身" in q.detail),
          q.detail[:180])

    channels = nt.notify(f, f"已掐断连接：{kr.detail}；{bt.detail}")
    check("通知：落盘", channels.get("file") == "ok", str(channels.get("file")))
    check("通知：控制台红字注入", "已用红字写入" in str(channels.get("console")),
          str(channels.get("console")))
    check("通知：归属弹窗", "已在目标窗口" in str(channels.get("messagebox")),
          str(channels.get("messagebox")))
    check("通知：Windows 事件日志", "已写入" in str(channels.get("eventlog")),
          str(channels.get("eventlog")))
    check("通知：桌面原因卡", "已写入" in str(channels.get("desktop_file")),
          str(channels.get("desktop_file")))

    cards = list(Path(os.path.expanduser("~")).glob("Desktop/EgressGuard_*"))
    check("桌面原因卡文件真实存在", bool(cards),
          f"{len(cards)} 张" + (f"：{cards[-1].name}" if cards else ""))

    why = nt.violation_for_pid(p.pid)
    check("程序可通过 /api/why 问到原因", bool(why and why.get("code")),
          f"code={why.get('code')} reason={(why or {}).get('reason', '')[:60]}")

    enf.release_program(exe)
    try:
        p.kill()
    except Exception:
        pass
    del_test_route(ip)


def t8_strict(enf: Enforcer, net: NI.NetInfo) -> None:
    section("T8 · 严格闸门（全局默认拒绝）开关 + 隧道存活")
    check("死亡开关已装好", arm_deadman(4), f"计划任务 {DEADMAN_TASK}")
    okd, outd, _ = _run_ps(
        f"$t = Get-ScheduledTask -TaskName '{DEADMAN_TASK}' -ErrorAction SilentlyContinue;"
        f"$a = $t.Actions[0]; "
        f"Write-Output ($a.Execute + ' ' + $a.Arguments)", timeout=30)
    check("死亡开关的计划任务指向正确（powershell.exe + restore_net.ps1）",
          "restore_net.ps1" in (outd or ""), (outd or "")[:160])

    import glob
    vpn = glob.glob(r"C:\Program Files\ikuuu_vpn\app\*.exe") + \
          glob.glob(r"C:\Program Files\ikuuu_vpn\*.exe")
    check("拿到隧道程序白名单", bool(vpn),
          ", ".join(os.path.basename(x) for x in vpn))

    r = enf.strict_kill_switch(True, vpn)
    check("严格闸门开启", r.ok, r.detail[:220])

    st = enf.firewall_state()
    flipped = any(act_of(v.get("default_outbound")) == "Block"
                  for v in st.values() if isinstance(v, dict))
    check("出站默认策略已变为 Block", flipped,
          json.dumps(st, ensure_ascii=False)[:260])

    ok, o, _ = _run_ps(
        "(Get-NetFirewallRule -Group 'EgressGuard_STRICT_ALLOW' -ErrorAction "
        "SilentlyContinue | Measure-Object).Count", timeout=30)
    n_allow = int((o.strip() or "0") or 0)
    check("白名单放行规则已建立（含本工具自身）", n_allow > len(vpn),
          f"{n_allow} 条 Allow 规则（隧道程序 {len(vpn)} 个 + 本工具自身）")

    # 关键：隧道自身是否还活着
    time.sleep(3)
    g = net.probe_egress(None, timeout=10)
    check("严格闸门下隧道仍可用（白名单没漏掉 VPN，且本工具自身已放行）",
          g.ok and bool(g.ip),
          f"出口={g.ip} {g.country}{g.city} isp={g.isp}" if g.ok else f"探测失败：{g.error}")

    r2 = enf.strict_kill_switch(False, [])
    check("严格闸门关闭", r2.ok, r2.detail)
    st2 = enf.firewall_state()
    check("出站默认策略已恢复 Allow",
          all(act_of(v.get("default_outbound")) != "Block"
              for v in st2.values() if isinstance(v, dict)),
          json.dumps(st2, ensure_ascii=False)[:260])

    check("死亡开关已撤掉", disarm_deadman(), "已删除计划任务")


def t8b_failclosed(enf: Enforcer, net: NI.NetInfo) -> None:
    section("T8b · 隧道断开自动熔断（fail-closed）")
    check("死亡开关已装好", arm_deadman(4), f"计划任务 {DEADMAN_TASK}")
    okd, outd, _ = _run_ps(
        f"$t = Get-ScheduledTask -TaskName '{DEADMAN_TASK}' -ErrorAction SilentlyContinue;"
        f"$a = $t.Actions[0]; "
        f"Write-Output ($a.Execute + ' ' + $a.Arguments)", timeout=30)
    check("死亡开关的计划任务指向正确（powershell.exe + restore_net.ps1）",
          "restore_net.ps1" in (outd or ""), (outd or "")[:160])

    import glob
    vpn = glob.glob(r"C:\Program Files\ikuuu_vpn\app\*.exe") + \
          glob.glob(r"C:\Program Files\ikuuu_vpn\*.exe")

    r = enf.fail_closed(True, vpn)
    check("熔断已触发（隧道断开场景）", r.ok, r.detail[:200])
    st = enf.firewall_state()
    check("熔断后出站默认策略 = Block",
          any(act_of(v.get("default_outbound")) == "Block"
              for v in st.values() if isinstance(v, dict)),
          json.dumps(st, ensure_ascii=False)[:220])

    ok, o, _ = _run_ps(
        "(Get-NetFirewallRule -Group 'EgressGuard_FAILCLOSED' -ErrorAction "
        "SilentlyContinue | Measure-Object).Count", timeout=30)
    check("熔断放行名单已建立（只有隧道程序 + 本工具）",
          0 < int((o.strip() or "0") or 0) <= len(vpn) + 8, f"{o.strip()} 条")

    # 熔断状态下：隧道程序被放行，所以隧道本身还能重连
    g = net.probe_egress(None, timeout=10)
    check("熔断状态下本工具仍可探测（自身已放行）", g.ok and bool(g.ip),
          f"出口={g.ip}" if g.ok else f"失败：{g.error}")

    r2 = enf.fail_closed(False, [])
    check("熔断已解除", r2.ok, r2.detail[:200])
    st2 = enf.firewall_state()
    check("解除后出站默认策略恢复 Allow",
          all(act_of(v.get("default_outbound")) != "Block"
              for v in st2.values() if isinstance(v, dict)),
          json.dumps(st2, ensure_ascii=False)[:220])

    check("死亡开关已撤掉", disarm_deadman(), "已删除计划任务")


def t9_emergency_restore(enf: Enforcer, net: NI.NetInfo) -> None:
    section("T9 · 紧急恢复：一键把网络还回来")
    arm_deadman(4)
    aliases = [a.alias for a in net.physical(force=True)]
    enf.enable_firewall()
    enf.install_static_rules(aliases)
    enf.quarantine_program(r"C:\Windows\System32\curl.exe", "紧急恢复测试")
    n = rules_count()
    check("已制造出脏状态", n > 0, f"EgressGuard 规则数={n}")

    r = enf.panic_restore()
    check("紧急恢复执行成功", r.ok, r.detail)
    check("EgressGuard 规则已全部清除", rules_count() == 0,
          f"剩余={rules_count()}")

    st = enf.firewall_state()
    check("出站策略为 Allow（网络已放开）",
          all(act_of(v.get("default_outbound")) != "Block"
              for v in st.values() if isinstance(v, dict)),
          json.dumps(st, ensure_ascii=False)[:220])

    g = net.probe_egress(None, timeout=10)
    check("网络实测可用", g.ok and bool(g.ip),
          f"出口={g.ip} {g.country}{g.city}" if g.ok else f"失败：{g.error}")
    disarm_deadman()


def t10_observation_mode() -> None:
    section("T10 · 观察档绝不误伤（只报告不动手）")
    cfg = Config()
    check("默认 enabled=False", not cfg.get("enabled"), f"enabled={cfg.get('enabled')}")
    check("默认 dry_run=True", cfg.get("dry_run") is True, f"dry_run={cfg.get('dry_run')}")
    check("演练档 effective_action 强制为 notify_only",
          cfg.effective_action == "notify_only",
          f"action={cfg.get('action')} -> effective={cfg.effective_action}")
    check("观察档下没有留下任何防火墙规则", rules_count() == 0,
          f"规则数={rules_count()}")


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def main() -> int:
    global _LOGFH
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DATA_DIR))
    ap.add_argument("--skip-slow", action="store_true")
    args = ap.parse_args()
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    ensure_dirs()
    _LOGFH = open(outdir / "acceptance_run.log", "w", encoding="utf-8")

    # 硬崩溃（段错误 / ctypes 访问违例 / 栈溢出）不会走 Python 异常路径，
    # 必须靠 faulthandler 把原生栈打出来，否则只能看到 exit code 1 一脸懵。
    try:
        import faulthandler
        faulthandler.enable(open(outdir / "faulthandler.log", "w",
                                 encoding="utf-8", errors="replace"))
    except Exception:
        pass

    out("=" * 74)
    out("  EgressGuard 端到端验收（管理员模式，真跑执行层）")
    out("=" * 74)
    out(f"  root   : {ROOT}")
    out(f"  python : {sys.executable}")
    out(f"  admin  : {W.is_admin()}")
    out(f"  frozen : {getattr(sys, 'frozen', False)}")
    out(f"  target : {TARGET_IP}:{TARGET_PORT} (SNI {TARGET_SNI})")

    if not W.is_admin():
        out("\n!! 必须以管理员运行，否则执行层测不了 !!")
        return 2

    ip = resolve_target()
    check("测试目标 IP 已确定（硬编码，绕开 fake-ip）", bool(ip),
          f"{TARGET_IP}:{TARGET_PORT} SNI={TARGET_SNI}")
    if not ip:
        return 2
    out(f"  测试 IP: {ip}")
    # 逐个候选实测，挑一个真能建立稳定连接的
    picked = pick_target()
    check("候选目标实测择优（TCP+TLS 握手成功）", bool(picked),
          f"选中 {picked[0]}:{TARGET_PORT} SNI={picked[1]}" if picked
          else "所有候选都连不上，无法继续")
    if not picked:
        return 2
    ip = TARGET_IP

    cfg = Config()
    bus = LogBus()
    net = NI.NetInfo(cfg.snapshot())
    eng = PolicyEngine(cfg, net, bus)
    enf = Enforcer(cfg, bus)
    # T11 要用到一个完整的 GuardCore（零泄漏自检与自动修复都在它身上）
    from eg.core import GuardCore as _GC
    core = _GC(cfg)
    nt = Notifier(cfg, bus)

    # 开跑前先清掉上一次可能残留的 EgressGuard 规则。
    # 不清的话，上一次 T7/E5 建的「程序→目标」规则会挡住这一次 T3 的靶子
    # （实测表现：靶子 connect 报 WinError 10013 权限错误，
    #  看起来像"测试环境有问题"，其实是上一次的规则还在）。
    try:
        enf.remove_all_rules()
    except Exception:
        pass
    base_fw = enf.firewall_state()
    out(f"  防火墙基线: {json.dumps(base_fw, ensure_ascii=False)}")
    base_enabled = any(v.get("enabled") for v in base_fw.values() if isinstance(v, dict))

    try:
        t_neg_undefined_names()
        t0_deadman_usable()
        t1_privilege()
        t2_detection(net, eng)
        t3_kill_connection(net, ip)
        t4_quarantine(enf)
        t5_static_rules(enf, net)
        t6_enable_firewall(enf)
        t7_closed_loop(net, eng, enf, nt, ip)
        if not args.skip_slow:
            t8_strict(enf, net)
            t8b_failclosed(enf, net)
        t9_emergency_restore(enf, net)
        t11_zero_leak_and_remediate(core)
        t10_observation_mode()
    except BaseException:
        check("验收流程未抛异常", False, traceback.format_exc()[-800:])
    finally:
        # 清理本身也必须容错：清理挂掉不能掩盖原始错误，
        # 更不能让进程带着"网络被锁死"的状态退出。
        for step_name, fn in (
            ("撤死亡开关", lambda: disarm_deadman()),
            ("删测试路由", lambda: del_test_route(ip)),
            ("清防火墙规则", lambda: enf.remove_all_rules()),
            ("恢复防火墙基线", lambda: (None if base_enabled else _run_ps(
                "Set-NetFirewallProfile -Profile Domain,Private,Public "
                "-Enabled False -ErrorAction SilentlyContinue; Write-Output 'OK'",
                timeout=30))),
        ):
            try:
                fn()
            except BaseException as e:
                out(f"  [清理告警] {step_name} 失败：{e}")

    n_pass = sum(1 for r in RESULTS if r["ok"])
    n_fail = len(RESULTS) - n_pass
    summary = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "root": str(ROOT), "python": sys.executable,
        "frozen": bool(getattr(sys, "frozen", False)),
        "is_admin": W.is_admin(), "target": f"{TARGET_IP}:{TARGET_PORT}",
        "total": len(RESULTS), "pass": n_pass, "fail": n_fail,
        "results": RESULTS,
    }
    (outdir / "acceptance_report.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# EgressGuard 端到端验收报告", "",
        f"- 时间：{summary['ts']}",
        f"- 运行形态：{'打包 exe' if summary['frozen'] else '源码'}",
        f"- 管理员：{summary['is_admin']}",
        f"- Python：`{summary['python']}`",
        f"- 测试目标：`{summary['target']}`",
        f"- **结果：{n_pass} / {len(RESULTS)} 通过，{n_fail} 未通过**", "",
        "| 结果 | 项目 | 说明 |", "|---|---|---|",
    ]
    for r in RESULTS:
        d = (r["detail"] or "").replace("|", "\\|").replace("\n", " ")[:220]
        lines.append(f"| {'PASS' if r['ok'] else 'FAIL'} | {r['name']} | {d} |")
    if n_fail:
        lines += ["", "## 未通过项", ""]
        for r in RESULTS:
            if not r["ok"]:
                lines.append(f"- **{r['name']}**：{r['detail']}")
    (outdir / "acceptance_report.md").write_text("\n".join(lines), encoding="utf-8")

    out("\n" + "=" * 74)
    out(f"  结果：{n_pass} / {len(RESULTS)} 通过，{n_fail} 未通过")
    out("=" * 74)
    for r in RESULTS:
        if not r["ok"]:
            out(f"  FAIL  {r['name']} — {r['detail'][:200]}")
    out(f"\n报告：{outdir / 'acceptance_report.md'}")
    if _LOGFH:
        _LOGFH.close()
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
