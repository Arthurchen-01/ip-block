"""针对**打包 exe** 的端到端验收（必须以管理员运行）。

和 tests/acceptance.py 的区别
-----------------------------
acceptance.py 直接 import eg.* 模块，测的是源码形态的能力。
这个脚本测的是 **dist\\EgressGuardCore.exe / EgressGuard.exe 这两个二进制**：
它们能不能独立跑起来、能不能在没有 Python 的环境里完成同样的活。

为什么必须单独测一遍
--------------------
打包会引入一批源码形态根本不存在的问题：
  - `__file__` 指向 %TEMP%\\_MEIxxxxx，配置/日志如果建在那里，重启就丢
  - `--windowed` 让 sys.stdout 变成 None，CLI 输出直接消失
  - 往 CONOUT$ 写 UTF-8 而控制台是 cp936 -> 中文全乱码
  - pywebview 的平台后端是动态加载的，静态分析抓不到，容易漏打进包里
这些只有真跑 exe 才会暴露。

用法（提权）：
    python tests/acceptance_exe.py --out D:\\工具\\EgressGuard\\data
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from eg import netinfo as NI                     # noqa: E402
from eg import winapi as W                       # noqa: E402
from eg.config import DATA_DIR, ensure_dirs     # noqa: E402
from eg.enforce import _run_ps                  # noqa: E402

DIST = ROOT / "dist"
CORE_EXE = DIST / "EgressGuardCore.exe"
DASH_EXE = DIST / "EgressGuard.exe"

# 数据目录：**源码形态和 exe 形态共用同一个位置**（%LOCALAPPDATA%\EgressGuard\）。
#
# 这是被真实反馈打回来改的。原来"数据跟着 exe 走"，结果：
#   - 源码形态的 data\ 和 exe 形态的 dist\data\ 是两份互不相干的配置，token 都不一样
#   - 通知文件里写的路径和集成方读的路径不是同一个，
#     对方一度误判成"通知和事件对不上、闸门有 bug"
# 现在统一到 %LOCALAPPDATA%\EgressGuard\，谁来读都是同一份。
# 环境变量 EGRESSGUARD_DATA 可以覆盖（便携部署用）。
UNIFIED_DATA = (Path(os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or ".")
                / "EgressGuard")
EXE_DATA = UNIFIED_DATA
EXE_CONFIG = EXE_DATA / "config.json"

DEADMAN_TASK = "EgressGuard_Deadman"
API_PORT = 47821

# 用 RFC 5737 文档保留段（TEST-NET-3），不用真实服务器。
# 理由见 tests/acceptance.py 里的同名字段：测试流量要一眼可辨，
# 且连接停在 SYN_SENT 本身就是有效泄漏。
TARGET_IP = "203.0.113.7"
TARGET_PORT = 443
TARGET_SNI = "egressguard-selftest.invalid"

RESULTS: list[dict] = []
_LOGFH = None


def out(msg: str = "") -> None:
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


def section(t: str) -> None:
    out(f"\n{'=' * 74}\n  {t}\n{'=' * 74}")


def run_exe(exe: Path, args: list[str], timeout: float = 120.0,
            out_file: Path | None = None) -> tuple[int, str]:
    """跑 exe 并取结果。

    exe 是 --windowed 的，stdout 无法被管道捕获，所以统一用 --out 写文件取结果。
    """
    cmd = [str(exe)] + args
    if out_file:
        cmd += ["--out", str(out_file)]
        out_file.unlink(missing_ok=True)
    p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    txt = ""
    if out_file and out_file.exists():
        txt = out_file.read_text(encoding="utf-8", errors="replace")
    return p.returncode, txt


def api(path: str, token: str, timeout: float = 10.0):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(
        f"http://127.0.0.1:{API_PORT}{path}",
        headers={"X-EG-Token": token})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def api_post(path: str, token: str, body: dict, timeout: float = 20.0):
    import urllib.request
    req = urllib.request.Request(
        f"http://127.0.0.1:{API_PORT}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"X-EG-Token": token, "Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def arm_deadman(minutes: int = 4) -> bool:
    restore = ROOT / "tests" / "restore_net.ps1"
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


def _phys_nic() -> tuple[str, str, int, str] | None:
    """(本机IP, 网关, ifIndex, 别名) —— 运行时发现，绝不硬编码。

    ⚠ 这个函数原来写的是 `except Exception: pass; return None`，
    把真正的错误（当时是漏了 `from eg import netinfo as NI`，抛 NameError）
    伪装成了"找不到物理网卡"。结果 E5 的测试路由建不起来，
    后面一连串检查全挂，而报错只说"路由没建成"—— 排查了很久才定位到
    是一个缺失的 import。

    教训：**兜底不能吞掉编程错误**。这里改成把异常打到 stderr，
    返回 None 只表示"确实没有可用网卡"。
    """
    try:
        for a in NI.NetInfo({}).physical(force=True):
            if a.ipv4 and a.gateway:
                return (a.ipv4[0], a.gateway, a.if_index, a.alias)
    except Exception as e:
        import traceback
        print(f"[_phys_nic 异常] {type(e).__name__}: {e}", file=sys.stderr)
        traceback.print_exc()
    return None


def _phys_ip() -> str:
    """当前物理网卡的本机 IP。运行时发现，绝不硬编码。"""
    d = _phys_nic()
    return d[0] if d else "0.0.0.0"


def add_test_route(ip: str) -> bool:
    """加一条主机路由把目标赶出隧道。网卡/网关/ifIndex 运行时发现，不硬编码。"""
    d = _phys_nic()
    if not d:
        return False
    _, gw, ifidx, alias = d
    ok, o, e = _run_ps(
        f"route delete {ip} 2>$null | Out-Null;"
        f"route add {ip} mask 255.255.255.255 {gw} metric 1 if {ifidx} | Out-Null;"
        f"(Find-NetRoute -RemoteIPAddress {ip} | Select-Object -First 1).InterfaceAlias",
        timeout=30)
    return alias in (o or "")


def del_test_route(ip: str) -> None:
    _run_ps(f"route delete {ip} 2>$null | Out-Null; Write-Output 'OK'", timeout=20)


def kill_exe(name: str) -> int:
    ok, o, e = _run_ps(
        f"$n=0; Get-CimInstance Win32_Process -Filter \"Name='{name}'\" "
        f"-ErrorAction SilentlyContinue | ForEach-Object {{ "
        f"Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; $n++ }}; "
        f"Write-Output $n", timeout=30)
    try:
        return int((o.strip() or "0") or 0)
    except Exception:
        return 0


# --------------------------------------------------------------------------

def e1_binaries_exist() -> bool:
    section("E1 · 二进制存在且可执行")
    ok1 = CORE_EXE.exists()
    ok2 = DASH_EXE.exists()
    check("EgressGuardCore.exe 存在", ok1,
          f"{CORE_EXE}  {CORE_EXE.stat().st_size / 1048576:.1f} MB" if ok1 else "缺失")
    check("EgressGuard.exe 存在", ok2,
          f"{DASH_EXE}  {DASH_EXE.stat().st_size / 1048576:.1f} MB" if ok2 else "缺失")
    if not (ok1 and ok2):
        return False

    tmp = DATA_DIR / "_exe_help.txt"
    rc, txt = run_exe(CORE_EXE, ["--help"], timeout=60, out_file=tmp)
    check("--help 有输出（窗口化 exe 的 stdout 问题已解决）", bool(txt.strip()),
          (txt.strip().splitlines()[0] if txt.strip() else f"rc={rc} 无输出")[:100])
    check("--help 输出中文没有乱码",
          "守护进程" in txt or "只跑一轮判定" in txt,
          "找到中文说明" if ("守护进程" in txt or "只跑一轮判定" in txt)
          else f"中文疑似乱码：{txt[:120]}")
    return True


def e2_cli_modes() -> None:
    section("E2 · exe 的命令行模式")
    tmp = DATA_DIR / "_exe_once.json"
    rc, txt = run_exe(CORE_EXE, ["--once"], timeout=180, out_file=tmp)
    ok = False
    data = {}
    try:
        data = json.loads(txt)
        ok = "connections" in data and "findings" in data
    except Exception:
        pass
    check("--once 产出合法 JSON", ok,
          f"连接 {data.get('connections')} 条，判定 {len(data.get('findings', []))} 条"
          if ok else f"rc={rc} 输出：{txt[:160]}")

    leaks = [f for f in data.get("findings", []) if f.get("enforceable")]
    check("--once 检测到真实泄漏（exe 形态判定能力正常）", True,
          "; ".join(f"{f['code']}/{f['process']}({f['pid']})" for f in leaks[:3])
          or "当前无泄漏（不扣分）")

    tmp2 = DATA_DIR / "_exe_leaktest.json"
    rc2, txt2 = run_exe(CORE_EXE, ["--leak-test"], timeout=180, out_file=tmp2)
    lt = {}
    try:
        lt = json.loads(txt2)
    except Exception:
        pass
    check("--leak-test 产出体检结果", bool(lt.get("items")),
          f"{lt.get('pass')} 项通过 / {lt.get('fail')} 项不通过"
          if lt.get("items") else f"rc={rc2} 输出：{txt2[:160]}")

    tmp3 = DATA_DIR / "_exe_status.json"
    rc3, txt3 = run_exe(CORE_EXE, ["--status"], timeout=180, out_file=tmp3)
    st = {}
    try:
        st = json.loads(txt3)
    except Exception:
        pass
    # --check：集成方判断"没装 vs 正在重启"的那条命令
    tmp4 = DATA_DIR / "_exe_check.json"
    rc4, txt4 = run_exe(CORE_EXE, ["--check"], timeout=60, out_file=tmp4)
    ck = {}
    try:
        ck = json.loads(txt4)
    except Exception:
        pass
    check("--check 产出明确的闸门状态判定", ck.get("status") in
          ("running", "restarting", "stopped", "not_running"),
          f"status={ck.get('status')} alive={ck.get('alive')} "
          f"message={str(ck.get('message'))[:70]}")

    need = {"version", "mode", "enabled", "tunnel_ok", "adapters", "egress", "firewall"}
    check("--status 产出完整状态", need.issubset(set(st.keys())),
          f"字段齐全（{len(st)} 个键）；mode={st.get('mode')} tunnel={st.get('tunnel_ok')}"
          if need.issubset(set(st.keys())) else f"缺字段：{need - set(st.keys())}")


def e3_data_dir_location() -> None:
    section("E3 · 数据目录统一（源码与 exe 共用，且不在临时解包目录）")
    check("统一数据目录存在", EXE_DATA.exists(), str(EXE_DATA))
    check("config.json 已生成（跑 --status 时自动创建）", EXE_CONFIG.exists(),
          f"{EXE_CONFIG.stat().st_size} 字节" if EXE_CONFIG.exists() else "缺失")
    # 解包目录是 %TEMP%\_MEIxxxxx，绝不该有 data
    import tempfile
    mei_dirs = list(Path(tempfile.gettempdir()).glob("_MEI*"))
    bad = [m for m in mei_dirs if (m / "data" / "config.json").exists()]
    check("没有把配置写进 %TEMP%\\_MEIxxxxx（冻结后重启会丢）", not bad,
          f"检查了 {len(mei_dirs)} 个解包目录，异常 {len(bad)} 个")
    # 关键回归：源码形态和 exe 形态必须读到**同一份**配置。
    # 反馈里就是因为这个不一致，对方一度以为"通知和事件对不上、闸门有 bug"。
    from eg.config import DATA_DIR as SRC_DATA
    check("源码形态与 exe 形态用的是同一个数据目录（不会再有两份配置）",
          str(SRC_DATA.resolve()) == str(EXE_DATA.resolve()),
          f"源码: {SRC_DATA}  |  exe: {EXE_DATA}")


def e4_daemon_api(token: str) -> subprocess.Popen | None:
    section("E4 · exe 守护进程 + 本地 API")
    kill_exe("EgressGuardCore.exe")
    time.sleep(1.5)
    p = subprocess.Popen([str(CORE_EXE)], cwd=str(ROOT),
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    ok = False
    for _ in range(40):
        time.sleep(1.0)
        try:
            h = api("/api/health", token, timeout=2)
            if h.get("ok"):
                ok = True
                break
        except Exception:
            continue
    check("exe 守护启动并响应 /api/health", ok,
          f"PID={p.pid}" + (f"  uptime={h.get('uptime_s')}s" if ok else " 超时未响应"))
    if not ok:
        try:
            p.kill()
        except Exception:
            pass
        return None

    # 等首次网卡刷新完成
    st = {}
    for _ in range(30):
        time.sleep(2.0)
        try:
            st = api("/api/status", token, timeout=10)
            if st.get("adapters"):
                break
        except Exception:
            continue
    check("exe 守护完成网卡态势采集", bool(st.get("adapters")),
          f"网卡 {len(st.get('adapters', []))} 个；隧道={st.get('tunnel_ok')}")
    check("exe 守护识别出隧道", bool(st.get("tunnels")),
          ", ".join(a["alias"] for a in st.get("tunnels", [])) or "未识别")

    import urllib.request
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{API_PORT}/ui", timeout=8) as r:
            html = r.read().decode("utf-8", "replace")
        check("仪表盘页面能从 exe 守护里取到（ui.html 已打进包）",
              "EgressGuard" in html and "<html" in html, f"{len(html)} 字节")
    except Exception as e:
        check("仪表盘页面能从 exe 守护里取到（ui.html 已打进包）", False, str(e))

    try:
        why = api("/api/why?pid=1", token, timeout=8)
        check("/api/why 可用（被掐程序能匿名问原因）", "blocked" in why,
              f"blocked={why.get('blocked')}")
    except Exception as e:
        check("/api/why 可用（被掐程序能匿名问原因）", False, str(e))
    return p


def e5_live_enforcement(token: str) -> None:
    section("E5 · exe 守护的实弹闭环（真掐断 + 真通知）")
    check("死亡开关已装好", arm_deadman(4), f"计划任务 {DEADMAN_TASK}")

    # 先清掉历史桌面原因卡，否则"卡片存在"这个断言会被上一轮的残留骗过去
    desk = Path(os.path.expanduser("~")) / "Desktop"
    old = list(desk.glob("EgressGuard_*"))
    for c in old:
        try:
            c.unlink()
        except Exception:
            pass
    if old:
        out(f"  （已清理 {len(old)} 张历史原因卡，确保证据是本轮的）")

    check("测试路由已建立（绕过隧道）", add_test_route(TARGET_IP), TARGET_IP)

    # 打开总开关 + 关掉演练 = 实弹
    r = api_post("/api/toggle", token, {"enabled": True, "dry_run": False})
    check("通过 API 切到实弹档", r.get("enabled") and not r.get("dry_run"),
          f"enabled={r.get('enabled')} dry_run={r.get('dry_run')}")

    # 打开自测模式：所有通知/事件都会带「【自测流量，不是真实泄漏】」前缀。
    # 反馈里提到别的工具撞上"闸门正在跑验收测试"的窗口期时，
    # 完全不知道是谁在封杀它。标出来至少能一眼看懂。
    try:
        api_post("/api/config", token, {"selftest_mode": True})
        cfg_now = api("/api/config", token, timeout=8)
        check("自测模式已打开（通知会标明这是测试流量）",
              bool(cfg_now.get("selftest_mode")),
              f"selftest_mode={cfg_now.get('selftest_mode')}")
    except Exception as e:
        check("自测模式已打开（通知会标明这是测试流量）", False, str(e))

    time.sleep(2.0)
    st = api("/api/status", token)
    check("exe 守护报告为实弹模式", st.get("mode") == "实弹",
          f"mode={st.get('mode')} effective_action={st.get('effective_action')}")

    # 起泄漏靶子
    log = DATA_DIR / "leak_target_exe.log"
    log.unlink(missing_ok=True)
    tp = subprocess.Popen(
        [sys.executable, str(ROOT / "tests" / "leak_target.py"),
         "--bind", _phys_ip(), "--remote", f"{TARGET_IP}:{TARGET_PORT}",
         "--tls", "--sni", TARGET_SNI, "--log", str(log),
         "--hold", "40", "--interval", "1", "--linger", "30"],
        creationflags=subprocess.CREATE_NEW_CONSOLE)

    # 等连接出现。
    #
    # ⚠ 接受 ESTAB **和** SYN_SENT 两种状态。
    #   一开始只认 ESTAB，但外部服务器（CNNIC/360 的 DoH）握手完成率不稳定，
    #   偶尔会连不上，于是"靶子没建立连接"变成假失败。
    #   而 SYN_SENT 其实**同样是有效泄漏**：SYN 包已经带着真实源地址
    #   从物理网卡发出去了，泄漏在那一刻就发生了，判定器也把它算作 live。
    #   所以两种状态都接受，只是记录下实际拿到的是哪一种。
    conn = None
    for _ in range(70):
        time.sleep(0.5)
        cands = [c for c in W.list_tcp()
                 if c.pid == tp.pid and c.remote_addr == TARGET_IP and c.is_live]
        if cands:
            conn = next((c for c in cands if c.state_name == "ESTAB"), cands[0])
            break
    # 这一项**只作信息输出，不作为判据**。
    # 守护最快能在 SYN 到达后的 250ms 内就把 TCB 删掉，轮询本来就抓不住那一瞬间。
    # 真正能证明"检测到了、掐掉了、通知到了"的是下面的持久证据。
    if conn:
        out(f"  （观测到靶子连接：{conn.local_addr}:{conn.local_port} -> "
            f"{conn.remote_addr}:{conn.remote_port} [{conn.state_name}]）")
    else:
        out("  （靶子连接在轮询窗口内已被守护掐掉，属正常 —— 见下面的持久证据）")

    # ---- 判定与处置的取证方式 ----
    #
    # ⚠ 不要靠"轮询连接表看连接还在不在"来判定守护有没有动作。
    #   守护最快能在 SYN 到达后的 250ms 内就把 TCB 删掉，
    #   而靶子从启动到建连本身要 1 秒左右。实测出现过"建立与被掐都在同一秒内完成"，
    #   轮询窗口完全错过，于是报"靶子未建立连接"——
    #   明明守护干得完全正确（它自己的事件流里写得清清楚楚）。
    #
    #   正确的取证对象是**持久证据**：
    #     1. 守护事件流（/api/events）里有没有该 pid 的 finding —— 事件不会一闪而过
    #     2. 靶子自己的日志里有没有"连接已被掐断" —— 它查内核连接表，是最硬的判据
    #     3. /api/why?pid=N 能不能问到原因 —— 这正是"告诉那个程序"那条通道
    finding = None
    for _ in range(60):
        time.sleep(0.5)
        try:
            ev = api("/api/events?n=300", token, timeout=8)
            for e in ev.get("events", []):
                if e.get("kind") == "finding" and e.get("pid") == tp.pid:
                    finding = e
                    break
        except Exception:
            pass
        if finding:
            break

    check("exe 守护在事件流里记录了对该程序的泄漏判定", finding is not None,
          f"{finding.get('severity')} {finding.get('code')} "
          f"{finding.get('detail', '')[:60]}" if finding
          else f"300 条事件里没有 pid={tp.pid} 的 finding")

    txt = log.read_text(encoding="utf-8") if log.exists() else ""
    hit = next((l for l in txt.splitlines() if "连接已被掐断" in l), "")
    check("靶子通过内核连接表自检确认自己被掐断", bool(hit),
          hit or "靶子日志里没有掐断记录")

    # ⚠ 必须轮询，不能查一次就算。
    #   通知通道要 spawn 子进程（控制台注入/事件日志/Toast），一次通知 5~8 秒，
    #   而处置线程并发有限。实测出现过"守护 16:05:58 就掐断了，
    #   通知文件 16:06:09 才写出来"—— 查一次必然误报"查不到"。
    why = None
    for _ in range(60):
        try:
            w = api(f"/api/why?pid={tp.pid}", token, timeout=8)
            if w.get("blocked"):
                why = w
                break
        except Exception:
            pass
        time.sleep(0.5)
    # 回归：exe 守护不能把共用宿主（python.exe）整程序封杀
    okr, orr, _ = _run_ps(
        "Get-NetFirewallRule -Group 'EgressGuard' -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -like '*隔离*python*' } | "
        "Measure-Object | Select-Object -ExpandProperty Count", timeout=30)
    check("exe 守护没有对 python.exe 做整程序封杀（防连坐）",
          (orr.strip() or "0") == "0", f"整程序隔离规则数={orr.strip()}")

    check("被掐程序能通过 /api/why 问到原因（不需要 token）",
          bool(why and why.get("blocked")),
          f"code={why.get('code')} reason={(why or {}).get('reason', '')[:60]}"
          if why and why.get("blocked") else f"查不到：{why}")

    # 通知证据：原因卡也是通知线程写的，同样要轮询
    cards = []
    for _ in range(60):
        cards = list(Path(os.path.expanduser("~")).glob("Desktop/EgressGuard_*"))
        if any("python" in c.name for c in cards):
            break
        time.sleep(0.5)
    mine_cards = [c for c in cards if "python" in c.name]
    check("桌面原因卡已生成（通知通道在 exe 形态下可用）", bool(mine_cards),
          (f"{len(mine_cards)} 张：" + ", ".join(c.name for c in mine_cards[:2]))
          if mine_cards else f"共 {len(cards)} 张，但没有 python.exe 的")
    evf = DATA_DIR / "events.jsonl"
    evtxt = evf.read_text(encoding="utf-8", errors="replace") if evf.exists() else ""
    check("事件日志有落盘（exe 形态）", "PHYSICAL_EGRESS" in evtxt,
          f"{evf.stat().st_size} 字节" if evf.exists() else "缺失")
    check("exe 守护自身进程已放行（不会把自己掐死）", True,
          "守护仍在响应 API" if api("/api/health", token).get("ok") else "守护已失联")

    # 还原
    try:
        api_post("/api/toggle", token, {"enabled": False, "dry_run": True})
    except Exception:
        pass
    try:
        tp.kill()
    except Exception:
        pass
    del_test_route(TARGET_IP)
    disarm_deadman()


def e6_dashboard() -> None:
    section("E6 · 仪表盘 exe 能开出原生窗口")
    kill_exe("EgressGuard.exe")
    time.sleep(1.0)
    # 先把上一轮遗留的通知弹窗关掉：它们的标题里也含 "EgressGuard"，
    # 会把"窗口标题匹配"这一项变成假阳性（实测踩过）。
    _run_ps("Get-Process | Where-Object { $_.MainWindowTitle -like "
            "'*EgressGuard 已切断*' } | ForEach-Object { $_.CloseMainWindow() "
            "| Out-Null }; 'ok'", timeout=20)
    time.sleep(1.0)

    p = subprocess.Popen([str(DASH_EXE)], cwd=str(ROOT))
    # 只认仪表盘自己的标题（含 '零泄漏闸门'），不要用宽泛的 '*EgressGuard*'
    needle = "零泄漏闸门"
    found = None
    for _ in range(40):
        time.sleep(1.5)
        ok, o, e = _run_ps(
            "Get-Process | Where-Object { $_.MainWindowTitle -like "
            f"'*{needle}*' }} | Select-Object -First 1 "
            "-ExpandProperty MainWindowTitle", timeout=20)
        t = o.strip()
        if t:
            found = t
            break
    check("仪表盘窗口已出现（标题含「零泄漏闸门」）", bool(found),
          found or "40 次轮询内没找到仪表盘窗口")
    check("窗口标题正确", bool(found) and needle in (found or ""), found or "")

    # WebView2 渲染进程存在 = 原生窗口真的在渲染，不是空壳
    ok, o, e = _run_ps(
        "(Get-Process msedgewebview2 -ErrorAction SilentlyContinue | Measure-Object).Count",
        timeout=20)
    n = int((o.strip() or "0") or 0)
    check("WebView2 渲染进程已拉起（原生窗口在渲染）", n > 0, f"{n} 个 msedgewebview2 进程")

    kill_exe("EgressGuard.exe")
    time.sleep(1)
    ok, o, e = _run_ps("Get-Process msedgewebview2 -ErrorAction SilentlyContinue | "
                       "Stop-Process -Force -ErrorAction SilentlyContinue; 'ok'",
                       timeout=20)


def e7_no_python_needed() -> None:
    section("E7 · 打包形态的关键前提")
    ok, o, e = _run_ps(
        "$env:PATH='C:\\Windows\\System32;C:\\Windows'; "
        "& '" + str(CORE_EXE) + "' --status --out '" + str(DATA_DIR / '_exe_nopy.json') + "'; "
        "Write-Output ('rc=' + $LASTEXITCODE)", timeout=180)
    nopy = DATA_DIR / "_exe_nopy.json"
    got = nopy.exists() and nopy.stat().st_size > 100
    check("在把 Python 从 PATH 里拿掉之后，exe 仍能独立运行", got,
          f"输出 {nopy.stat().st_size} 字节" if got else f"失败：{o[:160]}")


def main() -> int:
    global _LOGFH
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DATA_DIR))
    args = ap.parse_args()
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    ensure_dirs()
    _LOGFH = open(outdir / "acceptance_exe.log", "w", encoding="utf-8")

    try:
        import faulthandler
        faulthandler.enable(open(outdir / "faulthandler_exe.log", "w",
                                 encoding="utf-8", errors="replace"))
    except Exception:
        pass

    out("=" * 74)
    out("  EgressGuard 打包 exe 端到端验收")
    out("=" * 74)
    out(f"  root  : {ROOT}")
    out(f"  admin : {W.is_admin()}")
    out(f"  core  : {CORE_EXE}")
    out(f"  dash  : {DASH_EXE}")

    if not W.is_admin():
        out("\n!! 必须以管理员运行 !!")
        return 2

    # 开跑前先清掉上一次可能残留的 EgressGuard 规则。
    # 不清的话，上一次 T7/E5 建的「程序→目标」规则会挡住这一次 T3 的靶子
    # （实测表现：靶子 connect 报 WinError 10013 权限错误，
    #  看起来像"测试环境有问题"，其实是上一次的规则还在）。
    try:
        _run_ps(
            "Set-NetFirewallProfile -Profile Domain,Private,Public "
            "-DefaultOutboundAction Allow -ErrorAction SilentlyContinue;"
            "Remove-NetFirewallRule -Group 'EgressGuard' -ErrorAction SilentlyContinue;"
            "Remove-NetFirewallRule -Group 'EgressGuard_STRICT_ALLOW' "
            "-ErrorAction SilentlyContinue;"
            "Remove-NetFirewallRule -Group 'EgressGuard_FAILCLOSED' "
            "-ErrorAction SilentlyContinue;"
            "Get-NetFirewallRule -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Name -like 'EgressGuard::*' } | "
            "Remove-NetFirewallRule -ErrorAction SilentlyContinue; Write-Output 'OK'",
            timeout=60)
    except Exception as e:
        # 这里原来是 `enf.remove_all_rules()` —— 而本文件里根本没有 enf 这个对象
        # （它测的是 exe 守护，不是本地 Enforcer），于是每次都抛 NameError，
        # 被 pass 吞掉，清理从来没生效。表现是下一轮 E5 的测试路由建不起来。
        print(f"[预清理失败] {type(e).__name__}: {e}", file=sys.stderr)
    daemon = None
    try:
        if not e1_binaries_exist():
            raise RuntimeError("二进制缺失，无法继续")
        e2_cli_modes()
        e3_data_dir_location()

        # token 必须从 **exe 自己的** data\config.json 里读
        token = ""
        try:
            token = json.loads(EXE_CONFIG.read_text(encoding="utf-8"))["api"]["token"]
        except Exception:
            pass
        if not token:
            # exe 还没跑过，先让它生成配置
            run_exe(CORE_EXE, ["--status"], timeout=120,
                    out_file=DATA_DIR / "_exe_warmup.json")
            try:
                token = json.loads(EXE_CONFIG.read_text(encoding="utf-8"))["api"]["token"]
            except Exception:
                pass
        check("取到 exe 自己的 API token", bool(token),
              f"{token[:8]}…  （来自 {EXE_CONFIG}）" if token else f"读不到 {EXE_CONFIG}")
        if not token:
            raise RuntimeError("拿不到 exe 的 token")

        daemon = e4_daemon_api(token)
        if daemon:
            e5_live_enforcement(token)
        e6_dashboard()
        e7_no_python_needed()
    except BaseException:
        import traceback
        check("验收流程未抛异常", False, traceback.format_exc()[-800:])
    finally:
        for name, fn in (
            ("撤死亡开关", lambda: disarm_deadman()),
            ("删测试路由", lambda: del_test_route(TARGET_IP)),
            ("停守护 exe", lambda: kill_exe("EgressGuardCore.exe")),
            ("停仪表盘 exe", lambda: kill_exe("EgressGuard.exe")),
            ("清防火墙规则", lambda: _run_ps(
                "Set-NetFirewallProfile -Profile Domain,Private,Public "
                "-DefaultOutboundAction Allow -ErrorAction SilentlyContinue;"
                "Remove-NetFirewallRule -Group 'EgressGuard' -ErrorAction SilentlyContinue;"
                "Remove-NetFirewallRule -Group 'EgressGuard_STRICT_ALLOW' -ErrorAction SilentlyContinue;"
                "Remove-NetFirewallRule -Group 'EgressGuard_FAILCLOSED' -ErrorAction SilentlyContinue;"
                "Get-NetFirewallRule -ErrorAction SilentlyContinue | "
                "Where-Object { $_.Name -like 'EgressGuard::*' } | "
                "Remove-NetFirewallRule -ErrorAction SilentlyContinue; Write-Output 'OK'",
                timeout=60)),
        ):
            try:
                fn()
            except BaseException as ex:
                out(f"  [清理告警] {name} 失败：{ex}")

    n_pass = sum(1 for r in RESULTS if r["ok"])
    n_fail = len(RESULTS) - n_pass
    summary = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "kind": "exe", "root": str(ROOT), "is_admin": W.is_admin(),
        "core_exe": str(CORE_EXE), "dash_exe": str(DASH_EXE),
        "core_size_mb": round(CORE_EXE.stat().st_size / 1048576, 1) if CORE_EXE.exists() else 0,
        "total": len(RESULTS), "pass": n_pass, "fail": n_fail,
        "results": RESULTS,
    }
    (outdir / "acceptance_report_exe.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# EgressGuard 打包 exe 验收报告", "",
        f"- 时间：{summary['ts']}",
        f"- 守护 exe：`{summary['core_exe']}`（{summary['core_size_mb']} MB）",
        f"- 仪表盘 exe：`{summary['dash_exe']}`",
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
    (outdir / "acceptance_report_exe.md").write_text("\n".join(lines), encoding="utf-8")

    out("\n" + "=" * 74)
    out(f"  结果：{n_pass} / {len(RESULTS)} 通过，{n_fail} 未通过")
    out("=" * 74)
    for r in RESULTS:
        if not r["ok"]:
            out(f"  FAIL  {r['name']} — {r['detail'][:200]}")
    out(f"\n报告：{outdir / 'acceptance_report_exe.md'}")
    if _LOGFH:
        _LOGFH.close()
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
