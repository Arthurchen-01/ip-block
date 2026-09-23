import io
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"D:\工具\EgressGuard")
from eg.config import Config          # noqa: E402
from eg.enforce import Enforcer       # noqa: E402
from eg.logbus import LogBus          # noqa: E402

cfg = Config()
bus = LogBus()
enf = Enforcer(cfg, bus)
py = sys.executable
print("admin =", enf.is_admin)
print("python =", py)
print()

print("--- A. 对共用宿主的整程序封杀必须被拒绝 ---")
r = enf.quarantine_program(py, reason="测试：python.exe 裸奔")
print(f"  ok = {r.ok}")
print(f"  说明 = {r.detail}")
print()

print("--- B. 对共用宿主的【目标级】封杀应该成功（这是新的默认动作）---")
r2 = enf.block_target(py, "203.0.113.7", reason="测试：目标级封杀", port=443)
print(f"  ok = {r2.ok}")
print(f"  说明 = {r2.detail}")
print()

print("--- C. 验证规则真的建出来了，而且只封了那一个目标 ---")
ok, out, err = __import__("eg.enforce", fromlist=["_run_ps"])._run_ps(
    "Get-NetFirewallRule -Group 'EgressGuard' -ErrorAction SilentlyContinue | "
    "ForEach-Object { $af = $_ | Get-NetFirewallAddressFilter; "
    "$pf = $_ | Get-NetFirewallApplicationFilter; "
    "[PSCustomObject]@{ Name=$_.Name; Action=$_.Action.ToString(); "
    "Remote=(($af.RemoteAddress) -join '|'); Program=$pf.Program } } | "
    "ConvertTo-Json -Compress", timeout=40)
print("  ", out[:600])
print()

print("--- D. 再封 8 个目标后，普通程序应触发惯犯升级；python 仍不升级 ---")
import os  # noqa: E402
fake = r"C:\Program Files\FakeApp\fake.exe"
for i in range(9):
    enf._target_hits.setdefault(fake.lower(), set()).add(f"203.0.113.{i+1}")
esc, why = enf.should_escalate(fake)
print(f"  普通程序（已封 9 个目标）: escalate={esc}  理由={why}")
for i in range(9):
    enf._target_hits.setdefault(py.lower(), set()).add(f"198.51.100.{i+1}")
esc2, why2 = enf.should_escalate(py)
print(f"  python.exe（已封 9 个目标）: escalate={esc2}  理由={why2}")
print()

print("--- E. 清理测试规则 ---")
print("  ", enf.release_program(py).detail)
ok, out, err = __import__("eg.enforce", fromlist=["_run_ps"])._run_ps(
    "Get-NetFirewallRule -Group 'EgressGuard' -ErrorAction SilentlyContinue | "
    "Measure-Object | Select-Object -ExpandProperty Count", timeout=30)
print("  剩余 EgressGuard 规则数 =", out.strip())
