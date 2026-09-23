"""实测 v1.1.0 的结构性泄漏自动修复（端到端）。

流程：
  1. 先看当前状态（应该有 IPv6 旁路 + DNS 泄漏）
  2. 打开闸门 + 自动修复
  3. 跑一轮刷新，看它有没有真的修
  4. 用 --assert 的同一套逻辑确认 zero_leak
  5. 回滚，确认能恢复原状

全程可逆：修了什么都记在 remediation.json，rollback_remediation() 一键还原。
"""

import io
import json
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"D:\工具\EgressGuard")

from eg.config import Config  # noqa: E402
from eg.core import GuardCore, zero_leak_report  # noqa: E402


def snap(label):
    cfg = Config()
    core = GuardCore(cfg)
    core._refresh_adapters()
    rep = zero_leak_report(core)
    print(f"\n{'=' * 70}\n  {label}\n{'=' * 70}")
    print(f"  zero_leak = {rep['zero_leak']}   {rep['verdict']}")
    for c in rep["checks"]:
        mark = "OK  " if c["ok"] else "FAIL"
        print(f"    [{mark}] {c['name']:<18} {c['detail'][:78]}")
    print(f"  note: {rep['note']}")
    return rep, core


# ---- 1. 修复前 ----
rep0, _ = snap("1. 修复前（闸门关闭）")

# ---- 2. 打开闸门 + 自动修复 ----
cfg = Config()
cfg.update({"enabled": True, "dry_run": True,      # 演练档：不动连接，但结构性修复照做
            "auto_remediate": True,
            "auto_remediate_ipv6": True,
            "auto_remediate_dns": True,
            "remediate_cooldown_s": 0})
print(f"\n已设置：enabled=True dry_run=True auto_remediate=True")

core = GuardCore(cfg)
core._refresh_adapters()
print(f"\n{'=' * 70}\n  2. 触发一轮网卡刷新（自动修复就在这一步发生）\n{'=' * 70}")
core._refresh_adapters()
time.sleep(1)

# ---- 3. 修复后 ----
rep1, _ = snap("3. 修复后")

# ---- 4. 看修复记录 ----
from eg.config import DATA_DIR  # noqa: E402
rem = DATA_DIR / "remediation.json"
print(f"\n{'=' * 70}\n  4. 修复记录（{rem}）\n{'=' * 70}")
if rem.exists():
    print(rem.read_text(encoding="utf-8-sig"))
else:
    print("  （没有修复记录文件）")

# ---- 5. 事件流里的修复证据 ----
ev = DATA_DIR / "events.jsonl"
print(f"\n{'=' * 70}\n  5. 事件流里的自动修复记录\n{'=' * 70}")
if ev.exists():
    hits = []
    for line in ev.read_text(encoding="utf-8", errors="replace").splitlines()[-400:]:
        try:
            o = json.loads(line)
        except Exception:
            continue
        if str(o.get("code", "")).startswith("AUTO_REMEDIATE") or \
           str(o.get("code", "")).startswith("REMEDIATE"):
            hits.append(f"    [{o.get('severity')}] {o.get('title')} :: "
                        f"{str(o.get('detail'))[:110]}")
    print("\n".join(hits[-8:]) if hits else "  （没有找到修复记录）")

# ---- 6. 结论 ----
print(f"\n{'=' * 70}\n  6. 结论\n{'=' * 70}")
before = set(rep0["blocking"])
after = set(rep1["blocking"])
print(f"  修复前不过的项: {sorted(before) or '无'}")
print(f"  修复后不过的项: {sorted(after) or '无'}")
fixed = before - after
print(f"  被自动修掉的项: {sorted(fixed) or '无'}")
print(f"  zero_leak: {rep0['zero_leak']} -> {rep1['zero_leak']}")

# ---- 7. 回滚 ----
print(f"\n{'=' * 70}\n  7. 回滚\n{'=' * 70}")
cfg2 = Config()
core2 = GuardCore(cfg2)
r = core2.enforcer.rollback_remediation()
print(f"  {r.detail}")
cfg2.update({"enabled": False})
rep2, _ = snap("8. 回滚后")
print(f"\n  回滚后 zero_leak = {rep2['zero_leak']}  {rep2['verdict']}")
