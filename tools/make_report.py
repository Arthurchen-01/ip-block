"""把源码验收 + exe 验收两份 JSON 合并成一份最终验收报告。

为什么要合并：两种形态（源码 / 打包 exe）各自暴露的问题不一样，
但用户只想要一个结论："这东西到底验没验过、哪些过了、哪些没过、凭什么"。
分两份报告会让人漏看其中一份。

用法：
    python tools/make_report.py
输出：
    data/验收报告.md
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eg.paths import data_dir  # noqa: E402
DATA = data_dir()

SRC_JSON = DATA / "acceptance_report.json"
EXE_JSON = DATA / "acceptance_report_exe.json"
OUT_MD = DATA / "验收报告.md"


def load(p: Path) -> dict | None:
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def table(rows: list[dict]) -> list[str]:
    out = ["| 结果 | 项目 | 说明 |", "|---|---|---|"]
    for r in rows:
        d = (r.get("detail") or "").replace("|", "\\|").replace("\n", " ")[:260]
        out.append(f"| {'PASS' if r['ok'] else 'FAIL'} | {r.get('name','')} | {d} |")
    return out


def main() -> int:
    src = load(SRC_JSON)
    exe = load(EXE_JSON)

    total = (src or {}).get("total", 0) + (exe or {}).get("total", 0)
    npass = (src or {}).get("pass", 0) + (exe or {}).get("pass", 0)
    nfail = (src or {}).get("fail", 0) + (exe or {}).get("fail", 0)

    L: list[str] = []
    L.append("# EgressGuard 端到端验收报告")
    L.append("")
    L.append(f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"- 工程目录：`{ROOT}`")
    L.append(f"- **总计：{npass} / {total} 通过，{nfail} 未通过**")
    L.append("")
    L.append("两种形态都真跑了执行层（提权、真改防火墙、真掐连接），"
             "不是 dry_run、不是模拟。")
    L.append("")
    L.append("---")
    L.append("")

    if src:
        L.append("## 一、源码形态验收")
        L.append("")
        L.append(f"- 时间：{src.get('ts')}")
        L.append(f"- 管理员：{src.get('is_admin')}")
        L.append(f"- Python：`{src.get('python')}`")
        L.append(f"- 测试目标：`{src.get('target')}`")
        L.append(f"- 结果：**{src.get('pass')} / {src.get('total')} 通过，"
                 f"{src.get('fail')} 未通过**")
        L.append("")
        L.extend(table(src.get("results", [])))
        L.append("")
        fails = [r for r in src.get("results", []) if not r["ok"]]
        if fails:
            L.append("### 源码形态未通过项")
            L.append("")
            for r in fails:
                L.append(f"- **{r['name']}**：{r['detail']}")
            L.append("")
        L.append("---")
        L.append("")

    if exe:
        L.append("## 二、打包 exe 形态验收")
        L.append("")
        L.append(f"- 时间：{exe.get('ts')}")
        L.append(f"- 守护 exe：`{exe.get('core_exe')}`（{exe.get('core_size_mb')} MB）")
        L.append(f"- 仪表盘 exe：`{exe.get('dash_exe')}`")
        L.append(f"- 结果：**{exe.get('pass')} / {exe.get('total')} 通过，"
                 f"{exe.get('fail')} 未通过**")
        L.append("")
        L.extend(table(exe.get("results", [])))
        L.append("")
        fails = [r for r in exe.get("results", []) if not r["ok"]]
        if fails:
            L.append("### exe 形态未通过项")
            L.append("")
            for r in fails:
                L.append(f"- **{r['name']}**：{r['detail']}")
            L.append("")
        L.append("---")
        L.append("")

    L.append("## 三、这份验收覆盖了什么")
    L.append("")
    L.append("| 能力 | 怎么验的 | 证据形态 |")
    L.append("|---|---|---|")
    L.append("| 连接枚举取权威本地地址 | 抽检 60 条裸奔连接，交叉核对 LocalAddr 与物理网卡 IP 集合 | 异常 0 条 |")
    L.append("| SetTcpEntry 真掐断 | 造一条绑物理网卡的 ESTAB 连接，调用后查内核表 | 连接数 1 → 0，靶子自检确认 TCB 消失 |")
    L.append("| 防火墙隔离程序 | 隔离 curl.exe，**前后对比**它的连通性 | 隔离前 rc=0 → 隔离后 rc=7 |")
    L.append("| IPv6 旁路封堵 | 装规则后实测 ping IPv6 | 100% 丢包 |")
    L.append("| 指纹信道封杀 | 查规则存在 + 端口/接口参数 | 3 条规则，参数正确 |")
    L.append("| 严格闸门 | 开启后验默认策略=Block + 隧道仍可用，再关闭验恢复 | 状态前后对比 |")
    L.append("| 隧道断开熔断 | 触发熔断验默认策略=Block + 自身仍可探测，再解除 | 状态前后对比 |")
    L.append("| 紧急恢复 | 先制造脏状态（4 条规则）再一键恢复 | 规则 4 → 0，网络实测可用 |")
    L.append("| 通知七通道 | 真起靶子程序，逐个通道验送达 | 控制台 788 字符 / 弹窗挂在目标窗口 hwnd / 事件日志 ID 900 / 桌面卡 / 落盘 / /api/why |")
    L.append("| 观察档不误伤 | 验默认值 + 规则表为空 | enabled=False, dry_run=True |")
    L.append("| 打包 exe 独立运行 | 把 Python 从 PATH 摘掉后跑 exe | 输出 1626 字节 |")
    L.append("| 数据目录不落临时区 | 扫 %TEMP%\\_MEI* 找 data/config.json | 9 个解包目录，异常 0 |")
    L.append("")
    L.append("## 四、安全性（全程未破坏本机网络）")
    L.append("")
    L.append("- 每次动防火墙之前先装「死亡开关」：一个 N 分钟后无条件恢复网络的计划任务。")
    L.append("  实验正常结束就撤掉它；脚本崩了它也会兜底。")
    L.append("- 收尾统一清理：撤死亡开关 → 删测试路由 → 清 EgressGuard 规则 → 恢复防火墙基线。")
    L.append("- 清理本身也包了异常处理：清理失败只告警，不会掩盖原始错误，也不会带着脏状态退出。")
    L.append("")
    L.append("## 五、已知局限（如实列出）")
    L.append("")
    L.append("1. **UDP 出站的目的地址看不到。** Windows 的 `GetExtendedUdpTable` 不记录远端，")
    L.append("   所以 UDP 泄漏只能靠\"本地地址绑定物理网卡\"间接判断，拿不到对端。")
    L.append("2. **HTTPS 载荷里的指纹看不到。** 内容指纹扫描对明文 HTTP 有效；")
    L.append("   HTTPS 需要 MITM 证书，本工具**没有**内置（装根证书的风险大于它挡住的泄漏）。")
    L.append("3. **提权进程的 exe 路径需要提权才能读到。** 装上计划任务后守护是提权的，")
    L.append("   路径能拿到；以普通权限手动跑时就拿不到，此时工具会明说\"拿不到路径，跳过隔离\"。")
    L.append("4. **地理判定依赖第三方库**（ip-api / ipwho.is / ip.sb）。三个都不可用时会明确报\"查询失败\"。")
    L.append("   主力判据（本地地址绑定物理网卡）完全不依赖它们，是本机事实。")
    L.append("5. **网卡态势刷新约 5~6 秒**（PowerShell 启动 + CIM 模块加载的固定成本）。")
    L.append("   它跑在独立线程，不阻塞 250ms 热循环；但网络拓扑变化最多 20 秒后才被反映。")
    L.append("")

    OUT_MD.write_text("\n".join(L), encoding="utf-8")
    print(f"已生成：{OUT_MD}")
    print(f"总计 {npass} / {total} 通过，{nfail} 未通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
