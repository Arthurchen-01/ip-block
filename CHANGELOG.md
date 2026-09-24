# 变更记录

## [1.2.0] - 2026-09-24

> 版本跨度：`v1.1.0` → `v1.2.0`（基线提交 `5c60e02` / 上一个 tag `v1.1.0`）
> 代码量：`39 个文件，11300+ 行`（新增 `eg/tray.py`、`tools/make_icon.py`、`assets/`）
> 本版主题：**从"能跑的脚本"变成"像一个软件"** —— 应用图标、系统托盘、打包自诊断、
> 无控制台环境下的文件日志。同时修掉 4 个只在打包形态才暴露的 bug。

### 上一版（v1.1.0）的代码状态 —— 改之前是什么样

v1.1.0 在**功能**上是完整的（零泄漏自检 + 自动修复 + 119 项验收全过），
但它交付出来的东西**不像一个软件**：

| 文件 / 形态 | v1.1.0 时的状态 |
| :--- | :--- |
| `dist\*.exe` | **用的是 PyInstaller 的默认图标**。任务栏、资源管理器、Alt+Tab、属性页里全是那个通用图标，一眼就能看出是脚本打的包。属性 -> 详细信息里**版本号是空的**。 |
| 整个产品形态 | **没有任何常驻的可见入口**。闸门是常驻防护，但要问"现在有没有在漏"，必须先双击 `启动仪表盘.bat` 把窗口开出来。关掉窗口之后，它对用户就"不存在"了。 |
| `eg/dashboard.py` | **没有文件日志**。`--windowed` 打的 exe 没有控制台，任何 `print` 都进黑洞 —— 一旦打包后某处失败，现场什么都不剩。 |
| `tools/build_exe.py` | `version_info.txt` 写在 `build\` 里，而 PyInstaller 的 `--clean` 会把 `build\` 清掉 → **第二个 exe 必然构建失败**（`FileNotFoundError`）。表现是"第一个成功、第二个失败"，看着像随机问题。 |
| `eg/paths.py` | `resource()` 只接受一个参数。托盘代码按 `resource("assets", "egressguard.ico")` 调 → `TypeError`，而那段在 `try/except` 里 → **托盘静默不出现**。 |
| `eg/tray.py` | **不存在**。 |
| `tests/acceptance_exe.py` | 没有任何"像不像软件"的检查项 —— 图标、版本资源、托盘、冻结环境依赖完整性，全都没测。 |

### 本次改动的文件 —— 改了什么

| 文件 | 类型 | 改动 |
| :--- | :--- | :--- |
| `eg/tray.py` | **新** | 系统托盘：三态图标（绿=零泄漏 / 红=有泄漏 / 黄=闸门未启用）、悬停结论、右键菜单（打开仪表盘 / 零泄漏自检 / 开关闸门 / 打开数据目录 / 打开事件日志 / 退出）、泄漏气泡通知。用 win32gui 直接调 `Shell_NotifyIconW`，**不引入 pystray**。带逐步日志（`_log()`）—— 因为 windowed exe 没有控制台，托盘又在独立线程里，出问题本来完全没线索。 |
| `tools/make_icon.py` | **新** | 用 Pillow 画多尺寸 `.ico`（10 种尺寸）。图形语义：盾牌 + 被掐断的连接 + 右下角小锁。仓库自洽，不含二进制美术文件。 |
| `assets/egressguard.ico` | **新** | 应用图标（40 KB，10 种尺寸） |
| `assets/icon_ok.png` / `icon_leak.png` | **新** | 托盘与文档用的两种状态图 |
| `eg/dashboard.py` | 改 | 新增 `_setup_logging()`：把 stdout/stderr 落到 `logs/dashboard.log`（2MB 轮转）。**windowed exe 必须有这个**，否则打包后出问题什么都看不到。托盘接进 `run_window()`：`on_open_dashboard` 恢复并置顶已有窗口、`on_exit` 真正结束进程。新增 `--no-tray`。 |
| `eg/core.py` | 改 | 新增 `diagnostics()` 与 `--diag`：一次说清冻结环境下哪些模块/资源可用（win32gui / PIL / webview / pythoncom / 图标 / VERSION）。新增 `/api/zero_leak` 端点（托盘和集成方共用）。 |
| `eg/paths.py` | 改 | `resource()` 改**变参**：`resource("eg/ui.html")` 和 `resource("assets", "x.ico")` 都行。 |
| `tools/build_exe.py` | 改 | `version_info.txt` 移到系统临时目录（`--clean` 碰不到）；加 `--icon`、`--add-data assets`、`--version-file`；补 `win32gui/win32api/win32con` 的 hidden-import。 |
| `tests/acceptance_exe.py` | 改 | 新增 `e8_tray_and_icon()`：查图标文件、查 exe 版本资源与 `VERSION` 一致、跑 `--diag` 查冻结依赖、**用 `IsWindow` 校验托盘窗口真的存在**、查托盘状态轮询活着。 |
| `VERSION` | 改 | `1.1.0` → `1.2.0` |

### Added

- **应用图标**：盾牌 + 被掐断的连接 + 小锁，10 种尺寸的 `.ico`，两个 exe 都用它。
- **系统托盘常驻**：闸门终于有了一个常驻的可见入口。图标颜色一眼看出状态，
  右键能查零泄漏自检、开关闸门、打开数据目录/日志，发现泄漏会弹气泡。
- **打包自诊断 `--diag`**：一次输出冻结环境下所有依赖的可用性。
- **无控制台环境的文件日志**：`logs/dashboard.log`，2MB 轮转。
- **`/api/zero_leak`**：把零泄漏结论开放给托盘和集成方。

### Fixed

| # | 问题 | 后果 |
| ---: | :--- | :--- |
| 1 | `version_info.txt` 写在 `build\` 里，被 `--clean` 清掉 | **第二个 exe 必然构建失败**，表现为"第一个成功第二个失败"，像随机问题 |
| 2 | `resource()` 只收一个参数，托盘按两个传 | `TypeError` 被 `try/except` 吞掉 → **托盘静默不出现** |
| 3 | windowed exe 没有文件日志 | 打包后任何失败都没有现场，只能靠猜 |
| 4 | 旧 `EgressGuard.exe` 进程占着文件 | 重新打包报 `PermissionError: 拒绝访问` —— 构建脚本该先杀进程 |
| 5 | `dashboard.py` 缺 `Path`/`os` 导入；`acceptance_exe.py` 缺 `ctypes` | 由本轮新加的**静态扫描**抓出来的（`py_compile` 抓不到这类错） |

### Changed

- 版本号来源：`VERSION` 文件是唯一权威，`__version__` 读它，exe 版本资源也由它生成。
- 托盘状态轮询分两条路径：问守护 API（毫秒级，3 秒一次）；
  自己跑零泄漏自检（6 秒起步，降到 30 秒一次）—— 不分青红皂白会拖满 CPU。

### Verified

见 `%LOCALAPPDATA%\EgressGuard\验收报告.md`。本版新增的 E8 项覆盖：
应用图标存在、两个 exe 的版本资源与 `VERSION` 一致、`--diag` 报告冻结形态、
冻结环境下 win32gui/webview/PIL 全部可用、托盘模块能导入并加载图标、
**托盘窗口经 `IsWindow` 校验确实存在**、托盘状态轮询在跑并拿到了状态结论。

### 排查记录：一个查了半天的假象

托盘在**源码形态**下 `FindWindow('EgressGuardTray')` 能查到（返回 3414160），
打包后查却是 **0**，但托盘自己的日志明确写着：

```
[tray] CreateWindow -> hwnd=9179490
[tray] Shell_NotifyIcon(NIM_ADD) -> 1（1=成功）    ← MSDN：1 就是成功
[tray] 进入消息循环 PumpMessages
[tray] 气泡通知已发（启动提示）
[tray] 状态 -> off  「闸门未启用（观察档）—— 有泄漏：1 项结构性问题 + 1 项动态问题」
```

最后让**托盘把自己的 hwnd 写进 `tray_hwnd.txt`**，外部拿它做 `IsWindow` 校验：

```
托盘自报 hwnd = 43451340
IsWindow       = True
窗口类名       = 'EgressGuardTray'
窗口标题       = 'EgressGuard'
```

**托盘一直是好的，是 `FindWindow` 在冻结形态下查不到。**
教训写进验收项：**校验窗口存在要用 `IsWindow`，不要用 `FindWindow`**。

---

## [1.1.0] - 2026-09-24

> 版本跨度：`v1.0.0` → `v1.1.0`
> 基线：本目录**此前没有版本控制**（v1.0.0 是在同一会话里从零写出来的，没有 tag、没有提交）。
> 所以下面「上一版状态」是按会话记录逐条写的，不是从 `git diff` 抄的；本版**首次**建立
> git 仓库并把当前状态提交为基线，以后每一版都会有真实的 diff 行数。
> 代码量：`33 个文件，9416 行`（当前总量；`eg/` 核心 10 个模块共 6018 行）

### 上一版（v1.0.0）的代码状态 —— 改之前是什么样

v1.0.0 是一个**能跑、端到端验过 119/119** 的版本，但它在「不泄露」这个目标上有三个真实缺口：

| 文件 / 模块 | v1.0.0 时的状态 |
| :--- | :--- |
| `eg/core.py` | **结构性泄漏只报告，不修复**。`IPV6_GLOBAL_EXPOSED`（物理网卡上出现全局 IPv6）和 `DNS_LEAK`（物理网卡用了非隧道 DNS）只写一条事件、在仪表盘上亮个红条。用户不主动去点仪表盘上的按钮，它就**一直在漏**。而这两项是**常驻状态**，不是一次性事件 —— 换张网卡、路由器重新通告、VPN 客户端重装，泄漏就回来。 |
| `eg/core.py` | **没有「零泄漏」的统一结论**。要知道现在到底有没有在漏，得自己在仪表盘上把十几个指标拼起来判断。 |
| `eg/core.py` | **`_run_ps` 未导入**（只导入了 `Enforcer`）。于是 `_startup_selfcheck` 里所有残留路由清理、以及 IPv6 规则查询全部抛 `NameError`，被 `except Exception` 吞掉 —— **静默失效，看起来像功能正常**。 |
| `eg/winapi.py` | **UDP 出站的对端看不到**。Windows 的 `GetExtendedUdpTable` 不记录远端地址，所以 UDP 泄漏只能靠"本地地址绑定物理网卡"间接判断，拿不到"发给谁了"。这是判定上的一个真实盲区。 |
| `eg/enforce.py` | IPv6 封堵规则**绑在当时的物理网卡上**。一旦出现新网卡（实测这台机器上冒出过一块「以太网 2」），新网卡上的 IPv6 不在规则覆盖范围内，旁路重新打开。 |
| `tests/acceptance_exe.py` | 漏了 `from eg import netinfo as NI`，`_phys_nic()` 抛 `NameError` 被吞 → 伪装成"找不到物理网卡" → E5 的测试路由建不起来、后面一连串检查全挂。 |
| `tests/acceptance_exe.py` | 预清理写的是 `enf.remove_all_rules()`，而本文件里**根本没有 `enf` 这个对象** → 每次都 `NameError` 被吞 → 清理从来没生效 → 下一轮靶子被上一轮的残留规则挡住（`WinError 10013`）。 |
| `tests/restore_net.ps1` | **死亡开关一直是坏的**。文件存成 UTF-8 **无 BOM**，而计划任务用 `powershell.exe`(5.1) 跑它，5.1 读无 BOM 的 UTF-8 会按 GBK 解析，中文被撕碎后括号平衡崩掉 → 脚本**一行都执行不了**。而当时的验收只检查了"计划任务注册成功"，没检查脚本本身能不能跑。 |
| `tests/acceptance*.py` | **硬编码了本机网络**：`192.168.0.101`、网关 `192.168.0.1`、`if 24`。实测这台机器的内网在几小时内从 `192.168.0.101/24` 变到 `192.168.1.232/24` 又变回来，VPN 的 ifIndex 从 30 变成 9，还冒出一块新网卡 —— 硬编码的靶子直接 `BIND FAILED`（`WinError 10049`），整套验收全挂。 |
| `tests/acceptance*.py` | 靶子用真实服务器（`218.30.118.6`）做目标，别的工具撞上"闸门正在跑验收测试"的窗口期时，分不清那是真泄漏还是自测流量。 |
| 根目录 | **没有 `VERSION`、没有 `CHANGELOG.md`、没有 git**。`__version__` 是硬编码的 `"1.0.0"`，没有任何地方记录"上一版是什么样"。 |

### 本次改动的文件 —— 改了什么

| 文件 | 类型 | 改动 |
| :--- | :--- | :--- |
| `eg/config.py` | 改 | 新增 `auto_remediate` / `auto_remediate_ipv6` / `auto_remediate_dns` / `remediate_cooldown_s`；`blocked_regions` 补注释说明匹配的是地理库 `regionName+city` 字段 |
| `eg/enforce.py` | 改 | 新增 `remediate_ipv6()`（封 IPv6 全球单播，**规则改全局不绑接口**，自动覆盖新网卡）、`remediate_dns()`（把物理网卡 DNS 指向隧道）、`rollback_remediation()`（一键还原）、`_load/_save_remediation()`（修复留痕到 `remediation.json`） |
| `eg/core.py` | 改 | **补 `from .enforce import Enforcer, _run_ps`**（这是本轮最严重的 bug）；新增 `zero_leak_report()` 零泄漏自检、`_auto_remediate()` 自动修复、`--assert` CLI；IPv6 检查项改成**规则感知**（地址还在但已被封堵 → 判通过）；裸奔连接检查改成**先学隧道对端再判**、并区分「正在漏 / 历史痕迹」；两处 `except Exception` 改成打印 traceback 而不是静默吞掉 |
| `eg/__init__.py` | 改 | `__version__` 改为读 `VERSION` 文件 |
| `tests/acceptance.py` | 改 | 新增 `t_neg_undefined_names()` 静态扫描（AST 查"用了但没导入"的名字）、`t0_deadman_usable()`（查 BOM + PS 5.1 语法 + 日志目录）、`t11_zero_leak_and_remediate()`；网络参数全部改为**运行时发现**；靶子改用 RFC 5737 文档保留段；T3/T7 按**端口**核对而不是数连接条数 |
| `tests/acceptance_exe.py` | 改 | 补 `from eg import netinfo as NI`；预清理改用 `_run_ps`（原来引用的 `enf` 不存在）；新增 `--check` 与防连坐回归项；网络参数运行时发现 |
| `tests/restore_net.ps1` | 改 | **重写并转成 UTF-8 with BOM**（原来无 BOM 导致 PS 5.1 语法崩、脚本一行都跑不了）；日志路径改到统一数据目录；新增清理测试路由（`203.0.113.0/24` 等文档段） |
| `tests/leak_target.py` | 改 | 加连接重试（原来一次失败就退出，导致"守护掐得太快反而测不到"）；加存活宽限期（被掐后继续活 30 秒，否则通知送达时进程已退出） |
| `tests/verify_auto_remediate.py` | **新** | 自动修复的端到端验证：修复前 → 打开闸门 → 修复后 → 查修复记录 → 回滚 → 复验 |
| `tests/exp_guide_to_tunnel.py` | **新** | 「能不能把裸奔流量导回 VPN 出口」的实测实验（结论见 README） |
| `tests/verify_no_collateral.py` | **新** | 防连坐回归：验证共用宿主不会被整程序封杀、目标级封杀只封一个 IP |
| `install.ps1` | 改 | 数据目录改统一位置（`%LOCALAPPDATA%\EgressGuard`）；去掉已无必要的"复制 exe 到根目录"；新增给集成方的状态判据说明 |
| `tools/make_report.py` | 改 | 报告输出改到统一数据目录 |
| `闸门状态.bat` | **新** | 给集成方的一键状态检查（`--check`） |
| `VERSION` / `CHANGELOG.md` / `.gitignore` | **新** | 版本化基础设施 |
| `README.md` | 改 | 补「导回隧道」实测结论、反馈 9 条逐条处理、给集成方的状态判据、数据目录统一说明；修正全部过期路径 |

### Added

- **结构性泄漏自动修复**：物理网卡上出现全局 IPv6 → 自动装规则封堵（规则改为**全局**，新网卡自动覆盖）；
  物理网卡用了非隧道 DNS → 自动指向隧道 DNS。修复动作记进 `remediation.json`，可一键回滚。
  只做 `enabled=True` 时才动手；观察档会明确告诉你"检测到 N 项，闸门未启用所以没修"。
- **零泄漏自检**：`EgressGuardCore.exe --assert`（或 `/api/zero_leak`）给出一句话结论 +
  逐项依据，**退出码 0=零泄漏 / 1=有泄漏**，可以直接当脚本门禁。
- **静态扫描回归项**：AST 扫全项目"用了但没导入"的名字 —— 这类错误 `py_compile` 抓不到，
  只有跑到那一行才炸，而兜底 `except` 又会把它藏起来（本轮踩了两次）。
- **死亡开关可用性检查**：查 BOM、查 PS 5.1 语法、查日志目录。
- **集成方状态判据**：`--check` 明确区分「运行中 / 正在重启 / 已停止 / 未运行」。

### Changed

- 隔离粒度：**「程序」→「程序→目标」**。共用宿主（`python.exe`/`java.exe`/`svchost.exe` 等 40 个）
  与工具自身永不整程序封杀 —— 原来一个 python 脚本裸奔会让全机所有 Python 程序断网，
  而源码形态下守护自己就是 `python.exe`，等于自杀。
- IPv6 封堵规则从"绑当时那块网卡"改成**全局**，新出现的网卡自动覆盖。
- IPv6 检查项从"看地址在不在"改成**规则感知**（地址还在但已被封堵 → 判通过）。
- 验收靶子从真实服务器改成 **RFC 5737 文档保留段**（`203.0.113.0/24`），测试流量一眼可辨。
- 测试网络参数全部**运行时发现**，不再硬编码 IP / 网关 / ifIndex。
- 数据目录统一到 `%LOCALAPPDATA%\EgressGuard\`（源码与 exe 共用同一份配置）。
- 所有 `.ps1` 强制 UTF-8 **with BOM**。

### Fixed

| # | 问题 | 后果 |
| ---: | :--- | :--- |
| 1 | `core.py` 漏 `from .enforce import _run_ps` | 启动自检的残留路由清理、IPv6 规则查询**全部静默失效** |
| 2 | `acceptance_exe.py` 漏 `from eg import netinfo as NI` | `_phys_nic()` 抛 `NameError` 被吞，伪装成"找不到物理网卡"，E5 全挂 |
| 3 | `acceptance_exe.py` 预清理引用了不存在的 `enf` | 清理从未生效，下一轮靶子被残留规则挡住（`WinError 10013`） |
| 4 | `restore_net.ps1` 无 BOM | **死亡开关一行都跑不了** —— 切网实验的安全兜底一直是坏的 |
| 5 | 测试硬编码 IP / 网关 / ifIndex | 机器网络一变（实测变过两次）整套验收全挂 |
| 6 | IPv6 规则绑接口 | 新网卡出现后旁路重新打开 |
| 7 | IPv6 检查只看地址存在 | 自动修复生效了还在报"有泄漏"，让人误判成"修了没用" |
| 8 | 零泄漏自检没先学隧道对端 | 把隧道自己的外层传输报成裸奔，100+ 条假阳性 |
| 9 | 多处 `except Exception: pass` | 把编程错误伪装成"环境问题"，排查成本极高 |

### Verified

```
源码形态：93 / 93 通过，0 未通过
exe 形态：35 / 35 通过，0 未通过
────────────────────────────────
总计：   128 / 128 通过，0 未通过
```

自动修复的端到端实测（`tests/verify_auto_remediate.py`）：

| 阶段 | zero_leak | 结论 |
| :--- | :--- | :--- |
| 修复前（闸门关闭） | `false` | 有泄漏：2 项结构性问题 + 1 项动态问题 |
| 修复后（闸门开启） | `false` | 有泄漏：1 项动态问题（**结构上是干净的**） |
| 回滚后 | `false` | 恢复到 2 项结构性问题 |

被自动修掉的项：`['无 IPv6 旁路']`、`['无 DNS 泄漏']`。
实测现场：`以太网 2`（新出现的网卡）和 `WLAN 3` 都带着公网 IPv6
`2408:896e:1:1fb6::/64`（中国联通），两块网卡 DNS 都是 `192.168.0.1`。

---

## [1.0.0] - 2026-09-23

首个可用版本。从零写出「昆明 IP / 本机指纹零泄露闸门」：

- 五类泄漏判定（裸奔出站 / 出口 IP / IPv6 旁路 / DNS 泄漏 / 指纹外发）
- 判据用 `GetExtendedTcpTable` 的 `dwLocalAddr` 而不是路由表
- 七通道通知（控制台红字 / 归属弹窗 / 桌面原因卡 / 事件日志 / Toast / 落盘 / `/api/why`）
- 隔离、严格闸门、隧道断开熔断、紧急恢复
- PyInstaller 打包成两个无黑框 exe
- 源码 + exe 双形态端到端验收 **119 / 119**
- 死亡开关（切网实验的安全兜底）—— 但**当时实际是坏的**，见 1.1.0
