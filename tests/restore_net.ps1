# EgressGuard 死亡开关 —— 无条件把网络恢复到放行状态
#
# 由验收脚本在动防火墙之前装成一个 N 分钟后执行的计划任务（SYSTEM 身份）。
# 作用：即使实验把自己的网络切断了、或者脚本中途崩了，
#       几分钟后网络也会自动回来。这是"测试能切断自己网络的功能"的标准做法。
#
# 只恢复网络，不删数据、不动配置。
#
# ⚠ 编码铁律：这个文件必须存成 **UTF-8 with BOM**。
#   计划任务用的是 powershell.exe（5.1），它读无 BOM 的 UTF-8 会按 GBK 解析，
#   中文被撕碎后括号平衡就崩了 —— 脚本直接语法错误、一行都跑不了。
#   实测踩过：死亡开关因为这个原因**一直是坏的**，而验收只检查了
#   "计划任务注册成功"，没检查脚本本身能不能跑。
#   tests/acceptance.py 现在会显式做 PS 5.1 语法检查。

$ErrorActionPreference = 'Continue'

# 数据目录：统一在 %LOCALAPPDATA%\EgressGuard\
# （早期版本写的是脚本同级的 ..\data\，数据目录搬家后那条路径已经不存在，
#   会让日志写入直接抛 DirectoryNotFoundException —— 实测踩到过）
$dataDir = Join-Path $env:LOCALAPPDATA 'EgressGuard'
if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
}
$log = Join-Path $dataDir 'deadman.log'

function Write-Log([string]$m) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $m"
    try { Add-Content -Path $log -Value $line -Encoding UTF8 } catch {}
}

Write-Log "死亡开关触发：开始无条件恢复网络"

# 1. 出站默认策略恢复放行
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
    Write-Log "出站默认策略 -> Allow"
} catch { Write-Log "恢复默认策略失败：$($_.Exception.Message)" }

# 2. 删掉 EgressGuard 的所有规则组
foreach ($grp in @('EgressGuard', 'EgressGuard_STRICT_ALLOW', 'EgressGuard_FAILCLOSED')) {
    try {
        $rules = Get-NetFirewallRule -Group $grp -ErrorAction SilentlyContinue
        $n = ($rules | Measure-Object).Count
        if ($n -gt 0) {
            $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        }
        Write-Log "删除组 $grp 的 $n 条规则"
    } catch { Write-Log "删除组 $grp 失败：$($_.Exception.Message)" }
}

# 3. 按名字前缀兜底清理
try {
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'EgressGuard::*' } |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Log "按名字前缀兜底清理完成"
} catch {}

# 4. 删掉验收测试留下的主机路由
#
# 测试会把文档保留段（RFC 5737 的 203.0.113.0/24 等）指向物理网卡来制造泄漏，
# 脚本崩了这些路由就会留下 —— 而它们会把本该走隧道的流量带到物理网卡上，
# 等于凭空造出一条泄漏路径。必须清掉。
$testPrefixes = @('203.0.113.', '198.51.100.', '192.0.2.')
$removed = 0
try {
    $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $d = $_.DestinationPrefix
        $hit = $false
        foreach ($p in $testPrefixes) { if ($d.StartsWith($p)) { $hit = $true } }
        $hit
    }
    foreach ($r in $routes) {
        $ip = ($r.DestinationPrefix -split '/')[0]
        route delete $ip 2>$null | Out-Null
        $removed++
    }
    Write-Log "删除测试路由 $removed 条"
} catch { Write-Log "删除测试路由失败：$($_.Exception.Message)" }

# 5. 历史遗留的几个测试目标 IP（早期版本用过真实服务器）
foreach ($ip in @('223.5.5.5', '218.30.118.6', '198.18.0.107')) {
    try { route delete $ip 2>$null | Out-Null } catch {}
}

# 6. 自我撤销：跑完就把自己删掉，避免残留
try {
    Unregister-ScheduledTask -TaskName 'EgressGuard_Deadman' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Log "死亡开关计划任务已自我注销"
} catch {}

Write-Log "恢复完成"
