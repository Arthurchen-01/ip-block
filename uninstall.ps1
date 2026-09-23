#Requires -RunAsAdministrator
<#
    EgressGuard 卸载脚本（需要管理员）

    顺序很重要：**先放开网络，再拆守护**。
    反过来做的话，防火墙规则还在、守护没了，等于把网络锁死在一个没人管的闸门后面。
#>

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$TaskName = 'EgressGuard'

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

Say ""
Say "========================================================" 'Cyan'
Say "  EgressGuard 卸载" 'Cyan'
Say "========================================================" 'Cyan'
Say ""

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Say "  必须以管理员身份运行。" 'Red'
    Read-Host "按回车退出"; exit 1
}

# ---- 1. 先恢复网络（最要紧） ----
Say "[1/4] 恢复网络：删规则 + 出站策略回 Allow" 'White'
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
    Say "      出站默认策略已恢复为 Allow" 'Green'
} catch { Say "      恢复默认策略失败：$($_.Exception.Message)" 'Yellow' }

foreach ($grp in @('EgressGuard', 'EgressGuard_STRICT_ALLOW')) {
    try {
        $rules = Get-NetFirewallRule -Group $grp -ErrorAction SilentlyContinue
        if ($rules) {
            $n = ($rules | Measure-Object).Count
            $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Say "      已删除 $n 条规则（组 $grp）" 'Green'
        } else {
            Say "      组 $grp 无规则" 'DarkGray'
        }
    } catch { Say "      删除组 $grp 失败：$($_.Exception.Message)" 'Yellow' }
}
# 兜底：按名字前缀再扫一遍
try {
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'EgressGuard::*' } |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
} catch {}

# ---- 2. 停并删计划任务 ----
Say ""
Say "[2/4] 移除计划任务" 'White'
$t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($t) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Say "      已移除任务 $TaskName" 'Green'
} else {
    Say "      任务 $TaskName 不存在" 'DarkGray'
}

# ---- 3. 兜底杀残留进程 ----
Say ""
Say "[3/4] 清理残留守护进程" 'White'
$killed = 0
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*run_core.py*' } |
    ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        $killed++
    }
Say "      已结束 $killed 个残留进程" 'Green'

# ---- 4. 快捷方式与事件源 ----
Say ""
Say "[4/4] 清理快捷方式 / 事件源" 'White'
$lnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'EgressGuard 闸门.lnk'
if (Test-Path $lnk) { Remove-Item $lnk -Force; Say "      已删桌面快捷方式" 'Green' }
try {
    if ([System.Diagnostics.EventLog]::SourceExists('EgressGuard')) {
        Remove-EventLog -Source 'EgressGuard' -ErrorAction SilentlyContinue
        Say "      已注销事件源 EgressGuard" 'Green'
    }
} catch { Say "      注销事件源失败（可忽略）：$($_.Exception.Message)" 'DarkGray' }

Say ""
Say "========================================================" 'Cyan'
Say "  卸载完成。网络已恢复放行。" 'Green'
Say "========================================================" 'Cyan'
Say ""
Say "  数据保留在：$Root\data" 'DarkGray'
Say "    事件日志 events.jsonl / 配置 config.json / 原因卡 notices\" 'DarkGray'
Say "  确认不再需要后可整目录删除。" 'DarkGray'
Say ""
Read-Host "按回车退出"
