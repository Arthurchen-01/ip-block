#Requires -RunAsAdministrator
<#
    EgressGuard 安装脚本（需要管理员）

    两种运行形态，脚本自动择优：
      A. 已打包 exe（dist\EgressGuardCore.exe + dist\EgressGuard.exe）
         -> 直接用 exe，**目标机器不需要装 Python**
      B. 源码形态（run_core.py）
         -> 用 pythonw.exe 跑，需要机器上有 Python 3.9+

    做五件事：
      1. 选定运行形态（exe 优先）
      2. 注册 Windows 事件日志源 EgressGuard（"告诉程序"的事件日志通道要用）
      3. 建计划任务 EgressGuard：以**当前用户 + 最高权限 + S4U** 运行守护
         —— 关键：不用 SYSTEM。SYSTEM 跑在会话 0，弹窗/桌面原因卡/Toast
            全都送不到你的桌面，而"告诉那个程序为什么被掐"正是本工具的核心功能。
            S4U + Highest 既拿到提权令牌（能改防火墙、能掐连接），
            又跑在你自己的会话里（通知能到你眼前），且不弹 UAC。
      4. 建桌面快捷方式 + 可选地启用防火墙与常备规则
      5. 启动守护并等它响应
#>

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$TaskName = 'EgressGuard'
$EvtSource = 'EgressGuard'

function Say($msg, $color = 'Gray') { Write-Host $msg -ForegroundColor $color }
function Ok($msg)   { Say "  [OK]   $msg" 'Green' }
function Warn($msg) { Say "  [警告] $msg" 'Yellow' }
function Fail($msg) { Say "  [失败] $msg" 'Red' }

Say ""
Say "========================================================" 'Cyan'
Say "  EgressGuard 安装 —— 昆明 IP / 本机指纹零泄露闸门" 'Cyan'
Say "========================================================" 'Cyan'
Say ""

# ---- 0. 管理员检查 ----
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Fail "必须以管理员身份运行。右键本脚本 -> 以管理员身份运行。"
    Read-Host "按回车退出"
    exit 1
}
Ok "管理员权限已确认"
Say "  安装目录：$Root"

# ---- 1. 选定运行形态 ----
Say ""
Say "[1/5] 选定运行形态" 'White'

$coreExe = Join-Path $Root 'dist\EgressGuardCore.exe'
$dashExe = Join-Path $Root 'dist\EgressGuard.exe'

$useExe = (Test-Path $coreExe) -and (Test-Path $dashExe)
$coreTarget = $null
$coreArgs = ''
$dashTarget = $null
$dashArgs = ''

if ($useExe) {
    # 直接用 dist\ 下的 exe，**不再复制到根目录**。
    #
    # 以前要复制，是因为数据目录跟着 exe 走（exe 在哪，data\ 就在哪），
    # 不复制就会出现 dist\data\ 和根目录 data\ 两份互不相干的配置。
    # 现在数据目录统一在 %LOCALAPPDATA%\EgressGuard\，
    # exe 放哪都一样，复制这一步就没必要了。
    $coreTarget = $coreExe
    $dashTarget = $dashExe
    Ok "使用已打包 exe（本机无需 Python）"
    Say "      守护  : $coreTarget" 'DarkGray'
    Say "      仪表盘: $dashTarget" 'DarkGray'
    Say "      大小  : $([math]::Round((Get-Item $coreTarget).Length/1MB,1)) MB + $([math]::Round((Get-Item $dashTarget).Length/1MB,1)) MB" 'DarkGray'
} else {
    Say "  未找到 dist\EgressGuardCore.exe，回退到源码形态" 'DarkGray'
    $pythonw = $null
    $python = $null
    $cands = @()
    $cands += (Get-Command pythonw.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    $cands += (Get-Command python.exe  -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    $cands += (Get-ChildItem "$env:LOCALAPPDATA\Programs\Python" -Recurse -Filter pythonw.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $cands += (Get-ChildItem "C:\Python*" -Recurse -Filter pythonw.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    foreach ($c in $cands) {
        if ($c -and (Test-Path $c) -and $c -notlike '*WindowsApps*') {
            if ($c -like '*pythonw.exe') { if (-not $pythonw) { $pythonw = $c } }
            elseif (-not $python) { $python = $c }
        }
    }
    if (-not $pythonw -and $python) {
        $maybe = Join-Path (Split-Path $python) 'pythonw.exe'
        if (Test-Path $maybe) { $pythonw = $maybe }
    }
    if (-not $pythonw) {
        Fail "既没有打包好的 exe，也找不到 pythonw.exe。"
        Say "         先跑 tools\build_exe.py 打包，或装 Python 3.9+ 并加入 PATH。" 'Yellow'
        Read-Host "按回车退出"; exit 1
    }
    if (-not $python) { $python = $pythonw -replace 'pythonw\.exe$', 'python.exe' }
    Ok "使用源码形态"
    Say "      pythonw : $pythonw" 'DarkGray'
    Say "      版本    : $(& $python --version 2>&1)" 'DarkGray'
    $coreTarget = $pythonw
    $coreArgs = "`"$Root\run_core.py`""
    $dashTarget = $pythonw
    $dashArgs = "`"$Root\run_dashboard.py`""
}

# ---- 2. 注册事件日志源 ----
Say ""
Say "[2/5] 注册 Windows 事件日志源" 'White'
try {
    if ([System.Diagnostics.EventLog]::SourceExists($EvtSource)) {
        Ok "事件源 $EvtSource 已存在"
    } else {
        New-EventLog -LogName Application -Source $EvtSource -ErrorAction Stop
        Ok "已注册事件源 $EvtSource -> 应用程序日志"
    }
} catch {
    Warn "注册事件源失败（不影响主功能，事件日志通道会退化）：$($_.Exception.Message)"
}

# ---- 3. 建计划任务 ----
Say ""
Say "[3/5] 建立提权守护计划任务" 'White'

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Say "  已存在同名任务，先停止并删除…" 'DarkGray'
    Stop-ScheduledTask  -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 600
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Ok "旧任务已清理"
}

$action = New-ScheduledTaskAction -Execute $coreTarget -Argument $coreArgs `
    -WorkingDirectory $Root

$triggers = @(
    (New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME")
)

$principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType S4U -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew

try {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
        -Principal $principal -Settings $settings `
        -Description "EgressGuard 零泄漏闸门：阻断昆明 IP 与本机指纹外泄" -Force | Out-Null
    Ok "计划任务已建立（登录时自启，最高权限，不弹 UAC）"
} catch {
    Fail "计划任务建立失败：$($_.Exception.Message)"
    Warn "改用 SYSTEM 身份重试（注意：SYSTEM 在会话 0，弹窗/桌面原因卡送不到你的桌面）"
    try {
        $p2 = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
            -Principal $p2 -Settings $settings `
            -Description "EgressGuard 零泄漏闸门" -Force | Out-Null
        Ok "计划任务已建立（SYSTEM 身份）"
    } catch {
        Fail "仍然失败：$($_.Exception.Message)"
    }
}

# ---- 4. 启动守护 ----
Say ""
Say "[4/5] 启动守护进程" 'White'
Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

$apiPort = 47821
$dataDir = Join-Path $env:LOCALAPPDATA 'EgressGuard'
$cfgPath = Join-Path $dataDir 'config.json'
for ($i = 0; $i -lt 25; $i++) {
    Start-Sleep -Milliseconds 700
    try {
        $r = Invoke-WebRequest "http://127.0.0.1:$apiPort/api/health" -UseBasicParsing -TimeoutSec 2
        if ($r.StatusCode -eq 200) { Ok "守护已响应：$($r.Content)"; break }
    } catch {}
    if ($i -eq 24) { Warn "守护暂未响应。首次刷新网卡较慢，稍等十几秒再看仪表盘。" }
}

# ---- 5. 快捷方式 + 可选防火墙 ----
Say ""
Say "[5/5] 桌面快捷方式与防火墙" 'White'
try {
    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'EgressGuard 闸门.lnk'))
    $lnk.TargetPath = $dashTarget
    $lnk.Arguments = $dashArgs
    $lnk.WorkingDirectory = $Root
    $lnk.Description = "EgressGuard 仪表盘"
    $lnk.IconLocation = "$env:SystemRoot\System32\shell32.dll,78"
    $lnk.Save()
    Ok "桌面快捷方式：EgressGuard 闸门"
} catch {
    Warn "创建快捷方式失败：$($_.Exception.Message)"
}

Say "  当前 Windows 防火墙状态：" 'DarkGray'
foreach ($p in (Get-NetFirewallProfile)) {
    $st = if ($p.Enabled) { '已启用' } else { '已关闭' }
    $col = if ($p.Enabled) { 'Green' } else { 'Red' }
    Say "      $($p.Name.PadRight(8)) $st   出站默认=$($p.DefaultOutboundAction)" $col
}
$ans = Read-Host "  是否现在启用防火墙并安装常备规则（IPv6 全封 + 指纹信道封杀）？(y/N)"
if ($ans -match '^[yY]') {
    try {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
        Ok "防火墙已启用（三个配置文件）"
    } catch { Fail "启用防火墙失败：$($_.Exception.Message)" }

    $physAliases = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and
        $_.InterfaceDescription -notmatch 'Tunnel|wintun|TAP|WireGuard' }).Name
    if ($physAliases) {
        try {
            Remove-NetFirewallRule -Name 'EgressGuard::STATIC::BLOCK_IPV6' -ErrorAction SilentlyContinue
            New-NetFirewallRule -Name 'EgressGuard::STATIC::BLOCK_IPV6' `
                -DisplayName 'EgressGuard 阻断物理网卡 IPv6 出站' -Group 'EgressGuard' `
                -Direction Outbound -Action Block -Protocol Any `
                -RemoteAddress @('2000::/3') `
                -InterfaceAlias @($physAliases) -Profile Any -Enabled True | Out-Null
            Ok "IPv6 出站已在物理网卡上封杀（$($physAliases -join ', ')）"
        } catch { Fail "IPv6 规则失败：$($_.Exception.Message)" }

        try {
            Remove-NetFirewallRule -Name 'EgressGuard::STATIC::BLOCK_FINGERPRINT' -ErrorAction SilentlyContinue
            Remove-NetFirewallRule -Name 'EgressGuard::STATIC::BLOCK_FINGERPRINTU' -ErrorAction SilentlyContinue
            New-NetFirewallRule -Name 'EgressGuard::STATIC::BLOCK_FINGERPRINT' `
                -DisplayName 'EgressGuard 阻断指纹信道(TCP)' -Group 'EgressGuard' `
                -Direction Outbound -Action Block -Protocol TCP `
                -RemotePort @(139,445) -InterfaceAlias @($physAliases) `
                -Profile Any -Enabled True | Out-Null
            New-NetFirewallRule -Name 'EgressGuard::STATIC::BLOCK_FINGERPRINTU' `
                -DisplayName 'EgressGuard 阻断指纹信道(UDP)' -Group 'EgressGuard' `
                -Direction Outbound -Action Block -Protocol UDP `
                -RemotePort @(137,138,1900,3702,5353,5355) -InterfaceAlias @($physAliases) `
                -Profile Any -Enabled True | Out-Null
            Ok "指纹信道已封杀（NetBIOS / mDNS / LLMNR / SMB / SSDP / WS-Discovery）"
        } catch { Fail "指纹信道规则失败：$($_.Exception.Message)" }
    }
} else {
    Warn "已跳过。可以稍后在仪表盘上点「启用防火墙」「装常备规则」。"
}

# ---- 汇总 ----
Say ""
Say "========================================================" 'Cyan'
Say "  安装完成" 'Green'
Say "========================================================" 'Cyan'
Say ""
Say "  运行形态 : $(if ($useExe) { '打包 exe（无需 Python）' } else { '源码 + Python' })" 'White'
Say "  守护进程 : 计划任务 '$TaskName'（已启动，登录时自启）" 'White'
Say "  仪表盘   : 桌面「EgressGuard 闸门」快捷方式" 'White'
Say "  本地 API : http://127.0.0.1:$apiPort/api/status" 'White'
Say "  数据目录 : $dataDir" 'White'
Say "  事件日志 : $(Join-Path $dataDir 'events.jsonl')" 'White'
Say "  配置     : $cfgPath" 'White'
Say ""
Say "  下一步（重要）：" 'Yellow'
Say "    1. 打开仪表盘，确认「出口」显示的是境外 IP" 'Yellow'
Say "    2. 先保持「观察」档跑几分钟，看判定有没有误报" 'Yellow'
Say "    3. 无误报后打开「闸门」开关 -> 此时是演练档（只通知不动手）" 'Yellow'
Say "    4. 再确认一轮，最后关掉「演练」进入实弹" 'Yellow'
Say ""
Say "  紧急恢复：仪表盘上的红色「紧急恢复网络」按钮，或跑 卸载_右键管理员运行.bat" 'DarkGray'
Say "  系统托盘   : 启动仪表盘后，托盘图标会常驻（绿=零泄漏 / 红=有泄漏 / 黄=闸门未启用）" 'White'
Say "                 右键图标可查零泄漏自检、开关闸门、打开数据目录与日志" 'DarkGray'
Say "  零泄漏自检 : $(Join-Path $Root 'dist\EgressGuardCore.exe') --assert   （退出码 0=零泄漏，1=有泄漏）" 'DarkGray'
Say ""
Say "  集成方怎么判断闸门状态：" 'DarkGray'
Say "    1. GET http://127.0.0.1:$apiPort/api/health   -> 通了就是活着" 'DarkGray'
Say "    2. 连不上时读 $(Join-Path $dataDir 'state.json')" 'DarkGray'
Say "       last_heartbeat 在 30 秒内 -> 守护正在重启（不是没装）" 'DarkGray'
Say "       文件不存在或心跳过期   -> 闸门没在跑" 'DarkGray'
Say ""
Read-Host "按回车退出"
