# =====================================================================================
# ADVANCED WINDOWS NETWORK CHECK — VERSION 5.1
# Compatible with Windows 10/11 — NextDNS, Quad9, DoH/DoT, ISP router, VPN
# =====================================================================================
# History:
#   v1  : Base script
#   v2  : Connectivity fix, active DNS, ports, WinHTTP proxy, ISP IPv6
#   v3  : Full NextDNS, TCP/UDP ports, suspicious processes, sub-scores, HTML redesign
#   v4  : [NEW 01] Gateway (router) latency
#         [NEW 02] Network speed test (Cloudflare download/upload)
#         [NEW 03] Captive portal detection
#         [NEW 04] DNS leak detection
#         [NEW 05] Active outbound connections with owning process
#         [NEW 06] Suspicious root certificate audit
#         [NEW 07] Known Wi-Fi network history
#         [NEW 08] Internet Connection Sharing (ICS) detection
#         [NEW 09] IPv6 leak detection
#         [NEW 10] Comparison with the previous report (JSON)
#         [FIX 01] Removed Safe-Cmd (dead code)
#         [FIX 02] Consolidated Get-LatStat/Get-SC into Get-ColorByScore
#         [FIX 03] -Silent mode for scheduled execution
#         [FIX 04] HTML: new advanced Network & Security section
#   v4.3 : [FIX 05] DNS cache "Blocked": real detection via the resolved IP (0.0.0.0/127.0.0.1)
#                   instead of a non-functional PTR pattern that never matched anything
#         [FIX 06] Tightened DGA heuristic (length >=10, vowel ratio <=15%, excluding
#                   labels with a hyphen) to reduce false positives on legitimate technical names
#         [FIX 07] Expanded DGA whitelist (spotify.com, linkedin.com, brave.com, mozilla.net, etc.)
#         [NEW 11] Known telemetry list aligned with Block-Telemetry_v5: domains that are
#                   deliberately blocked telemetry are no longer wrongly classified as "Potential DGA"
#   v4.4 : [NEW 12] Direct reading of the hosts file (in addition to the DNS cache): counts the
#                   actual number of null-routed domains (0.0.0.0/127.0.0.1), distinguishes the
#                   Block-Telemetry_v5 block from the rest, and shows the coverage rate observed in the cache
#                   — the DNS cache only reflects domains actually queried recently,
#                   not everything configured in the hosts file
#   v5.1 : [NEW 13] -SelfTest: validates the key functions (Get-ColorByScore, Get-ScoreState,
#                   Test-CategoryEnabled, packet loss calculation) without running the full analysis
#         [NEW 14] -Category: filters the optional/expensive sections (Speed, RootCerts,
#                   WiFi, Comparison) for a targeted diagnostic without rerunning everything
#         [NEW 15] -SkipSpeedTest: dedicated shortcut to skip the throughput test (useful in a scheduled task)
#         [NEW 16] -PurgeDays: automatic purge of old CSV/HTML/JSON reports (default 60 days)
#         [NEW 17] Packet loss (%) added to the gateway latency test, alongside avg/min/max
#         [NEW 18] Hosts file freshness: alerts if the Block-Telemetry block hasn't been
#                   updated in a long time (local proxy, no network call to an external source)
#         [NEW 19] SVG sparkline of the global score over the JSON report history (inline in the HTML)
#         [NEW 20] Desktop toast notification at the end of execution (score + errors/warnings)
#         [NEW 21] Live JS filter in the HTML table (text search + filter by status)
#         [FIX 08] Replaced System.Net.WebClient (obsolete, no reliable timeout) with
#                   Invoke-WebRequest -TimeoutSec for the speed test and captive portal detection
#         [FIX 09] -SelfTest: $script:T += failed after the 1st assertion (the initial $null
#                   wasn't cast to an array in this specific context -> op_Addition failed from the 2nd
#                   call onward). Replaced with an explicit List[object], immune to this pitfall.
#         [FIX 10] Desktop toast silently invisible: ToastNotificationManager (WinRT) requires
#                   an AUMID registered via a Start menu shortcut for an unpackaged
#                   script — otherwise it fails silently. Replaced with NotifyIcon.ShowBalloonTip,
#                   which works reliably with no prior configuration.
#   v5.1 : [FIX 11] Removed `#Requires -RunAsAdministrator`: PowerShell refused to even start the script
#                   from a non-elevated session (ScriptRequiresElevation), so the built-in
#                   auto-elevation block below was unreachable. The self-elevation block now works as documented.
#         [NEW 22] Full English translation (console, HTML report, comments, score states and -Category values:
#                   Speed, RootCerts, WiFi, Comparison). JSON/CSV field names are unchanged (Categorie, Element, Valeur, Statut, SousScore).
#         [FIX 12] Locale-independent parsing: netsh wlan (EN/FR labels), adapter LinkSpeed (Gbps / Gbits/s,
#                   decimal comma), culture-neutral ISO dates (yyyy-MM-dd) in the report.
#         [FIX 14] Speed test: Invoke-WebRequest progress bar disabled during the test (it throttled PS 5.1 downloads and
#                   under-reported the throughput) + warm-up request so TLS setup isn't timed.
#         [FIX 15] Routing: a single default route was reported as "Multiple routes" (.Count on a lone CIM object).
#         [FIX 16] Hosts file: Block-Telemetry markers aligned with Block-Telemetry.ps1 (+ legacy FR markers).
#         [FIX 17] Hosts file age is only scored when a Block-Telemetry block exists (no penalty for users without it).
#         [FIX 18] Wi-Fi history no longer runs netsh with key=clear (passwords are never retrieved, only the presence of a key).
#         [NEW 23] Console restyled after Check-Security: framed numbered banners, icon | category │ check : value lines,
#                   wrapped long values, gauge scores, error/warning recap and » report paths.
#         [FIX 13] Removed the stale Authenticode signature block (invalidated by any edit).
#                   Re-sign with Sign-MyScripts.ps1 before deployment if needed.
# =====================================================================================

param(
    [switch]$Silent,            # [FIX 03] Silent mode: generates the files without showing the console
    [switch]$SelfTest,          # [NEW 13] Validates the key functions and exits without running the full analysis
    [string[]]$Category = @("All"),  # [NEW 14] Filters the optional sections: Speed, RootCerts, WiFi, Comparison
    [switch]$SkipSpeedTest,     # [NEW 15] Shortcut to skip the throughput test (equivalent to -Category without Speed)
    [int]$PurgeDays = 60        # [NEW 16] Purges CSV/HTML/JSON reports older than N days (0 = disabled)
)

#region AUTO-ELEVATION

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $args = "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`""
    if ($Silent)       { $args += " -Silent" }
    if ($SelfTest)     { $args += " -SelfTest" }
    if ($SkipSpeedTest){ $args += " -SkipSpeedTest" }
    if ($Category -and $Category.Count -gt 0 -and $Category[0] -ne "All") {
        $args += " -Category " + (($Category | ForEach-Object { "`"$_`"" }) -join ",")
    }
    if ($PurgeDays -ne 60) { $args += " -PurgeDays $PurgeDays" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $args
    exit
}
Set-ExecutionPolicy Bypass -Scope Process -Force

#endregion

#region INITIALIZATION

$Results           = @()
$ScoreConnectivity = 100
$ScoreSecurity     = 100
$ScoreDNS          = 100

$IsWifi            = $false
$IsEthernet        = $false
$IsVPN             = $false
$MainAdapter       = $null
$NextDNSInstalled  = $false
$GatewayIP         = $null

$Timestamp  = Get-Date -Format "yyyy-MM-dd_HH-mm"
$OutputDir  = "$env:USERPROFILE\Desktop\Maintenance_Reports\Check Network"
$CsvPath    = "$OutputDir\Network_Report_$Timestamp.csv"
$HtmlPath   = "$OutputDir\Network_Report_$Timestamp.html"
$JsonPath   = "$OutputDir\Network_Report_$Timestamp.json"

# Create the output folder if it doesn't exist
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# [NEW 10] Look for the most recent JSON report in the dedicated folder
$PreviousJson = Get-ChildItem "$OutputDir\Network_Report_*.json" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

#endregion

#region FUNCTIONS

function Add-Result {
    param(
        [string]$Categorie,
        [string]$Element,
        [string]$Valeur,
        [string]$Statut,
        [string]$Sous = "General"
    )
    $script:Results += [PSCustomObject]@{
        Categorie = $Categorie
        Element   = $Element
        Valeur    = $Valeur
        Statut    = $Statut
        SousScore = $Sous
    }
    $p = switch ($Statut) { "ERROR" { 15 } "WARNING" { 5 } default { 0 } }
    if ($p -gt 0) {
        switch ($Sous) {
            "Connectivity" { $script:ScoreConnectivity -= $p }
            "Security"     { $script:ScoreSecurity     -= $p }
            "DNS"          { $script:ScoreDNS          -= $p }
            default {
                $script:ScoreConnectivity -= [Math]::Floor($p / 3)
                $script:ScoreSecurity     -= [Math]::Floor($p / 3)
                $script:ScoreDNS          -= [Math]::Floor($p / 3)
            }
        }
    }
}

function Show-Step {
    param([string]$Text, [int]$Percent)
    if (-not $Silent) {
        Write-Progress -Activity "Windows Network Analysis v5.1" -Status $Text -PercentComplete $Percent
    }
}

# [FIX 02] Single color/label function for scores (replaces Get-LatStat + Get-SC)
function Get-ColorByScore {
    param([int]$S)
    if ($S -ge 90) { return "ok" }
    if ($S -ge 60) { return "warn" }
    return "err"
}

function Get-ScoreState {
    param([int]$S)
    if ($S -ge 90) { "EXCELLENT" } elseif ($S -ge 75) { "GOOD" } elseif ($S -ge 50) { "FAIR" } else { "CRITICAL" }
}
function Get-ScoreColor {
    param([int]$S)
    if ($S -ge 90) { "Green" } elseif ($S -ge 75) { "Yellow" } elseif ($S -ge 50) { "DarkYellow" } else { "Red" }
}

function Test-TCPConnect {
    param([string]$Target, [int]$Port, [int]$TimeoutMs = 3000)
    try {
        $SW    = [System.Diagnostics.Stopwatch]::StartNew()
        $TCP   = New-Object System.Net.Sockets.TcpClient
        $Async = $TCP.BeginConnect($Target, $Port, $null, $null)
        $Wait  = $Async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        $SW.Stop()
        if ($Wait -and $TCP.Connected) {
            try { $TCP.EndConnect($Async) } catch {}
            $TCP.Close()
            return [PSCustomObject]@{ Success = $true; LatMs = $SW.ElapsedMilliseconds }
        }
        $TCP.Close()
        return [PSCustomObject]@{ Success = $false; LatMs = 0 }
    }
    catch { return [PSCustomObject]@{ Success = $false; LatMs = 0 } }
}

function Resolve-WithLatency {
    param([string]$Name, [string]$Server = "")
    try {
        $SW = [System.Diagnostics.Stopwatch]::StartNew()
        $R  = if ($Server) {
            Resolve-DnsName -Name $Name -Server $Server -Type A -ErrorAction Stop |
                Where-Object { $_.Type -eq "A" } | Select-Object -First 1
        } else {
            Resolve-DnsName -Name $Name -Type A -ErrorAction Stop |
                Where-Object { $_.Type -eq "A" } | Select-Object -First 1
        }
        $SW.Stop()
        if ($R) { return [PSCustomObject]@{ Success = $true; IP = $R.IPAddress; LatMs = $SW.ElapsedMilliseconds } }
    }
    catch {}
    return [PSCustomObject]@{ Success = $false; IP = ""; LatMs = 0 }
}

function Get-ProcName {
    param([int]$ProcID)
    try { return (Get-Process -Id $ProcID -ErrorAction Stop).ProcessName }
    catch { return "Unknown" }
}

function Get-ProcPath {
    param([int]$ProcID)
    try { return (Get-Process -Id $ProcID -ErrorAction Stop).MainModule.FileName }
    catch { return "" }
}

# [NEW 14] Optional/expensive sections controllable via -Category ("core" sections always run)
function Test-CategoryEnabled {
    param([string]$Name)
    if (-not $script:Category -or $script:Category.Count -eq 0) { return $true }
    if ($script:Category -contains "All") { return $true }
    return ($script:Category -contains $Name)
}

# [NEW 17] Calculates the packet loss rate from the number of successes / attempts
function Get-PacketLossPct {
    param([int]$Success, [int]$Total)
    if ($Total -le 0) { return 0 }
    return [Math]::Round((($Total - $Success) / $Total) * 100, 0)
}

# [NEW 13] -SelfTest mode: validates the critical functions without running the full network analysis
function Invoke-SelfTest {
    # [FIX 09] $script:T += used to fail: $null + [PSCustomObject] does not turn into an array
    # in this context, so from the 2nd Add onward the real type becomes a single object -> op_Addition fails.
    # A List[object] with .Add() is immune to this pitfall and more efficient.
    $script:SelfTestResults = [System.Collections.Generic.List[object]]::new()
    function Assert-Eq($Name, $Actual, $Expected) {
        $script:SelfTestResults.Add([PSCustomObject]@{ Test = $Name; Pass = ($Actual -eq $Expected); Got = $Actual; Want = $Expected })
    }

    Assert-Eq "Get-ColorByScore(100)"        (Get-ColorByScore 100)        "ok"
    Assert-Eq "Get-ColorByScore(90)"         (Get-ColorByScore 90)         "ok"
    Assert-Eq "Get-ColorByScore(89)"         (Get-ColorByScore 89)         "warn"
    Assert-Eq "Get-ColorByScore(60)"         (Get-ColorByScore 60)         "warn"
    Assert-Eq "Get-ColorByScore(59)"         (Get-ColorByScore 59)         "err"
    Assert-Eq "Get-ScoreState(95)"           (Get-ScoreState 95)           "EXCELLENT"
    Assert-Eq "Get-ScoreState(80)"           (Get-ScoreState 80)           "GOOD"
    Assert-Eq "Get-ScoreState(60)"           (Get-ScoreState 60)           "FAIR"
    Assert-Eq "Get-ScoreState(10)"           (Get-ScoreState 10)           "CRITICAL"
    Assert-Eq "Test-CategoryEnabled(All)"    (Test-CategoryEnabled "Speed") $true
    Assert-Eq "Get-PacketLossPct(4/4)"       (Get-PacketLossPct 4 4)       0
    Assert-Eq "Get-PacketLossPct(2/4)"       (Get-PacketLossPct 2 4)       50
    Assert-Eq "Get-PacketLossPct(0/4)"       (Get-PacketLossPct 0 4)       100

    $script:Category = @("Speed")
    Assert-Eq "Test-CategoryEnabled(active filter)" (Test-CategoryEnabled "WiFi") $false
    $script:Category = @("All")

    $T = $script:SelfTestResults

    Write-Host ""
    Write-Host "  === SELFTEST Check-Network v5.1 ===" -ForegroundColor Cyan
    foreach ($Item in $T) {
        $Color = if ($Item.Pass) { "Green" } else { "Red" }
        $Mark  = if ($Item.Pass) { "[OK]" } else { "[FAIL]" }
        Write-Host ("  {0,-7} {1,-35} got={2} want={3}" -f $Mark, $Item.Test, $Item.Got, $Item.Want) -ForegroundColor $Color
    }
    $PassCount = ($T | Where-Object { $_.Pass }).Count
    Write-Host ""
    Write-Host "  Result: $PassCount / $($T.Count) assertions passed" -ForegroundColor $(if ($PassCount -eq $T.Count) { "Green" } else { "Red" })
    Write-Host ""
}

if ($SelfTest) {
    Invoke-SelfTest
    exit
}

# [NEW 20] Desktop notification (system balloon) at the end of execution
function Send-NetworkToast {
    param([int]$Score, [int]$Errors, [int]$Warnings)
    # [FIX 10] The WinRT ToastNotificationManager API requires an AUMID registered via a
    # Start menu shortcut to work from an unpackaged PS script — without it, the call
    # fails silently (no error, no notification). NotifyIcon.ShowBalloonTip works
    # reliably from any script, with no prior configuration.
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing        -ErrorAction Stop

        $StatusLine = if ($Errors -gt 0) { "$Errors error(s), $Warnings warning(s)" }
                      elseif ($Warnings -gt 0) { "$Warnings warning(s)" }
                      else { "No issues detected" }

        $IconType = if ($Errors -gt 0) { [System.Windows.Forms.ToolTipIcon]::Error }
                    elseif ($Warnings -gt 0) { [System.Windows.Forms.ToolTipIcon]::Warning }
                    else { [System.Windows.Forms.ToolTipIcon]::Info }

        $NotifyIcon = New-Object System.Windows.Forms.NotifyIcon
        $NotifyIcon.Icon             = [System.Drawing.SystemIcons]::Information
        $NotifyIcon.Visible          = $true
        $NotifyIcon.BalloonTipTitle  = "Check-Network — Score $Score/100"
        $NotifyIcon.BalloonTipText   = $StatusLine
        $NotifyIcon.BalloonTipIcon   = $IconType
        $NotifyIcon.ShowBalloonTip(6000)

        # The balloon must stay "alive" for a few seconds so it can show before Dispose()
        Start-Sleep -Seconds 4
        $NotifyIcon.Dispose()
    }
    catch {
        # Notifications unavailable (session with no interactive desktop, RDP disconnected, etc.) — non-blocking
    }
}

#endregion

#region STARTUP

if (-not $Silent) {
    Clear-Host
    Write-Host ""
    Write-Host ("  ╔" + ("═" * 62) + "╗") -ForegroundColor Cyan
    Write-Host "  ║" -NoNewline -ForegroundColor Cyan
    Write-Host (" ADVANCED WINDOWS NETWORK ANALYSIS  ·  v5.1").PadRight(62) -NoNewline -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan
    Write-Host ("  ╚" + ("═" * 62) + "╝") -ForegroundColor Cyan
    Write-Host ""
}

#endregion

#region WINDOWS VERSION

Show-Step "Detecting system..." 2
try {
    $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Add-Result "System" "Windows Version" "$($OS.Caption) (Build $($OS.BuildNumber))" "OK" "General"
}
catch { Add-Result "System" "Windows Version" "Could not detect" "INFO" "General" }

#endregion

#region CONNECTION TYPE DETECTION

Show-Step "Detecting connection type..." 4

try {
    $ActiveAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
    $VPNAdapters = @(); $WifiAdapters = @(); $EthernetAdapters = @()

    foreach ($A in $ActiveAdapters) {
        if ($A.Name -match "(?i)vpn|tunnel|tap|tun|wireguard|openvpn|nordvpn|expressvpn|proton" -or
            $A.InterfaceDescription -match "(?i)vpn|tunnel|tap|tun|wireguard|openvpn") {
            $VPNAdapters += $A; $script:IsVPN = $true
        }
        elseif ($A.MediaType -match "(?i)802\.11" -or
                $A.Name -match "(?i)wi.fi|wifi|wireless|wlan" -or
                $A.InterfaceDescription -match "(?i)wireless|wi.fi|802\.11") {
            $WifiAdapters += $A; $script:IsWifi = $true
        }
        else { $EthernetAdapters += $A; $script:IsEthernet = $true }
    }

    $DefaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1

    if ($DefaultRoute) {
        $script:MainAdapter = Get-NetAdapter -InterfaceIndex $DefaultRoute.InterfaceIndex -ErrorAction SilentlyContinue
        $script:GatewayIP   = $DefaultRoute.NextHop
    }
    if (-not $script:MainAdapter) { $script:MainAdapter = $ActiveAdapters | Select-Object -First 1 }

    $ConnTypes = @()
    if ($IsEthernet) { $ConnTypes += "Ethernet" }
    if ($IsWifi)     { $ConnTypes += "Wi-Fi" }
    if ($IsVPN)      { $ConnTypes += "VPN" }

    if ($ConnTypes.Count -gt 0) {
        Add-Result "Connection" "Detected type(s)" ($ConnTypes -join " + ") "OK" "Connectivity"
        Add-Result "Connection" "Main interface" $script:MainAdapter.Name "OK" "Connectivity"
    }
    else { Add-Result "Connection" "Detected type" "No active interface" "ERROR" "Connectivity" }

    foreach ($V in $VPNAdapters) {
        Add-Result "VPN" "VPN interface" $V.InterfaceDescription "INFO" "Connectivity"
    }
}
catch { Add-Result "Connection" "Interface detection" "Error: $_" "ERROR" "Connectivity" }

#endregion

#region NETWORK INTERFACES

Show-Step "Analyzing network interfaces..." 6

try {
    foreach ($A in (Get-NetAdapter -ErrorAction Stop)) {
        $Label  = switch ($A.Status) {
            "Up"           { "Connected"    }
            "Disabled"     { "Disabled"     }
            "Disconnected" { "Disconnected" }
            default        { $A.Status }
        }
        $Statut = switch ($A.Status) {
            "Up"           { "OK"   }
            "Disabled"     { "INFO" }
            "Disconnected" { "INFO" }
            default        { "WARNING" }
        }
        Add-Result "Interfaces" $A.Name "$Label | $($A.InterfaceDescription)" $Statut "Connectivity"
    }
}
catch { Add-Result "Interfaces" "Analysis" "Error: $_" "ERROR" "Connectivity" }

#endregion

#region IP ADDRESSES / DNS / GATEWAY

Show-Step "Analyzing IP, DNS, gateway..." 8

try {
    $IPConfigs = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.NetAdapter.Status -eq "Up" }

    foreach ($Cfg in $IPConfigs) {
        $IfName = $Cfg.InterfaceAlias

        foreach ($v4 in $Cfg.IPv4Address) {
            Add-Result "IP" "$IfName - IPv4" "$($v4.IPAddress) / $($v4.PrefixLength)" "OK" "Connectivity"
        }
        foreach ($v6 in $Cfg.IPv6Address) {
            if ($v6.IPAddress -notmatch "^fe80") {
                Add-Result "IP" "$IfName - IPv6" $v6.IPAddress "INFO" "Connectivity"
            }
        }
        if ($Cfg.IPv4DefaultGateway) {
            Add-Result "IP" "$IfName - Gateway" $Cfg.IPv4DefaultGateway.NextHop "OK" "Connectivity"
        }

        $KnownDNSv4 = @("8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1",
            "208.67.222.222","208.67.220.220","9.9.9.9","149.112.112.112",
            "4.2.2.1","4.2.2.2","168.63.129.16")
        $KnownDNSv6 = @("2001:4860:4860::8888","2001:4860:4860::8844",
            "2606:4700:4700::1111","2606:4700:4700::1001",
            "2620:fe::fe","2620:fe::9","2620:fe::fe:9")

        $DNSv4 = $Cfg.DNSServer | Where-Object { $_.AddressFamily -eq 2  } | Select-Object -ExpandProperty ServerAddresses | Select-Object -Unique
        $DNSv6 = $Cfg.DNSServer | Where-Object { $_.AddressFamily -eq 23 } | Select-Object -ExpandProperty ServerAddresses | Select-Object -Unique

        if ($DNSv4) {
            $AllOK = $true
            foreach ($D in $DNSv4) {
                $Priv      = $D -match "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)"
                $IsNextDNS = $D -match "^45\.90\.(2[89]|3[01])\."
                if (-not $Priv -and -not $IsNextDNS -and $D -notin $KnownDNSv4) { $AllOK = $false }
            }
            $DNSv4Stat = if ($AllOK) { "OK" } else { "WARNING" }
            Add-Result "DNS" "$IfName - DNS IPv4" ($DNSv4 -join ", ") $DNSv4Stat "DNS"
        }
        else { Add-Result "DNS" "$IfName - DNS IPv4" "None configured" "WARNING" "DNS" }

        if ($DNSv6) {
            $GW6    = if ($Cfg.IPv6DefaultGateway) { $Cfg.IPv6DefaultGateway.NextHop } else { "" }
            $AllOK  = $true
            foreach ($D in $DNSv6) {
                # fec0:: = deprecated site-local (RFC 3879), used as Windows DNS loopback
                $Priv = $D -match "^(fe80:|fc|fd|::1|fec0:)" -or $D -eq $GW6 -or
                        $D -match "^(2a01:cb0|2a01:cb1|2a01:e00|2a01:e35|2a01:e0a|2001:41d0|2a01:4f8|2a01:cb08|2a07:a8c)"
                if (-not $Priv -and $D -notin $KnownDNSv6) { $AllOK = $false }
            }
            $DNSv6Stat = if ($AllOK) { "OK" } else { "WARNING" }
            Add-Result "DNS" "$IfName - DNS IPv6" ($DNSv6 -join ", ") $DNSv6Stat "DNS"
        }
    }
}
catch { Add-Result "IP/DNS" "IP Analysis" "Error: $_" "ERROR" "Connectivity" }

#endregion

#region GATEWAY LATENCY

# [NEW 01] Latency test to the router (first network hop)
# Latency > 5ms to the router indicates a problem with the cable/Ethernet port or Wi-Fi
Show-Step "Testing gateway (router) latency..." 10

if ($GatewayIP) {
    try {
        $Results_lat = @()
        for ($i = 0; $i -lt 4; $i++) {
            $R = Test-TCPConnect -Target $GatewayIP -Port 80 -TimeoutMs 1000
            if (-not $R.Success) {
                # Port 80 closed on the router — try via ICMP Test-Connection
                try {
                    $Ping = Test-Connection -ComputerName $GatewayIP -Count 1 -ErrorAction Stop
                    $R = [PSCustomObject]@{ Success = $true; LatMs = $Ping.ResponseTime }
                }
                catch { $R = [PSCustomObject]@{ Success = $false; LatMs = 0 } }
            }
            if ($R.Success) { $Results_lat += $R.LatMs }
        }

        if ($Results_lat.Count -gt 0) {
            $AvgLat = [Math]::Round(($Results_lat | Measure-Object -Average).Average, 1)
            $MinLat = ($Results_lat | Measure-Object -Minimum).Minimum
            $MaxLat = ($Results_lat | Measure-Object -Maximum).Maximum
            $LossPct = Get-PacketLossPct -Success $Results_lat.Count -Total 4

            # Thresholds suited to residential routers (Orange, Free, SFR...)
            # Latency up to 25ms is normal depending on network activity
            $LatStatut = if ($AvgLat -le 25)  { "OK" }
                         elseif ($AvgLat -le 50) { "WARNING" }
                         else                    { "ERROR" }

            Add-Result "Gateway" "Latency to $GatewayIP" `
                "Avg $AvgLat ms | Min $MinLat ms | Max $MaxLat ms" $LatStatut "Connectivity"

            # [NEW 17] Packet loss — an unstable Wi-Fi link can have a correct average latency
            # while still losing packets intermittently; the two metrics are complementary
            $LossStatut = if ($LossPct -eq 0) { "OK" } elseif ($LossPct -le 25) { "WARNING" } else { "ERROR" }
            Add-Result "Gateway" "Packet loss to $GatewayIP" "$LossPct% ($($Results_lat.Count)/4 responses)" $LossStatut "Connectivity"
        }
        else {
            Add-Result "Gateway" "Latency to $GatewayIP" "Router did not respond to tests" "INFO" "Connectivity"
        }
    }
    catch {
        Add-Result "Gateway" "Gateway latency test" "Error: $_" "INFO" "Connectivity"
    }
}
else {
    Add-Result "Gateway" "Gateway latency" "Gateway not detected" "INFO" "Connectivity"
}

#endregion

#region NETWORK SPEED

# [NEW 02] Download throughput test via speed.cloudflare.com
# Downloads 5 MB from Cloudflare and measures the actual throughput
# [FIX 08] Invoke-WebRequest -TimeoutSec replaces WebClient (reliable timeout, no more indefinite blocking)
# [NEW 14/15] Controllable via -Category Speed or -SkipSpeedTest (useful in a scheduled task)
Show-Step "Testing network speed..." 12

if ($SkipSpeedTest -or -not (Test-CategoryEnabled "Speed")) {
    Add-Result "Speed" "Throughput test" "Skipped (-SkipSpeedTest or -Category)" "INFO" "Connectivity"
}
else {
# [FIX 14] Windows PowerShell 5.1 renders a progress bar for Invoke-WebRequest, which throttles downloads and
# made the measured throughput far lower than the real link speed. Disable it for the test, restore afterwards.
$SavedProgress = $ProgressPreference
$ProgressPreference = "SilentlyContinue"
try {
    $SpeedURL = "https://speed.cloudflare.com/__down?bytes=5000000"
    # Warm-up: open DNS/TCP/TLS first so connection setup is not counted in the timed transfer
    try { $null = Invoke-WebRequest -Uri "https://speed.cloudflare.com/__down?bytes=1000" -UseBasicParsing -TimeoutSec 10 } catch { }
    $SW = [System.Diagnostics.Stopwatch]::StartNew()
    $Resp = Invoke-WebRequest -Uri $SpeedURL -UseBasicParsing -TimeoutSec 15 -Headers @{ "User-Agent" = "Mozilla/5.0" }
    $SW.Stop()

    $Bytes   = $Resp.RawContentLength
    if (-not $Bytes -or $Bytes -le 0) { $Bytes = $Resp.Content.Length }
    $Secs    = $SW.Elapsed.TotalSeconds
    $MbpsDL  = [Math]::Round(($Bytes * 8) / ($Secs * 1000000), 1)

    $SpeedStatut = if ($MbpsDL -ge 50)  { "OK" }
                   elseif ($MbpsDL -ge 10) { "WARNING" }
                   else                    { "ERROR" }

    Add-Result "Speed" "Download (Cloudflare)" "$MbpsDL Mbps ($([Math]::Round($Bytes/1MB,1)) MB in $([Math]::Round($Secs,2))s)" $SpeedStatut "Connectivity"
}
catch {
    Add-Result "Speed" "Download" "Test failed (network or firewall): $_" "INFO" "Connectivity"
}

# Upload test via speed.cloudflare.com (more reliable than httpbin.org)
try {
    $UpURL  = "https://speed.cloudflare.com/__up"
    $UpData = New-Object byte[] 2000000  # 2 MB

    $SW = [System.Diagnostics.Stopwatch]::StartNew()
    $null = Invoke-WebRequest -Uri $UpURL -Method Post -Body $UpData -UseBasicParsing -TimeoutSec 15 `
        -ContentType "application/octet-stream" -Headers @{ "User-Agent" = "Mozilla/5.0" }
    $SW.Stop()

    $MbpsUL   = [Math]::Round((2000000 * 8) / ($SW.Elapsed.TotalSeconds * 1000000), 1)
    $UpStatut = if ($MbpsUL -ge 10) { "OK" } elseif ($MbpsUL -ge 2) { "WARNING" } else { "ERROR" }

    Add-Result "Speed" "Upload (Cloudflare)" "$MbpsUL Mbps" $UpStatut "Connectivity"
}
catch {
    Add-Result "Speed" "Upload" "Test failed: $_" "INFO" "Connectivity"
}
$ProgressPreference = $SavedProgress
}

#endregion

#region CAPTIVE PORTAL

# [NEW 03] Captive portal detection (hotel, cafe, airport networks)
# Windows uses msftconnecttest.com to detect redirects
# [FIX 08] Invoke-WebRequest -TimeoutSec replaces WebClient
Show-Step "Detecting captive portal..." 14

try {
    $CaptiveURL = "http://www.msftconnecttest.com/connecttest.txt"
    $Resp = Invoke-WebRequest -Uri $CaptiveURL -UseBasicParsing -TimeoutSec 8 -Headers @{ "User-Agent" = "Microsoft NCSI" }

    if ($Resp.Content.Trim() -eq "Microsoft Connect Test") {
        Add-Result "Network" "Captive portal" "None — direct connection" "OK" "Security"
    }
    else {
        Add-Result "Network" "Captive portal" "Detected — active redirect (filtered network)" "WARNING" "Security"
    }
}
catch {
    # Timeout or error = possible blocking captive portal
    Add-Result "Network" "Captive portal" "Test failed (possible redirect): $_" "INFO" "Security"
}

#endregion

#region NEXTDNS

Show-Step "Detecting NextDNS..." 16

try {
    $NextDNSApp  = $null
    $RegPaths    = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($Path in $RegPaths) {
        $Found = Get-ItemProperty $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match "(?i)nextdns" }
        if ($Found) { $NextDNSApp = $Found | Select-Object -First 1; break }
    }

    $NextDNSExePaths = @(
        "$env:ProgramFiles\NextDNS\nextdns.exe",
        "${env:ProgramFiles(x86)}\NextDNS\nextdns.exe",
        "$env:LOCALAPPDATA\NextDNS\nextdns.exe",
        "$env:APPDATA\NextDNS\nextdns.exe"
    )
    $NextDNSExe  = $NextDNSExePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    $NextDNSSvc  = Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.ServiceName -match "(?i)nextdns" -or $_.DisplayName -match "(?i)nextdns" } |
        Select-Object -First 1
    $NextDNSProc = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "(?i)nextdns" } | Select-Object -First 1

    $script:NextDNSInstalled = $NextDNSApp -or $NextDNSExe -or $NextDNSSvc

    if ($script:NextDNSInstalled) {
        $Version = if ($NextDNSApp) { $NextDNSApp.DisplayVersion } else { "?" }
        Add-Result "NextDNS" "Installation" "Detected v$Version" "OK" "DNS"

        if ($NextDNSSvc) {
            $SvcS = if ($NextDNSSvc.Status -eq "Running") { "OK" } else { "WARNING" }
            Add-Result "NextDNS" "Service" "$($NextDNSSvc.Status) ($($NextDNSSvc.ServiceName))" $SvcS "DNS"
        }
        if ($NextDNSProc) {
            $MemMB = [Math]::Round($NextDNSProc.WorkingSet64 / 1MB, 1)
            Add-Result "NextDNS" "Process" "PID $($NextDNSProc.Id) — $MemMB MB" "OK" "DNS"
        }

        $ConfigPaths = @(
            "$env:ProgramData\NextDNS\config",
            "$env:APPDATA\NextDNS\config",
            "$env:LOCALAPPDATA\NextDNS\config"
        )
        $ConfigContent = $null
        foreach ($P in $ConfigPaths) {
            if (Test-Path $P) {
                try { $ConfigContent = Get-Content $P -Raw -ErrorAction Stop; break }
                catch {}
            }
        }

        if ($ConfigContent) {
            if ($ConfigContent -match "profile[=\s]+([a-zA-Z0-9]+)") {
                Add-Result "NextDNS" "Profile ID" $Matches[1] "OK" "DNS"
            }
            $Mode = "Classic DNS (port 53)"
            if ($ConfigContent -match "(?i)doh|dns-over-https|https")  { $Mode = "DoH (DNS-over-HTTPS port 443)" }
            elseif ($ConfigContent -match "(?i)dot|dns-over-tls|tls")  { $Mode = "DoT (DNS-over-TLS port 853)" }
            Add-Result "NextDNS" "Transport mode" $Mode "OK" "DNS"
        }
        else {
            try {
                $RegConfig = Get-ItemProperty "HKLM:\SOFTWARE\NextDNS" -ErrorAction Stop
                if ($RegConfig.ProfileID) {
                    Add-Result "NextDNS" "Profile ID (registry)" $RegConfig.ProfileID "OK" "DNS"
                }
            }
            catch {
                Add-Result "NextDNS" "Configuration" "Config via app UI" "INFO" "DNS"
            }
        }

        # Check DNS servers = NextDNS
        try {
            $ActualDNS = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.ServerAddresses.Count -gt 0 } |
                ForEach-Object { $_.ServerAddresses } |
                Where-Object { $_ -ne "127.0.0.1" -and $_ -notmatch "^0\." } |
                Sort-Object -Unique

            $IsNextDNSIP   = $ActualDNS | Where-Object { $_ -match "^45\.90\.(2[89]|3[01])\." }
            $IsLocalhost   = $ActualDNS | Where-Object { $_ -match "^(127\.0\.0\.1|::1)$" }

            if ($IsNextDNSIP) {
                Add-Result "NextDNS" "Active DNS" "NextDNS servers confirmed ($($ActualDNS -join ', '))" "OK" "DNS"
            }
            elseif ($IsLocalhost) {
                Add-Result "NextDNS" "Active DNS" "Local proxy (127.0.0.1) — NextDNS intercepting locally" "OK" "DNS"
            }
            else {
                # Normal with NextDNS Desktop in DoH mode:
                # Windows still sees the router/Quad9 DNS because NextDNS intercepts
                # requests at the application level (not through Windows DNS config)
                Add-Result "NextDNS" "Active DNS" "Application-level DoH mode — NextDNS intercepts before the router ($($ActualDNS -join ', '))" "OK" "DNS"
            }
        }
        catch {
            Add-Result "NextDNS" "DNS check" "Could not verify" "INFO" "DNS"
        }

        # NextDNS latency test
        foreach ($IP in @("45.90.28.1", "45.90.30.1")) {
            $R = Test-TCPConnect -Target $IP -Port 53
            if ($R.Success) {
                $LatS = if ($R.LatMs -le 50) {"OK"} elseif ($R.LatMs -le 150) {"WARNING"} else {"ERROR"}
                Add-Result "NextDNS" "Latency $IP (TCP/53)" "$($R.LatMs) ms" $LatS "DNS"
            }
            else {
                $R2 = Test-TCPConnect -Target $IP -Port 443
                if ($R2.Success) {
                    $LatS = if ($R2.LatMs -le 50) {"OK"} elseif ($R2.LatMs -le 150) {"WARNING"} else {"ERROR"}
                    Add-Result "NextDNS" "Latency $IP (DoH/443)" "$($R2.LatMs) ms" $LatS "DNS"
                }
                else {
                    Add-Result "NextDNS" "Server $IP" "Not directly reachable (normal if DoH via app)" "INFO" "DNS"
                }
            }
        }
    }
    else {
        Add-Result "NextDNS" "Installation" "Not detected" "INFO" "DNS"
    }
}
catch {
    Add-Result "NextDNS" "NextDNS analysis" "Error: $_" "INFO" "DNS"
}

#endregion

#region WINDOWS DNS OVER HTTPS

Show-Step "Checking Windows DoH..." 18

try {
    $DoHKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    $DoHReg = Get-ItemProperty -Path $DoHKey -Name "EnableAutoDoh" -ErrorAction Stop
    $DoHMode = switch ($DoHReg.EnableAutoDoh) {
        0 { "Disabled" }
        1 { "Automatic (if server supports it)" }
        2 { "Forced (everything goes through DoH)" }
        default { "Unknown ($($DoHReg.EnableAutoDoh))" }
    }
    $DoHS = if ($DoHReg.EnableAutoDoh -ge 1) { "OK" } else { "INFO" }
    Add-Result "DoH Windows" "Native DNS-over-HTTPS" $DoHMode $DoHS "DNS"
}
catch {
    if ($script:NextDNSInstalled) {
        Add-Result "DoH Windows" "DNS-over-HTTPS" "Handled by NextDNS (DoH/DoT via app)" "OK" "DNS"
    }
    else {
        Add-Result "DoH Windows" "Native DNS-over-HTTPS" "Not configured (classic unencrypted DNS)" "INFO" "DNS"
    }
}

#endregion

#region INTERNET CONNECTIVITY

Show-Step "Testing Internet connectivity..." 20

$InternetOK       = $false
$DNSProveInternet = $false
$TestDomains      = @("google.com","microsoft.com","cloudflare.com")
$ResolvedCount    = 0
$TotalLatMs       = 0

foreach ($Domain in $TestDomains) {
    $R = Resolve-WithLatency -Name $Domain
    if ($R.Success) { $ResolvedCount++; $TotalLatMs += $R.LatMs }
}

if ($ResolvedCount -ge 2) {
    $InternetOK       = $true
    $DNSProveInternet = $true
    $AvgLat = if ($ResolvedCount -gt 0) { [Math]::Round($TotalLatMs / $ResolvedCount, 0) } else { 0 }
    Add-Result "Internet" "DNS resolution" "$ResolvedCount/$($TestDomains.Count) domains — avg latency $AvgLat ms" "OK" "Connectivity"
}
else {
    Add-Result "Internet" "DNS resolution" "Failed ($ResolvedCount/$($TestDomains.Count))" "WARNING" "Connectivity"
}

try {
    $RealDNS = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.ServerAddresses.Count -gt 0 } |
        ForEach-Object { $_.ServerAddresses } |
        Where-Object { $_ -notmatch "^(0\.|127\.0\.0\.1)" } |
        Sort-Object -Unique

    foreach ($DNS in $RealDNS) {
        $R = Test-TCPConnect -Target $DNS -Port 53
        if ($R.Success) {
            $InternetOK = $true
            $LS = if ($R.LatMs -le 50) {"OK"} elseif ($R.LatMs -le 150) {"WARNING"} else {"ERROR"}
            Add-Result "Internet" "DNS $DNS (TCP/53)" "$($R.LatMs) ms" $LS "Connectivity"
        }
        else {
            $R2 = Resolve-WithLatency -Name "google.com" -Server $DNS
            if ($R2.Success) {
                $InternetOK = $true
                $LS = if ($R2.LatMs -le 50) {"OK"} elseif ($R2.LatMs -le 150) {"WARNING"} else {"ERROR"}
                Add-Result "Internet" "DNS $DNS (UDP)" "Responds — $($R2.LatMs) ms" $LS "Connectivity"
            }
            elseif (-not $DNSProveInternet) {
                Add-Result "Internet" "DNS $DNS" "Not responding" "WARNING" "Connectivity"
            }
        }
    }
}
catch {
    Add-Result "Internet" "Active DNS" "Could not read" "INFO" "Connectivity"
}

if ($InternetOK) {
    Add-Result "Internet" "General connectivity" "Internet accessible" "OK" "Connectivity"
}
elseif ($DNSProveInternet) {
    Add-Result "Internet" "General connectivity" "DNS OK — TCP filtered (strict firewall or DoH)" "INFO" "Connectivity"
}
else {
    Add-Result "Internet" "General connectivity" "No reachable target" "ERROR" "Connectivity"
}

#endregion

#region DNS RESOLUTION

Show-Step "Testing DNS resolution + anti-hijacking..." 23

$KnownIPRanges = @{
    "google.com"     = @("142.250.","142.251.","172.217.","172.253.","216.58.","216.239.","74.125.","66.102.","64.233.")
    "microsoft.com"  = @("20.","13.","40.","104.47.","104.208.","150.171.","131.253.","207.68.","65.52.","23.96.","52.96.")
    "cloudflare.com" = @("104.16.","104.17.","198.41.","162.158.","172.64.","172.65.","172.66.","172.67.","172.68.","172.69.","172.70.","172.71.")
}

foreach ($Domain in @("google.com","microsoft.com","cloudflare.com")) {
    $R = Resolve-WithLatency -Name $Domain
    if ($R.Success) {
        $IPOk = $false
        foreach ($Range in $KnownIPRanges[$Domain]) {
            if ($R.IP.StartsWith($Range)) { $IPOk = $true; break }
        }
        $LS = if ($R.LatMs -le 100) {"OK"} elseif ($R.LatMs -le 200) {"WARNING"} else {"ERROR"}
        if ($IPOk) {
            Add-Result "DNS" "$Domain resolution" "$($R.IP) — $($R.LatMs) ms" $LS "DNS"
        }
        else {
            Add-Result "DNS" "$Domain resolution" "$($R.IP) — unexpected IP (possible hijacking?)" "WARNING" "DNS"
        }
    }
    else {
        Add-Result "DNS" "$Domain resolution" "Failed" "ERROR" "DNS"
    }
}

#endregion

#region DNS LEAK

# [NEW 04] DNS leak detection
# Compares the DNS servers that actually respond with the ones configured
# If a resolution goes through an unconfigured DNS server -> possible leak
Show-Step "Detecting DNS leak..." 26

if ($script:NextDNSInstalled) {
    try {
        $ConfiguredDNS = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            ForEach-Object { $_.ServerAddresses } |
            Where-Object { $_ -notmatch "^(0\.|127\.)" } |
            Sort-Object -Unique

        $LeakFound = $false

        # Test whether active TCP/53 connections actually go out to the configured DNS servers
        $ActiveDNSConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $_.RemotePort -eq 53 }

        foreach ($Conn in $ActiveDNSConns) {
            $IsConfigured = $ConfiguredDNS | Where-Object { $_ -eq $Conn.RemoteAddress }
            if (-not $IsConfigured) {
                $LeakFound = $true
                $ProcN = Get-ProcName $Conn.OwningProcess
                Add-Result "DNS Leak" "DNS leak detected" `
                    "$ProcN → $($Conn.RemoteAddress):53 (outside NextDNS)" "WARNING" "DNS"
            }
        }

        if (-not $LeakFound) {
            Add-Result "DNS Leak" "DNS leak" "No leak detected — everything goes through NextDNS" "OK" "DNS"
        }
    }
    catch {
        Add-Result "DNS Leak" "DNS leak analysis" "Could not analyze: $_" "INFO" "DNS"
    }
}
else {
    Add-Result "DNS Leak" "DNS leak" "NextDNS not installed — analysis not applicable" "INFO" "DNS"
}

#endregion

#region NEXTDNS BYPASS DETECTION

Show-Step "Detecting DNS bypass..." 28

if ($script:NextDNSInstalled) {
    try {
        $TCPBypass = Get-NetTCPConnection -State Established -ErrorAction Stop |
            Where-Object {
                $_.RemotePort -eq 53 -and
                $_.RemoteAddress -notmatch "^(127\.|::1|45\.90\.)" -and
                $_.RemoteAddress -ne "0.0.0.0"
            }

        $BypassFound = $false
        foreach ($Conn in $TCPBypass) {
            $BypassFound = $true
            $ProcN = Get-ProcName $Conn.OwningProcess
            Add-Result "Bypass DNS" "NextDNS bypass app" `
                "$ProcN → $($Conn.RemoteAddress):53 (hardcoded DNS)" "WARNING" "DNS"
        }

        if (-not $BypassFound) {
            Add-Result "Bypass DNS" "NextDNS bypass" "No bypass detected" "OK" "DNS"
        }
    }
    catch {
        Add-Result "Bypass DNS" "Bypass analysis" "Could not analyze: $_" "INFO" "DNS"
    }
}

#endregion

#region IPV6 LEAK

# [NEW 09] IPv6 leak detection
# If IPv6 is active but the IPv6 DNS doesn't go through NextDNS,
# IPv6 queries may bypass filtering
Show-Step "Detecting IPv6 leak..." 30

try {
    $IPv6Adapters = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop |
        Where-Object { $_.Enabled }

    if ($IPv6Adapters -and $script:NextDNSInstalled) {

        $IPv6DNS = Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses.Count -gt 0 } |
            ForEach-Object { $_.ServerAddresses } |
            Sort-Object -Unique

        # Get the local IPv6 gateway to exclude it from suspect DNS
        $GW6Local = @()
        try {
            $GW6Local = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
                Where-Object { $_.IPv6DefaultGateway } |
                ForEach-Object { $_.IPv6DefaultGateway.NextHop }
        }
        catch {}

        $NextDNSv6Ranges = @("2a07:a8c0:","2a07:a8c1:")
        $IsNextDNSv6  = $false
        $IsPrivateAll = $true

        foreach ($D in $IPv6DNS) {
            foreach ($Range in $NextDNSv6Ranges) {
                if ($D.StartsWith($Range)) { $IsNextDNSv6 = $true; break }
            }
            # Considered private/non-suspect:
            # - loopback (::1), link-local (fe80:), ULA (fc/fd)
            # - deprecated Windows site-local (fec0:)
            # - French ISP ranges (2a01:cb0x = Orange, 2a01:e0x = Free...)
            # - local IPv6 gateway (router address)
            $IsLocal = $D -match "^(fe80:|fc|fd|::1|fec0:)" -or
                       $D -match "^(2a01:cb0|2a01:cb1|2a01:e00|2a01:e35|2a01:e0a|2001:41d0|2a01:4f8)" -or
                       ($GW6Local -contains $D)

            if (-not $IsLocal) {
                $IsPrivateAll = $false
            }
        }

        if ($IsNextDNSv6) {
            Add-Result "IPv6 Leak" "IPv6 DNS" "NextDNS IPv6 active — no leak" "OK" "DNS"
        }
        elseif ($IsPrivateAll) {
            # All IPv6 DNS servers are local/private — no leak
            Add-Result "IPv6 Leak" "IPv6 DNS" "IPv6 DNS local only (fec0:/fe80:) — no leak" "OK" "DNS"
        }
        elseif ($IPv6DNS) {
            Add-Result "IPv6 Leak" "IPv6 DNS" `
                "IPv6 DNS ($($IPv6DNS -join ', ')) outside NextDNS — possible IPv6 leak" "WARNING" "DNS"
        }
        else {
            Add-Result "IPv6 Leak" "IPv6 DNS" "No IPv6 DNS configured — IPv6 not filtered" "INFO" "DNS"
        }
    }
    elseif (-not $IPv6Adapters) {
        Add-Result "IPv6 Leak" "IPv6" "Disabled — no IPv6 leak risk" "OK" "DNS"
    }
    else {
        Add-Result "IPv6 Leak" "IPv6 Leak" "Analysis not applicable (NextDNS absent)" "INFO" "DNS"
    }
}
catch {
    Add-Result "IPv6 Leak" "IPv6 leak analysis" "Error: $_" "INFO" "DNS"
}

#endregion

#region WINDOWS FIREWALL

Show-Step "Analyzing Windows Firewall..." 32

try {
    foreach ($P in (Get-NetFirewallProfile -ErrorAction Stop)) {
        $FwVal = if ($P.Enabled) { "Active" } else { "INACTIVE" }
        $FwStat = if ($P.Enabled) { "OK" } else { "ERROR" }
        Add-Result "Firewall" "$($P.Name) profile" $FwVal $FwStat "Security"
    }
}
catch { Add-Result "Firewall" "Analysis" "Error: $_" "ERROR" "Security" }

#endregion

#region NETWORK PROFILE

Show-Step "Analyzing network profile..." 34

try {
    foreach ($P in (Get-NetConnectionProfile -ErrorAction Stop)) {
        $Label = switch ($P.NetworkCategory) {
            "Public"              { "Public (most restrictive)" }
            "Private"             { "Private (trusted network)" }
            "DomainAuthenticated" { "Domain (enterprise)" }
            default               { $P.NetworkCategory }
        }
        Add-Result "Network Profile" $P.Name $Label "OK" "Security"
    }
}
catch { Add-Result "Network Profile" "Analysis" "Error: $_" "INFO" "Security" }

#endregion

#region LISTENING TCP PORTS

Show-Step "Analyzing listening TCP ports..." 36

try {
    $Listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop

    $PortsCritiques = @{
        21=  "FTP (unencrypted)";  22 = "SSH"; 23 = "Telnet (unencrypted)"
        25 = "SMTP"; 110 = "POP3 (unencrypted)"; 143 = "IMAP (unencrypted)"
        1433 = "SQL Server"; 1521 = "Oracle DB"; 3306 = "MySQL"
        5432 = "PostgreSQL"; 27017 = "MongoDB"; 5900 = "VNC"
    }
    $PortsSensibles = @{
        445 = "SMB"; 3389 = "RDP"; 8080 = "HTTP alt"; 8443 = "HTTPS alt"
        8888 = "HTTP dev"; 9090 = "HTTP admin"; 4000 = "Dev port"; 5000 = "Dev port"; 7000 = "Dev port"
    }
    $WhitelistProcs = @("svchost","System","lsass","services","wininit","spoolsv",
        "SearchIndexer","MsMpEng","WmiPrvSE","nextdns","dns")

    $AlreadyReported = @{}

    foreach ($Conn in $Listeners) {
        $Port    = $Conn.LocalPort
        $LocalIP = $Conn.LocalAddress
        $Exposed = ($LocalIP -eq "0.0.0.0" -or $LocalIP -eq "::")
        $Key     = "$Port-$LocalIP"
        if ($AlreadyReported.ContainsKey($Key)) { continue }
        $AlreadyReported[$Key] = $true

        $ProcN = Get-ProcName $Conn.OwningProcess
        $ProcP = Get-ProcPath $Conn.OwningProcess
        $ExpL  = if ($Exposed) { "EXPOSED on network (0.0.0.0)" } else { "Local ($LocalIP)" }

        if ($PortsCritiques.ContainsKey($Port)) {
            $S = if ($Exposed) { "ERROR" } else { "WARNING" }
            $D = "$($PortsCritiques[$Port]) — $ExpL — $ProcN"
            if ($ProcP) { $D += " ($ProcP)" }
            Add-Result "TCP Ports" "Port $Port" $D $S "Security"
        }
        elseif ($PortsSensibles.ContainsKey($Port)) {
            $S = if ($Exposed) { "WARNING" } else { "INFO" }
            $D = "$($PortsSensibles[$Port]) — $ExpL — $ProcN"
            if ($ProcP) { $D += " ($ProcP)" }
            Add-Result "TCP Ports" "Port $Port" $D $S "Security"
        }
        elseif ($Exposed -and $Port -lt 49152) {
            $IsWL = $WhitelistProcs | Where-Object { $ProcN -match "(?i)^$_" }
            if (-not $IsWL) {
                $D = "Non-standard exposed — $ProcN"
                if ($ProcP) { $D += " ($ProcP)" }
                Add-Result "TCP Ports" "Port $Port exposed" $D "WARNING" "Security"
            }
        }
    }

    Add-Result "TCP Ports" "Total TCP ports" "$(($Listeners | Select-Object -ExpandProperty LocalPort -Unique).Count) ports listening" "INFO" "Security"
}
catch { Add-Result "TCP Ports" "Analysis" "Error: $_" "INFO" "Security" }

#endregion

#region UDP PORTS

Show-Step "Analyzing UDP ports..." 39

try {
    $UDPListeners = Get-NetUDPEndpoint -ErrorAction Stop
    $PortsUDPCritiques = @{
        53   = "Local DNS"; 137 = "NetBIOS Name Service"; 138 = "NetBIOS Datagram"
        161  = "SNMP"; 1900 = "SSDP/UPnP"; 5353 = "mDNS"
    }
    $WhitelistProcsUDP = @("svchost","System","dns","nextdns")
    $AlreadyUDP = @{}

    foreach ($UDP in $UDPListeners) {
        $Port    = $UDP.LocalPort
        $LocalIP = $UDP.LocalAddress
        if (-not $PortsUDPCritiques.ContainsKey($Port)) { continue }
        $Key = "$Port-$LocalIP"
        if ($AlreadyUDP.ContainsKey($Key)) { continue }
        $AlreadyUDP[$Key] = $true

        $ProcN    = Get-ProcName $UDP.OwningProcess
        $Exposed  = ($LocalIP -eq "0.0.0.0" -or $LocalIP -eq "::" -or $LocalIP -eq "*")
        $IsWL     = $WhitelistProcsUDP | Where-Object { $ProcN -match "(?i)^$_" }
        $S        = if ($Port -eq 161 -and $Exposed) {"ERROR"} elseif ($IsWL) {"INFO"} elseif ($Exposed) {"WARNING"} else {"INFO"}
        $ExpL     = if ($Exposed) {"exposed on network"} else {"local ($LocalIP)"}

        Add-Result "UDP Ports" "UDP/$Port ($ExpL)" "$($PortsUDPCritiques[$Port]) — $ProcN" $S "Security"
    }

    Add-Result "UDP Ports" "Total UDP ports" "$(($UDPListeners | Select-Object -ExpandProperty LocalPort -Unique).Count) ports" "INFO" "Security"
}
catch { Add-Result "UDP Ports" "UDP Analysis" "Error: $_" "INFO" "Security" }

#endregion

#region SUSPICIOUS PROCESSES ON 0.0.0.0

Show-Step "Detecting suspicious listening processes..." 42

try {
    $WhitelistSystem = @(
        "svchost","System","lsass","services","wininit","spoolsv","SearchIndexer",
        "MsMpEng","WmiPrvSE","nextdns","dns","Idle","RuntimeBroker",
        "SecurityHealthService","OneDrive","Teams","slack","discord","chrome","firefox","msedge"
    )

    $ExposedListeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { ($_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::") -and $_.LocalPort -lt 49152 }

    $SuspectProcs = @{}
    foreach ($Conn in $ExposedListeners) {
        $ProcN = Get-ProcName $Conn.OwningProcess
        $ProcP = Get-ProcPath $Conn.OwningProcess
        $IsWL  = $false
        foreach ($W in $WhitelistSystem) {
            if ($ProcN -match "(?i)^$W") { $IsWL = $true; break }
        }
        if (-not $IsWL) {
            if (-not $SuspectProcs.ContainsKey($ProcN)) {
                $SuspectProcs[$ProcN] = @{ Path = $ProcP; Ports = @($Conn.LocalPort) }
            }
            else { $SuspectProcs[$ProcN].Ports += $Conn.LocalPort }
        }
    }

    if ($SuspectProcs.Count -eq 0) {
        Add-Result "Processes" "Exposed on 0.0.0.0" "No non-system process" "OK" "Security"
    }
    else {
        foreach ($PN in $SuspectProcs.Keys) {
            $Info  = $SuspectProcs[$PN]
            $Ports = ($Info.Ports | Sort-Object -Unique) -join ", "
            $D     = "Ports: $Ports"
            if ($Info.Path) { $D += " | $($Info.Path)" }
            Add-Result "Processes" "Exposed: $PN" $D "WARNING" "Security"
        }
    }
}
catch { Add-Result "Processes" "Process analysis" "Error: $_" "INFO" "Security" }

#endregion

#region ESTABLISHED CONNECTIONS

Show-Step "Analyzing established connections..." 45

try {
    $Established = Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object { $_.RemoteAddress -notin @("127.0.0.1","::1") }

    $SuspectPorts = @(4444,1337,31337,6666,6667,6668,1234,9999)
    $SuspectFound = $false

    foreach ($C in $Established) {
        if ($C.RemotePort -in $SuspectPorts) {
            $SuspectFound = $true
            $ProcN = Get-ProcName $C.OwningProcess
            Add-Result "Connections" "Suspicious port $($C.RemotePort)" "$($C.RemoteAddress) via $ProcN" "ERROR" "Security"
        }
    }

    if (-not $SuspectFound) { Add-Result "Connections" "Suspicious connections" "None detected" "OK" "Security" }
    Add-Result "Connections" "Total connections" "$($Established.Count) established TCP connections" "INFO" "Security"
}
catch { Add-Result "Connections" "Analysis" "Error: $_" "INFO" "Security" }

#endregion

#region OUTBOUND CONNECTIONS

# [NEW 05] Analysis of active outbound connections with source process
Show-Step "Analyzing outbound connections..." 47

try {
    # Get the current script's PID to exclude it from outbound connections
    $ScriptProcID = $PID

    $Outbound = Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object {
            $_.RemoteAddress -notmatch "^(127\.|::1|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" -and
            $_.RemoteAddress -ne "0.0.0.0" -and
            $_.RemotePort -in @(80, 443, 8080, 8443) -and
            $_.OwningProcess -ne $ScriptProcID  # Exclude the script itself (pwsh)
        } |
        Sort-Object RemoteAddress -Unique |
        Select-Object -First 15

    if ($Outbound) {
        # Group by process
        $ByProc = @{}
        foreach ($C in $Outbound) {
            $ProcN = Get-ProcName $C.OwningProcess
            if (-not $ByProc.ContainsKey($ProcN)) { $ByProc[$ProcN] = @() }
            $ByProc[$ProcN] += "$($C.RemoteAddress):$($C.RemotePort)"
        }
        foreach ($PN in $ByProc.Keys) {
            $IPs = ($ByProc[$PN] | Select-Object -Unique | Select-Object -First 5) -join ", "
            Add-Result "Outbound" $PN $IPs "INFO" "Security"
        }
    }
    else {
        Add-Result "Outbound" "HTTP(S) connections" "No active outbound connection" "INFO" "Security"
    }
}
catch { Add-Result "Outbound" "Outbound analysis" "Error: $_" "INFO" "Security" }

#endregion

#region ROOT CERTIFICATES

# [NEW 06] Audit of suspicious root certificates in the Windows store
# An unofficial root certificate can allow HTTPS interception
# [NEW 14] Expensive section (enumerates the whole Root store) — controllable via -Category RootCerts
Show-Step "Auditing root certificates..." 50

if (-not (Test-CategoryEnabled "RootCerts")) {
    Add-Result "Certificates" "Root audit" "Skipped (-Category)" "INFO" "Security"
}
else {
try {
    $RootCerts = Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction Stop

    # Legitimate Microsoft root issuers
    $TrustedIssuers = @(
        "Microsoft", "DigiCert", "GlobalSign", "Comodo", "Sectigo", "VeriSign",
        "Entrust", "GoDaddy", "Go Daddy", "Thawte", "Symantec", "Baltimore", "USERTrust",
        "ISRG Root", "Let's Encrypt", "QuoVadis", "Certigna", "Certinomis",
        "FNMT", "AC Camerfirma", "SwissSign", "T-TeleSec", "D-TRUST",
        "Buypass", "Certum", "HARICA", "SSL.com", "Amazon", "Apple",
        "Google Trust Services", "Starfield", "Network Solutions",
        "IdenTrust", "Secure Global CA", "AddTrust", "UTN", "ANF",
        "Cybertrust", "ePKI", "SECOM", "JPRS", "Korea", "Government",
        "Actalis", "Izenpe", "ACCVRAIZ", "TrustCor", "Hongkong Post",
        "OU=Go Daddy", "CN=Go Daddy",
        "e-Tugra", "Trustwave", "Chambers of Commerce",
        "TeliaSonera", "TWCA", "TURKTRUST", "StartCom",
        "E1", "E2", "R3", "R4", "X1", "X2", "X3"  # Let's Encrypt intermediates
    )

    # Ignore certificates whose Subject is a plain Windows GUID (internal system certs)
    $GUIDPattern = "^[{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}]?$"

    $SuspectCerts = @()
    foreach ($Cert in $RootCerts) {
        $Subject  = $Cert.Subject
        $IsTrusted = $false
        foreach ($Issuer in $TrustedIssuers) {
            if ($Subject -match [regex]::Escape($Issuer)) { $IsTrusted = $true; break }
        }
        if (-not $IsTrusted) {
            $SubjectClean = $Subject -replace "CN=","" -replace ",.*",""
            # Ignore internal Windows GUIDs
            if ($SubjectClean -match "^[{]?[0-9A-Fa-f\-]{30,}[}]?$") { continue }
            $Expiry = $Cert.NotAfter.ToString("yyyy-MM-dd")
            $SuspectCerts += [PSCustomObject]@{
                Subject    = $SubjectClean
                Expiry     = $Expiry
                Thumbprint = $Cert.Thumbprint
            }
        }
    }

    Add-Result "Certificates" "Total root certificates" "$($RootCerts.Count) certificates in the store" "INFO" "Security"

    if ($SuspectCerts.Count -eq 0) {
        Add-Result "Certificates" "Non-standard certificates" "No suspicious certificate detected" "OK" "Security"
    }
    elseif ($SuspectCerts.Count -le 5) {
        foreach ($C in $SuspectCerts) {
            Add-Result "Certificates" "Non-standard cert." "$($C.Subject) (exp. $($C.Expiry))" "WARNING" "Security"
        }
    }
    else {
        # Many non-standard certificates = normal on some PCs (enterprise, education)
        Add-Result "Certificates" "Non-standard certificates" "$($SuspectCerts.Count) certs. outside known CAs — check if enterprise PC" "INFO" "Security"
    }
}
catch {
    Add-Result "Certificates" "Certificate audit" "Error: $_" "INFO" "Security"
}
}

#endregion

#region SMB SHARES / SMBV1

Show-Step "Analyzing SMB..." 53

try {
    $Shares = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '^\w+\$$' }
    if ($Shares) {
    foreach ($S in $Shares) { Add-Result "SMB" "Share '$($S.Name)'" $S.Path "WARNING" "Security" }
    }
    else { Add-Result "SMB" "Network shares" "No non-system share" "OK" "Security" }
}
catch { Add-Result "SMB" "Share analysis" "Error: $_" "INFO" "Security" }

try {
    if ((Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol) {
        Add-Result "SMB" "SMBv1" "ENABLED — Vulnerable (WannaCry, NotPetya)" "ERROR" "Security"
    }
    else { Add-Result "SMB" "SMBv1" "Disabled" "OK" "Security" }
}
catch { Add-Result "SMB" "SMBv1" "Could not verify" "INFO" "Security" }

#endregion

#region ICS CONNECTION SHARING

# [NEW 08] Internet Connection Sharing (ICS) detection
# If active, the machine shares its connection and opens additional ports
Show-Step "Detecting ICS connection sharing..." 55

try {
    $ICSService = Get-Service -Name "SharedAccess" -ErrorAction Stop

    if ($ICSService.Status -eq "Running") {
        # Check whether interfaces actually have sharing enabled
        # The EnabledInterfaces key contains the GUIDs of shared interfaces
        $ICSEnabled = $false
        try {
            $ICSFwPolicy = Get-ItemProperty `
                "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" `
                -ErrorAction Stop
            # If the FirewallPolicy key exists with non-empty entries = ICS active
            $ICSEnabled = $true
        }
        catch {}

        # Double-check via ICS network connections (virtual interface)
        $ICSAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceDescription -match "(?i)ICS|Hosted|Virtual|Microsoft Wi-Fi Direct" }

        if ($ICSEnabled -and $ICSAdapter) {
            Add-Result "ICS" "Connection sharing (ICS)" "Active — the machine is sharing its Internet connection" "WARNING" "Security"
        }
        else {
            # Service running but not actually active (default automatic startup)
            Add-Result "ICS" "Connection sharing (ICS)" "Service present — sharing not active" "OK" "Security"
        }
    }
    else {
        Add-Result "ICS" "Connection sharing (ICS)" "Disabled" "OK" "Security"
    }
}
catch { Add-Result "ICS" "ICS analysis" "Could not verify" "INFO" "Security" }

#endregion

#region PROXY

Show-Step "Analyzing proxy..." 57

try {
    $IEP = Get-ItemProperty `
        -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction Stop
    if ($IEP.ProxyEnable -eq 1) {
        Add-Result "Proxy" "WinINET proxy" "Configured: $($IEP.ProxyServer)" "WARNING" "Security"
    }
    else { Add-Result "Proxy" "WinINET proxy" "Disabled" "OK" "Security" }
}
catch { Add-Result "Proxy" "WinINET proxy" "Could not read" "INFO" "Security" }

try {
    $WHP = Get-ItemProperty `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    if ($WHP -and $WHP.ProxyEnable -eq 1 -and $WHP.ProxyServer) {
        Add-Result "Proxy" "WinHTTP proxy" "Configured: $($WHP.ProxyServer)" "WARNING" "Security"
    }
    else {
        $NetshOut = & netsh winhttp show proxy 2>&1 | Out-String
        if ($NetshOut -match "Direct access|Accès direct|Aucun proxy|no proxy|direct") {
            Add-Result "Proxy" "WinHTTP proxy" "Direct access" "OK" "Security"
        }
        elseif ($NetshOut -match "Proxy Server|Serveur proxy") {
            $Line = ($NetshOut -split "`n" | Where-Object { $_ -match "Proxy|proxy" } | Select-Object -First 1)
            Add-Result "Proxy" "WinHTTP proxy" $Line.Trim() "WARNING" "Security"
        }
        else { Add-Result "Proxy" "WinHTTP proxy" "Direct access" "OK" "Security" }
    }
}
catch { Add-Result "Proxy" "WinHTTP proxy" "Direct access" "OK" "Security" }

#endregion

#region IPV6 / NETBIOS

Show-Step "IPv6 and NetBIOS..." 59

try {
    $v6        = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop
    $v6Enabled = $v6 | Where-Object { $_.Enabled }
    $n         = $v6Enabled.Count
    # [FIX] Get-NetAdapterBinding reflects the "IPv6" checkbox in the adapter's
    # properties, not the connection state — a disconnected Wi-Fi card still
    # counts if IPv6 is enabled on it. We clarify how many are actually connected.
    $ActiveAdaptersSafe = if ($ActiveAdapters) { $ActiveAdapters } else { @() }
    $nActive   = ($v6Enabled | Where-Object { $_.Name -in $ActiveAdaptersSafe.Name }).Count
    $IPv6Label = if ($n -gt 0) { "Enabled on $n interface(s) ($nActive connected)" } else { "Disabled" }
    Add-Result "IPv6" "IPv6 state" $IPv6Label "INFO" "Connectivity"
}
catch {
    # WMI fallback if Get-NetAdapterBinding fails
    try {
        $NICs6 = Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop |
            Where-Object { $_.IPEnabled -and $_.IPAddress -match ":" }
        $IPv6Label = if ($NICs6) { "Enabled (detected via WMI)" } else { "Disabled" }
        Add-Result "IPv6" "IPv6 state" $IPv6Label "INFO" "Connectivity"
    }
    catch { Add-Result "IPv6" "IPv6 state" "Undetermined" "INFO" "Connectivity" }
}

try {
    $NICs = Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled }
    if ($NICs | Where-Object { $_.TcpipNetbiosOptions -in @(0,1) }) {
        Add-Result "NetBIOS" "NetBIOS over TCP/IP" "Enabled (public network risk)" "WARNING" "Security"
    }
    else { Add-Result "NetBIOS" "NetBIOS over TCP/IP" "Disabled" "OK" "Security" }
}
catch { Add-Result "NetBIOS" "NetBIOS state" "Could not verify" "INFO" "Security" }

#endregion

#region INTERFACE PERFORMANCE

Show-Step "Interface performance..." 61

try {
    if ($MainAdapter) {
        $Speed     = $MainAdapter.LinkSpeed
        $SpeedMbps = 0
        # LinkSpeed is localized ("1 Gbps" on en-US, "1 Gbits/s" on fr-FR, decimal comma possible)
        if ($Speed -match "(\d+(?:[.,]\d+)?)\s*(G|M|K)(?:bps|bits/s|bit/s)") {
            $SpeedMbps = $SpeedNum = [double]::Parse(($Matches[1] -replace ',', '.'), [Globalization.CultureInfo]::InvariantCulture)
            $SpeedMbps = switch ($Matches[2]) {
                "G" { $SpeedNum*1000 }
                "M" { $SpeedNum }
                "K" { $SpeedNum/1000 }
            }
        }
        $Stat = if ($SpeedMbps -ge 100) {"OK"} elseif ($SpeedMbps -ge 10) {"WARNING"} elseif ($SpeedMbps -gt 0) {"ERROR"} else {"INFO"}
        Add-Result "Performance" "Link speed ($($MainAdapter.Name))" $Speed $Stat "Connectivity"

        try {
            $AWMI = Get-WmiObject Win32_NetworkAdapter -ErrorAction SilentlyContinue |
                Where-Object { $_.NetConnectionID -eq $MainAdapter.Name }
            if ($AWMI -and $AWMI.AdapterType) {
                Add-Result "Performance" "Adapter type" $AWMI.AdapterType "INFO" "Connectivity"
            }
        }
        catch {}
    }
}
catch { Add-Result "Performance" "Speed analysis" "Error: $_" "INFO" "Connectivity" }

#endregion

#region NETWORK ERROR STATISTICS

Show-Step "Network error statistics..." 63

try {
    foreach ($A in (Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" })) {
        try {
            $S = Get-NetAdapterStatistics -Name $A.Name -ErrorAction Stop
            $TotalErr = $S.ReceivedPacketErrors + $S.OutboundPacketErrors +
                        $S.ReceivedDiscardedPackets + $S.OutboundDiscardedPackets
            $TotalPkt = $S.ReceivedUnicastPackets + $S.SentUnicastPackets
            if ($TotalPkt -gt 0) {
                $Rate = [Math]::Round(($TotalErr / $TotalPkt) * 100, 3)
                $Stat = if ($Rate -eq 0) {"OK"} elseif ($Rate -lt 0.1) {"WARNING"} else {"ERROR"}
                Add-Result "Network Stats" "Errors $($A.Name)" "Rate: $Rate% ($TotalErr/$TotalPkt)" $Stat "Connectivity"
            }
            else { Add-Result "Network Stats" "Errors $($A.Name)" "No traffic yet" "INFO" "Connectivity" }
        }
        catch {}
    }
}
catch { Add-Result "Network Stats" "Analysis" "Error: $_" "INFO" "Connectivity" }

#endregion

#region ROUTING TABLE

Show-Step "Routing table..." 65

try {
    $Routes  = Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop
    $Default = @($Routes | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" })   # @() : a single CIM object has no reliable .Count
    if ($Default.Count -gt 0) {
        if ($Default.Count -eq 1) {
            Add-Result "Routing" "Default route" "Via $($Default.NextHop) (metric $($Default.RouteMetric))" "OK" "Connectivity"
        }
        else {
            $List = ($Default | ForEach-Object { "$($_.NextHop) [m$($_.RouteMetric)]" }) -join " | "
            Add-Result "Routing" "Multiple routes" $List "WARNING" "Connectivity"
        }
    }
    else { Add-Result "Routing" "Default route" "None" "ERROR" "Connectivity" }
    Add-Result "Routing" "Total IPv4 routes" "$(@($Routes).Count) routes" "INFO" "Connectivity"
}
catch { Add-Result "Routing" "Routing analysis" "Error: $_" "ERROR" "Connectivity" }

#endregion

#region ARP CACHE

Show-Step "ARP cache..." 67

try {
    $ARP = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.State -ne "Permanent" }
    $Dup = $ARP | Where-Object { $_.LinkLayerAddress -ne "00-00-00-00-00-00" } |
        Group-Object LinkLayerAddress | Where-Object { $_.Count -gt 1 }
    if ($Dup) {
        foreach ($G in $Dup) {
            Add-Result "ARP" "Duplicate MAC $($G.Name)" "IPs: $(($G.Group | Select-Object -ExpandProperty IPAddress) -join ', ')" "WARNING" "Security"
        }
    }
    else { Add-Result "ARP" "ARP cache" "No duplicate MAC" "OK" "Security" }
    Add-Result "ARP" "ARP entries" "$(@($ARP).Count) entr$(if (@($ARP).Count -eq 1) {"y"} else {"ies"})" "INFO" "Security"
}
catch { Add-Result "ARP" "ARP analysis" "Error: $_" "INFO" "Security" }

#endregion

#region DNS CACHE

Show-Step "Analyzing local DNS cache..." 70

try {
    $DNSCache = Get-DnsClientCache -ErrorAction Stop
    if (-not $DNSCache) { Add-Result "DNS Cache" "Cache" "Empty cache" "INFO" "DNS" }
    else {

        $WL = @(
            "adobe.com","adobe.io","adobe.de","adobe.net","adobelogin.com","adobeereg.com",
            "adobejanus.com","adobegenuine.com","adobestats.io","adobedtm.com","omtrdc.net",
            "demdex.net","licensingstack.com","helpexamples.com","opsource.net",
            "microsoft.com","microsoftonline.com","windows.com","windowsupdate.com",
            "live.com","office.com","office365.com","azure.com","azurewebsites.net",
            "msftconnecttest.com","msftncsi.com","bing.com","msn.com","skype.com","sharepoint.com",
            "google.com","googleapis.com","gstatic.com","googleusercontent.com","googlevideo.com",
            "youtube.com","ytimg.com","googletagmanager.com","doubleclick.net","chrome.com",
            "apple.com","icloud.com","mzstatic.com","mozilla.org","mozilla.com","firefox.com",
            "akamai.net","akadns.net","akamaiedge.net","edgekey.net","edgesuite.net",
            "cloudflare.com","cloudflare.net","cloudfront.net","fastly.net","amazonaws.com",
            "awsstatic.com","azureedge.net","trafficmanager.net","verisign.com","verisign.net",
            "thawte.com","digicert.com","letsencrypt.org","sentry.io","wikimedia.org",
            "wikipedia.org","nextdns.io","speed.cloudflare.com","httpbin.org",
            # [FIX 07] Missing legitimate roots — source of DGA false positives
            # as soon as a technical subdomain (e.g. crashdump.spotify.com) shows up in the cache
            "spotify.com","spotifycdn.com","scdn.co",
            "linkedin.com","licdn.com",
            "brave.com","bravesoftware.com",
            "mozilla.net"
        )
        $WLip = @("63.140.","192.150.","209.34.83.","199.7.","199.232.","162.247.242.",
            "13.107.","40.96.","20.","52.114.","23.79.","104.64.","104.16.","104.17.",
            "151.101.","185.199.","140.82.","172.217.","216.58.","142.250.","142.251.",
            "17.","168.63.","45.90.")
        $AWSip = @("3.","13.","15.","18.","23.22.","34.","44.","52.","54.","65.8.","99.","100.")
        $TelDom = @("adobestats.io","omtrdc.net","demdex.net","adobedtm.com","doubleclick.net",
            "googletagmanager.com","scorecardresearch.com","quantserve.com","segment.io",
            "mixpanel.com","amplitude.com","hotjar.com","newrelic.com","datadog.com",
            "sentry.io","bugsnag.com",
            # [NEW 11] Domains aligned with the Block-Telemetry_v5 lists — prevents the
            # endpoints we deliberately block from being reclassified as "Potential DGA"
            "snap.licdn.com","platform.linkedin.com",
            "log.spotify.com","crashdump.spotify.com","audio-ec.spotify.com",
            "heads4-ash2-accesspoint.ap.spotify.com","heads4-accesspoint.ap.spotify.com","cpapi.spotify.com",
            "p3a.brave.com","p2a.brave.com","cr.brave.com","variations.brave.com","star-randsrv.bsg.brave.com",
            "telemetry.mozilla.org","incoming.telemetry.mozilla.org","crash-stats.mozilla.com",
            "normandy.cdn.mozilla.net","normandy-cdn.mozilla.net","experimenter.mozilla.org",
            "firefox.settings.services.mozilla.com","coverage.mozilla.org","mozac.telemetry.mozilla.org")
        $BadTLD  = @(".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".download",".stream",".gdn")
        $BadPatt = @("update-required","security-alert","virus-detected","account-suspended","confirm-payment")

        function Get-DnsCategory {
            param([string]$N, $Data)
            $n = $N.ToLower().Trim()

            # [FIX 05] The old rule only matched a reverse PTR query for 0.0.0.0,
            # which never matches a domain name blocked via the hosts file.
            # We now check the IP actually resolved by the cache (classic null route).
            if ($Data) {
                $DataList = @($Data) | ForEach-Object { "$_".Trim() }
                if ($DataList -contains "0.0.0.0" -or $DataList -contains "127.0.0.1") { return "BLOQUE" }
            }

            if ($n -match "\.in-addr\.arpa$")              { return "PTR"       }
            if ($n -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
                foreach ($p in $WLip)  { if ($n.StartsWith($p)) { return "IP_OK"  } }
                foreach ($p in $AWSip) { if ($n.StartsWith($p)) { return "IP_AWS" } }
                return "IP_INCONNUE"
            }
            foreach ($p in $BadPatt) { if ($n -match [regex]::Escape($p)) { return "MALWARE"  } }
            foreach ($t in $BadTLD)  { if ($n.EndsWith($t))               { return "TLD_BAD"  } }
            foreach ($d in $TelDom)  { if ($n -eq $d -or $n.EndsWith(".$d")) { return "TELEMETRIE" } }
            foreach ($d in $WL)      { if ($n -eq $d -or $n.EndsWith(".$d")) { return "LEGITIME"   } }

            # [FIX 06] Tightened DGA heuristic: a real DGA generates long, pseudo-random
            # strings with almost no vowels. Many legitimate technical names (crashdump,
            # platform, normandy-cdn...) fell into the old threshold (>=8 chars, <=2 vowels).
            # We raise the threshold, reason in ratio rather than absolute count, and exclude
            # labels with a hyphen (very rare in a real DGA, common in human/CDN naming).
            $lbl = $n.Split('.')[0]
            if (-not $lbl.Contains('-')) {
                $vow   = ($lbl -replace '[^aeiou]','').Length
                $ratio = if ($lbl.Length -gt 0) { $vow / $lbl.Length } else { 1 }
                if ($lbl.Length -ge 10 -and $ratio -le 0.15) {
                    $root   = ($n.Split('.')[-2..(-1)] -join '.')
                    $rootOK = $false
                    foreach ($d in $WL) { if ($root -eq $d -or $root.EndsWith(".$d")) { $rootOK = $true; break } }
                    if (-not $rootOK) { return "DGA" }
                }
            }
            return "INCONNU"
        }

        $cL=$cT=$cB=$cIk=$cIa=$cIu=$cDGA=$cBTLD=$cMal=$cUnk = 0
        foreach ($E in ($DNSCache | Sort-Object Entry -Unique)) {
            switch (Get-DnsCategory -N $E.Entry -Data $E.Data) {
                "BLOQUE"     { $cB++  }
                "PTR"        { $cL++  }
                "LEGITIME"   { $cL++  }
                "IP_OK"      { $cIk++ }
                "IP_AWS"     { $cIa++ }
                "TELEMETRIE" { $cT++  }
                "IP_INCONNUE"{ $cIu++; Add-Result "DNS Cache" "Unlisted IP" "$($E.Entry)" "WARNING" "DNS" }
                "DGA"        { $cDGA++;  Add-Result "DNS Cache" "Potential DGA"     "$($E.Entry)" "WARNING" "DNS" }
                "TLD_BAD"    { $cBTLD++; Add-Result "DNS Cache" "Dangerous TLD"     "$($E.Entry)" "ERROR"        "DNS" }
                "MALWARE"    { $cMal++;  Add-Result "DNS Cache" "Malicious pattern" "$($E.Entry)" "ERROR"      "DNS" }
                "INCONNU"    { $cUnk++;  if ($E.TimeToLive -gt 604800) { Add-Result "DNS Cache" "Abnormal TTL" "$($E.Entry)" "WARNING" "DNS" } }
            }
        }

        Add-Result "DNS Cache" "Total (deduplicated)" "$(($DNSCache | Sort-Object Entry -Unique).Count) entries" "INFO" "DNS"
        if ($cL -gt 0)    { Add-Result "DNS Cache" "Legitimate infrastructure" "$cL entries" "OK" "DNS" }
        if ($cT -gt 0)    { Add-Result "DNS Cache" "Telemetry" "$cT domains — usage collection, not a threat" "INFO" "DNS" }
        if ($cB -gt 0)    { Add-Result "DNS Cache" "Blocked (DNS filter)" "$cB filtered domains — DNS filter active" "OK" "DNS" }
        if ($cIk -gt 0)   { Add-Result "DNS Cache" "Known hosting IPs" "$cIk IPs" "OK" "DNS" }
        if ($cIa -gt 0)   { Add-Result "DNS Cache" "Amazon AWS IPs" "$cIa IPs" "OK" "DNS" }
        if ($cDGA -eq 0 -and $cBTLD -eq 0 -and $cMal -eq 0) {
            Add-Result "DNS Cache" "Threats" "None (DGA, TLD, phishing)" "OK" "DNS"
        }
        if ($cUnk -gt 0)  { Add-Result "DNS Cache" "Unclassified" "$cUnk entries with no threat indicator" "INFO" "DNS" }
    }
}
catch { Add-Result "DNS Cache" "Analysis" "Error: $_" "INFO" "DNS" }

#endregion

#region HOSTS FILE

Show-Step "Analyzing hosts file..." 72

try {
    $HostsPath  = "$env:SystemRoot\System32\drivers\etc\hosts"
    $HostsLines = Get-Content -Path $HostsPath -Encoding UTF8 -ErrorAction Stop

    # [NEW 12] The DNS cache (previous section) only reflects domains actually
    # queried since the last startup/flush — not everything that's blocked.
    # So we read the hosts file directly to get the true configured total, and
    # distinguish the block added by Block-Telemetry_v5 from the rest (manual or third-party entries).
    # Markers written by Block-Telemetry.ps1 (must stay identical to $Marker / $MarkerEnd there).
    # Legacy French markers (pre-translation versions) are still recognised.
    $BTMarkers    = @("# === TELEMETRY BLOCK - Do not modify manually ===", "# === BLOC TELEMETRIE - Ne pas modifier manuellement ===")
    $BTMarkerEnds = @("# === END TELEMETRY BLOCK ===", "# === FIN BLOC TELEMETRIE ===")

    $TotalNull      = 0
    $InBTBlock      = 0
    $OutsideBTBlock = 0
    $InsideBlock    = $false
    $BTBlockFound   = $false

    foreach ($Line in $HostsLines) {
        if ($BTMarkers | Where-Object { $Line -match [regex]::Escape($_) })    { $InsideBlock = $true;  $BTBlockFound = $true; continue }
        if ($BTMarkerEnds | Where-Object { $Line -match [regex]::Escape($_) }) { $InsideBlock = $false; continue }

        if ($Line -match '^\s*(0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)') {
            $TotalNull++
            if ($InsideBlock) { $InBTBlock++ } else { $OutsideBTBlock++ }
        }
    }

    Add-Result "Hosts File" "Configured domains (total)" "$TotalNull null-route entries (0.0.0.0 / 127.0.0.1)" "INFO" "DNS"

    if ($BTBlockFound) {
        Add-Result "Hosts File" "Block-Telemetry block" "$InBTBlock domains in the identified block" "OK" "DNS"
        if ($OutsideBTBlock -gt 0) {
            Add-Result "Hosts File" "Other entries outside block" "$OutsideBTBlock domains (added manually or by another tool)" "INFO" "DNS"
        }
    }
    else {
        Add-Result "Hosts File" "Block-Telemetry block" "Not detected — no active blocking via this script" "INFO" "DNS"
    }

    # Comparison with what was actually seen going through the DNS cache (DNS CACHE section)
    $cBSafe = if ($cB) { $cB } else { 0 }
    if ($TotalNull -gt 0) {
        $CoveragePct = [Math]::Round(($cBSafe / $TotalNull) * 100, 0)
        Add-Result "Hosts File" "DNS cache coverage" "$cBSafe / $TotalNull domains seen in cache ($CoveragePct%) — the rest simply hasn't been queried since the last startup/flush" "INFO" "DNS"
    }

    # [NEW 18] Hosts file freshness — local proxy (last-modified date) since the
    # script has no access to an official Block-Telemetry_v5 version source at runtime
    $HostsAgeDays = [Math]::Round(((Get-Date) - (Get-Item $HostsPath).LastWriteTime).TotalDays, 0)
    # [FIX 17] Only judge freshness when the Block-Telemetry block is present: an untouched hosts file is
    # perfectly normal for anyone who does not use that script and must not be scored as a problem.
    $AgeStatut = if (-not $BTBlockFound) { "INFO" }
                 elseif ($HostsAgeDays -le 120) { "OK" }
                 elseif ($HostsAgeDays -le 240) { "WARNING" }
                 else { "ERROR" }
    Add-Result "Hosts File" "Last modified" "$HostsAgeDays day(s) ago" $AgeStatut "DNS"
}
catch {
    Add-Result "Hosts File" "Analysis" "Error (hosts file not found or inaccessible): $_" "INFO" "DNS"
}

#endregion

#region WI-FI (if detected)

if ($IsWifi -and (Test-CategoryEnabled "WiFi")) {

    Show-Step "Analyzing Wi-Fi..." 74

    try {
        $W = netsh wlan show interfaces 2>&1 | Out-String
        if ($W -match "SSID\s+:\s+(.+)")           { Add-Result "Wi-Fi" "SSID"           $Matches[1].Trim() "OK"   "Connectivity" }
        if ($W -match "(?:Authentication|Authentification)\s+:\s+(.+)") {
            $Auth = $Matches[1].Trim()
            $AS   = switch -Regex ($Auth) { "WPA3"{"OK"} "WPA2"{"OK"} "WPA"{"WARNING"} "WEP|Open|None|Ouvert|Aucun"{"ERROR"} default{"INFO"} }
            Add-Result "Wi-Fi" "Authentication" $Auth $AS "Security"
        }
        if ($W -match "Signal\s+:\s+(\d+)%") {
            $Pct = [int]$Matches[1]
            $SS  = if ($Pct -ge 70) {"OK"} elseif ($Pct -ge 40) {"WARNING"} else {"ERROR"}
            Add-Result "Wi-Fi" "Signal" "$Pct%" $SS "Connectivity"
        }
        if ($W -match "(?:Radio type|Type de radio)\s+:\s+(.+)") { Add-Result "Wi-Fi" "Standard" $Matches[1].Trim() "INFO" "Connectivity" }
        if ($W -match "(?:Channel|Canal)\s+:\s+(.+)") { Add-Result "Wi-Fi" "Channel"  $Matches[1].Trim() "INFO" "Connectivity" }
    }
    catch { Add-Result "Wi-Fi" "Analysis" "Error: $_" "INFO" "Connectivity" }

    # [NEW 07] Known Wi-Fi network history
    Show-Step "Wi-Fi history..." 76

    try {
        $ProfilesOut = netsh wlan show profiles 2>&1 | Out-String
        $Profiles    = [regex]::Matches($ProfilesOut, "(?:All User Profile|User Profile|Profil Tous les utilisateurs|Profil Utilisateur)\s*:\s*(.+)")
        Add-Result "Wi-Fi History" "Saved profiles" "$($Profiles.Count) network(s) remembered" "INFO" "Security"

        foreach ($PM in $Profiles) {
            $PName = $PM.Groups[1].Value.Trim()
            try {
                $PDetail = netsh wlan show profile name="$PName" 2>&1 | Out-String
                $Auth    = "?"
                $KeyType = "?"
                if ($PDetail -match "(?:Authentication|Authentification)\s+:\s+(.+)")  { $Auth    = $Matches[1].Trim() }
                # [FIX 18] No key=clear: only check that a key exists, never retrieve the Wi-Fi password itself
                if ($PDetail -match "(?i)(?:Security key|Cl. de s.curit.)\s*:\s*(?:Present|Pr.sent)") { $KeyType = "Password stored" }
                else                                               { $KeyType = "No key" }
                $AuthS = if ($Auth -match "WPA3|WPA2") {"OK"} elseif ($Auth -match "WEP|Open|None|Ouvert|Aucun") {"ERROR"} else {"INFO"}
                Add-Result "Wi-Fi History" $PName "$Auth — $KeyType" $AuthS "Security"
            }
            catch { Add-Result "Wi-Fi History" $PName "Could not read" "INFO" "Security" }
        }
    }
    catch { Add-Result "Wi-Fi History" "Wi-Fi profiles" "Error: $_" "INFO" "Security" }
}

#endregion

#region COMPARISON WITH PREVIOUS REPORT

# [NEW 10] Compares with the last JSON report to detect changes
Show-Step "Comparing with previous report..." 80

if (-not (Test-CategoryEnabled "Comparison")) {
    Add-Result "Comparison" "Previous report" "Skipped (-Category)" "INFO" "General"
}
elseif ($PreviousJson -and $PreviousJson.FullName -ne $JsonPath) {
    try {
        $PrevData    = Get-Content $PreviousJson.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
        $PrevDate    = $PreviousJson.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        $PrevResults = @{}
        foreach ($R in $PrevData) {
            $Key = "$($R.Categorie)|$($R.Element)"
            $PrevResults[$Key] = $R.Statut
        }

        $Changes = @()
        foreach ($R in $Results) {
            $Key = "$($R.Categorie)|$($R.Element)"
            if ($PrevResults.ContainsKey($Key)) {
                $OldStatut = $PrevResults[$Key]
                if ($OldStatut -ne $R.Statut) {
                    $Changes += [PSCustomObject]@{
                        Element  = "$($R.Categorie) > $($R.Element)"
                        Avant    = $OldStatut
                        Apres    = $R.Statut
                        Valeur   = $R.Valeur
                    }
                }
            }
            else {
                $Changes += [PSCustomObject]@{
                    Element = "$($R.Categorie) > $($R.Element)"
                    Avant   = "Nouveau"
                    Apres   = $R.Statut
                    Valeur  = $R.Valeur
                }
            }
        }

        if ($Changes.Count -eq 0) {
            Add-Result "Comparison" "Previous report ($PrevDate)" "No changes detected" "OK" "General"
        }
        else {
            Add-Result "Comparison" "Previous report ($PrevDate)" "$($Changes.Count) change(s) detected" "INFO" "General"
            foreach ($C in $Changes | Where-Object { $_.Apres -in @("ERROR","WARNING") }) {
                $S = if ($C.Apres -eq "ERROR") { "ERROR" } else { "WARNING" }
                Add-Result "Comparison" "Change $($C.Element)" "Before: $($C.Avant) → After: $($C.Apres)" $S "General"
            }
        }
    }
    catch {
        Add-Result "Comparison" "Previous report" "Could not load: $_" "INFO" "General"
    }
}
else {
    Add-Result "Comparison" "Previous report" "No previous report found on the desktop" "INFO" "General"
}

#endregion

#region SCORE

Show-Step "Calculating scores..." 95

$ScoreConnectivity = [Math]::Max(0, $ScoreConnectivity)
$ScoreSecurity     = [Math]::Max(0, $ScoreSecurity)
$ScoreDNS          = [Math]::Max(0, $ScoreDNS)
$ScoreGlobal       = [Math]::Round(($ScoreConnectivity + $ScoreSecurity + $ScoreDNS) / 3)

        Add-Result "Scores" "Connectivity" "$ScoreConnectivity / 100 — $(Get-ScoreState $ScoreConnectivity)" "INFO" "General"
        Add-Result "Scores" "Security"     "$ScoreSecurity / 100 — $(Get-ScoreState $ScoreSecurity)"         "INFO" "General"
        Add-Result "Scores" "DNS"          "$ScoreDNS / 100 — $(Get-ScoreState $ScoreDNS)"                   "INFO" "General"
        Add-Result "Scores" "Global score" "$ScoreGlobal / 100 — $(Get-ScoreState $ScoreGlobal)"             "INFO" "General"

#endregion

#region CONSOLE DISPLAY

Show-Step "Finalizing..." 100
if (-not $Silent) { Clear-Host }

# [NEW 23] Console layout aligned with Check-Security: framed banners, one line per check
# (icon | category │ check : value), long values wrapped under the "│", score gauges, » file list.
$BarWidth = 62
$ConWidth = 100
try { if ($Host.UI.RawUI.WindowSize.Width -ge 60) { $ConWidth = [Math]::Min($Host.UI.RawUI.WindowSize.Width, 120) } } catch { }
$CatWidth  = 16
$LogIcons  = @{ "OK" = "✓"; "WARNING" = "!"; "ERROR" = "✗"; "INFO" = "·" }
$LogColors = @{ "OK" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red"; "INFO" = "Cyan" }

function Write-Frame {
    param([string]$Text, [string]$BorderColor = "DarkCyan", [string]$TextColor = "Cyan")
    $Padded = (" $Text").PadRight($BarWidth)
    Write-Host ("  ╔" + ("═" * $BarWidth) + "╗") -ForegroundColor $BorderColor
    Write-Host "  ║" -NoNewline -ForegroundColor $BorderColor
    Write-Host $Padded -NoNewline -ForegroundColor $TextColor
    Write-Host "║" -ForegroundColor $BorderColor
    Write-Host ("  ╚" + ("═" * $BarWidth) + "╝") -ForegroundColor $BorderColor
}

function Write-ResultLine {
    param([string]$Category, [string]$Element, [string]$Valeur, [string]$Statut)

    $Icon  = $LogIcons[$Statut];  if (-not $Icon)  { $Icon  = "•" }
    $Color = $LogColors[$Statut]; if (-not $Color) { $Color = "Cyan" }
    $IconCol = $Icon.PadRight(2)
    $CatCol  = $Category.PadRight($CatWidth)
    if ($CatCol.Length -gt $CatWidth) { $CatCol = $CatCol.Substring(0, $CatWidth) }

    $Indent = " " * (3 + 2 + 1 + $CatWidth)
    $Avail  = $ConWidth - $Indent.Length - 3

    if (("$Element : $Valeur").Length -le $Avail) {
        Write-Host "   " -NoNewline
        Write-Host "$IconCol " -NoNewline -ForegroundColor $Color
        Write-Host $CatCol -NoNewline -ForegroundColor DarkCyan
        Write-Host "│ " -NoNewline -ForegroundColor DarkGray
        Write-Host $Element -NoNewline -ForegroundColor Gray
        Write-Host " : " -NoNewline -ForegroundColor DarkGray
        Write-Host $Valeur -ForegroundColor $Color
        return
    }

    # Long value: element on the first line, value wrapped below, aligned under the "│"
    Write-Host "   " -NoNewline
    Write-Host "$IconCol " -NoNewline -ForegroundColor $Color
    Write-Host $CatCol -NoNewline -ForegroundColor DarkCyan
    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    Write-Host $Element -ForegroundColor Gray

    $Remaining = $Valeur
    $Chunks = @()
    while ($Remaining.Length -gt $Avail) {
        $CutAt = $Avail
        $Best  = [Math]::Max($Remaining.LastIndexOf(" ", $CutAt), $Remaining.LastIndexOf(",", $CutAt))
        if ($Best -gt ($Avail / 2)) { $CutAt = $Best + 1 }
        $Chunks   += $Remaining.Substring(0, $CutAt).TrimEnd()
        $Remaining = $Remaining.Substring($CutAt).TrimStart()
    }
    $Chunks += $Remaining
    foreach ($Chunk in $Chunks) {
        Write-Host $Indent -NoNewline
        Write-Host "│ " -NoNewline -ForegroundColor DarkGray
        Write-Host $Chunk -ForegroundColor $Color
    }
}

function Write-ScoreBar {
    param([string]$Label, [int]$Score, [string]$State)
    $Color  = Get-ScoreColor $Score
    $Filled = [Math]::Round($Score / 5)
    $Bar    = ("█" * $Filled) + ("░" * (20 - $Filled))
    Write-Host ("   {0,-20}" -f $Label) -NoNewline -ForegroundColor Gray
    Write-Host $Bar -NoNewline -ForegroundColor $Color
    Write-Host ("  {0}/100" -f $Score) -NoNewline -ForegroundColor $Color
    Write-Host ("  {0}" -f $State) -ForegroundColor DarkGray
}

if (-not $Silent) {

    Write-Host ""
    Write-Frame "WINDOWS NETWORK ANALYSIS  ·  v5.1" "Cyan" "Cyan"
    Write-Host ""

    $ConnLabel = @()
    if ($IsEthernet) { $ConnLabel += "Ethernet" }
    if ($IsWifi)     { $ConnLabel += "Wi-Fi" }
    if ($IsVPN)      { $ConnLabel += "VPN" }

    $OSVal = ($Results | Where-Object { $_.Element -eq "Windows Version" } | Select-Object -ExpandProperty Valeur -First 1)
    Write-Host ("   {0,-20}" -f "Date")       -NoNewline -ForegroundColor Gray; Write-Host (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -ForegroundColor White
    Write-Host ("   {0,-20}" -f "Connection") -NoNewline -ForegroundColor Gray; Write-Host ($ConnLabel -join " + ") -ForegroundColor White
    Write-Host ("   {0,-20}" -f "OS")         -NoNewline -ForegroundColor Gray; Write-Host $OSVal -ForegroundColor White

    $DisplayGroups = [ordered]@{
        "SYSTEM AND CONNECTION"      = @("System","Connection","Interfaces","IP","Gateway","Speed","Performance","Network Stats","Routing","IPv6")
        "INTERNET & CAPTIVE PORTAL"  = @("Internet","Network")
        "DNS, NEXTDNS & LEAKS"       = @("DNS","NextDNS","DoH Windows","Bypass DNS","DNS Leak","IPv6 Leak","DNS Cache","Hosts File")
        "NETWORK SECURITY"           = @("Firewall","Network Profile","TCP Ports","UDP Ports","Processes","Connections","Outbound","SMB","Proxy","NetBIOS","ARP","Certificates","ICS")
        "WI-FI & HISTORY"            = @("Wi-Fi","Wi-Fi History")
        "COMPARISON & EVOLUTION"     = @("Comparison","Maintenance")
    }

    $SecNo = 0
    foreach ($GroupName in $DisplayGroups.Keys) {
        $CatList      = $DisplayGroups[$GroupName]
        $GroupResults = @($Results | Where-Object { $_.Categorie -in $CatList })
        if ($GroupResults.Count -eq 0) { continue }

        $SecNo++
        Write-Host ""
        Write-Frame "$SecNo. $GroupName"
        foreach ($R in $GroupResults) {
            Write-ResultLine -Category $R.Categorie -Element $R.Element -Valeur $R.Valeur -Statut $R.Statut
        }
    }

    # ── Summary ─────────────────────────────────────────────────────────────
    $CtAll  = @($Results | Where-Object { $_.Categorie -ne "Scores" }).Count
    $CtOK   = @($Results | Where-Object { $_.Statut -eq "OK" }).Count
    $CtWarn = @($Results | Where-Object { $_.Statut -eq "WARNING" }).Count
    $CtErr  = @($Results | Where-Object { $_.Statut -eq "ERROR" }).Count

    Write-Host ""
    Write-Frame "✓ ANALYSIS COMPLETE" "Cyan" "Green"
    Write-Host ""

    Write-ScoreBar "Connectivity"   $ScoreConnectivity (Get-ScoreState $ScoreConnectivity)
    Write-ScoreBar "Security"       $ScoreSecurity     (Get-ScoreState $ScoreSecurity)
    Write-ScoreBar "DNS"            $ScoreDNS          (Get-ScoreState $ScoreDNS)
    Write-ScoreBar "Global score"   $ScoreGlobal       (Get-ScoreState $ScoreGlobal)

    Write-Host ("   {0,-20}" -f "Checks") -NoNewline -ForegroundColor Gray
    Write-Host "$CtAll total" -NoNewline -ForegroundColor White
    Write-Host "  ·  " -NoNewline -ForegroundColor DarkGray
    Write-Host "✓ $CtOK OK" -NoNewline -ForegroundColor Green
    Write-Host "  ·  " -NoNewline -ForegroundColor DarkGray
    Write-Host "! $CtWarn WARN" -NoNewline -ForegroundColor Yellow
    Write-Host "  ·  " -NoNewline -ForegroundColor DarkGray
    Write-Host "✗ $CtErr ERROR" -ForegroundColor Red

    $ErrItems  = @($Results | Where-Object { $_.Statut -eq "ERROR" })
    $WarnItems = @($Results | Where-Object { $_.Statut -eq "WARNING" })
    $MaxVal    = $ConWidth - 12

    if ($ErrItems.Count -gt 0) {
        Write-Host ""
        Write-Host "   ✗ ERROR" -ForegroundColor Red
        foreach ($P in ($ErrItems | Select-Object -First 5)) {
            $PV = if ($P.Valeur.Length -gt $MaxVal) { $P.Valeur.Substring(0, $MaxVal - 1) + "…" } else { $P.Valeur }
            Write-Host "      • [$($P.Categorie)] $($P.Element): $PV" -ForegroundColor Red
        }
        if ($ErrItems.Count -gt 5) { Write-Host "      ... and $($ErrItems.Count - 5) more" -ForegroundColor DarkRed }
    }
    if ($WarnItems.Count -gt 0) {
        Write-Host ""
        Write-Host "   ! WARNING" -ForegroundColor Yellow
        foreach ($P in ($WarnItems | Select-Object -First 5)) {
            $PV = if ($P.Valeur.Length -gt $MaxVal) { $P.Valeur.Substring(0, $MaxVal - 1) + "…" } else { $P.Valeur }
            Write-Host "      • [$($P.Categorie)] $($P.Element): $PV" -ForegroundColor Yellow
        }
        if ($WarnItems.Count -gt 5) { Write-Host "      ... and $($WarnItems.Count - 5) more" -ForegroundColor DarkYellow }
    }
    if ($ErrItems.Count -eq 0 -and $WarnItems.Count -eq 0) {
        Write-Host ""
        Write-Host "   ✓ No issues detected" -ForegroundColor Green
    }
}

#endregion

#region CSV EXPORT

try { $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Force }
catch {}

#endregion

#region JSON EXPORT

try { $Results | ConvertTo-Json -Depth 3 | Out-File $JsonPath -Encoding UTF8 -Force }
catch {}

#endregion

#region PURGE REPORTS

# [NEW 16] Purge of old CSV/HTML/JSON reports beyond -PurgeDays (0 = disabled); also cleans legacy French-named reports (Rapport_Reseau_*)
if ($PurgeDays -gt 0) {
    try {
        $PurgeLimit = (Get-Date).AddDays(-$PurgeDays)
        $OldFiles = Get-ChildItem -Path $OutputDir -Include "Network_Report_*.csv","Network_Report_*.html","Network_Report_*.json","Rapport_Reseau_*.csv","Rapport_Reseau_*.html","Rapport_Reseau_*.json" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $PurgeLimit -and $_.FullName -ne $CsvPath -and $_.FullName -ne $HtmlPath -and $_.FullName -ne $JsonPath }
        if ($OldFiles) {
            $OldFiles | Remove-Item -Force -ErrorAction SilentlyContinue
            Add-Result "Maintenance" "Purge reports" "$($OldFiles.Count) old file(s) deleted (> $PurgeDays days)" "INFO" "General"
        }
        else {
            Add-Result "Maintenance" "Purge reports" "Nothing to purge (> $PurgeDays days)" "INFO" "General"
        }
    }
    catch {
        Add-Result "Maintenance" "Purge reports" "Error: $_" "INFO" "General"
    }
}

#endregion

#region HTML EXPORT

try {

$HtmlDate = Get-Date -Format "yyyy-MM-dd HH:mm"
$ConnType = $ConnLabel -join " + "

# ── Helpers ──────────────────────────────────────────────────────────────────
function Get-SC  { param([int]$S)    if ($S -ge 90){"#10b981"} elseif ($S -ge 75){"#f59e0b"} elseif ($S -ge 50){"#f97316"} else {"#ef4444"} }
function Get-SL  { param([int]$S)    if ($S -ge 90){"Excellent"} elseif ($S -ge 75){"Good"} elseif ($S -ge 50){"Fair"} else {"Critical"} }
function Get-DO  { param([int]$S)    [Math]::Round(175.9 - (175.9 * $S / 100), 1) }
function Get-BC  { param([string]$S) switch ($S) {"OK"{"ok"} "WARNING"{"warn"} "ERROR"{"err"} default{"info"}} }
function Get-BT  { param([string]$S) switch ($S) {"OK"{"OK"} "WARNING"{"Warn"} "ERROR"{"Error"} default{"Info"}} }
function He { param([string]$S)
    if (-not $S) { return "" }
    $S = $S.Replace("&",  "&amp;")
    $S = $S.Replace("<",  "&lt;")
    $S = $S.Replace(">",  "&gt;")
    $S = $S.Replace('"',  "&quot;")
    $S = $S.Replace("'",  "&#39;")
    return $S
}

$TotalOK   = ($Results | Where-Object { $_.Statut -eq "OK"      }).Count
$TotalWarn = ($Results | Where-Object { $_.Statut -eq "WARNING" }).Count
$TotalErr  = ($Results | Where-Object { $_.Statut -eq "ERROR"   }).Count
$TotalAll  = $Results.Count
$GColor    = Get-SC $ScoreGlobal
$GLabel    = Get-SL $ScoreGlobal

# ── Donuts ────────────────────────────────────────────────────────────────────
function New-Donut { param([string]$L,[int]$S)
    $c=$( Get-SC $S); $g=$(Get-SL $S); $d=$(Get-DO $S)
    "<div class='di'><svg viewBox='0 0 100 100'><circle cx='50' cy='50' r='28' fill='none' stroke='#1e293b' stroke-width='6'/><circle cx='50' cy='50' r='28' fill='none' stroke='$c' stroke-width='6' stroke-linecap='round' stroke-dasharray='175.9' stroke-dashoffset='$d' transform='rotate(-90 50 50)'/><text x='50' y='46' text-anchor='middle' font-family='DM Mono,monospace' font-size='16' font-weight='700' fill='$c'>$S</text><text x='50' y='58' text-anchor='middle' font-family='DM Sans,sans-serif' font-size='9' fill='#64748b'>/100</text></svg><span class='dl'>$L</span><span class='dg' style='color:$c'>$g</span></div>"
}

$Donuts  = New-Donut "Connectivity" $ScoreConnectivity
$Donuts += New-Donut "Security"     $ScoreSecurity
$Donuts += New-Donut "DNS"          $ScoreDNS
$Donuts += New-Donut "Global"       $ScoreGlobal

# ── Sparkline history [NEW 19] ──────────────────────────────────────────────
# Re-reads the last N JSON reports from the folder to plot the global score trend
$SparklineHtml = ""
try {
    $HistFiles = Get-ChildItem "$OutputDir\Network_Report_*.json" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime | Select-Object -Last 10
    $HistScores = @()
    foreach ($HF in $HistFiles) {
        try {
            $HD = Get-Content $HF.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
            $SG = $HD | Where-Object { $_.Categorie -eq "Scores" -and $_.Element -eq "Global score" }
            if ($SG -and $SG.Valeur -match "^(\d+)\s*/\s*100") {
                $HistScores += [int]$Matches[1]
            }
        }
        catch {}
    }
    if ($HistScores.Count -ge 2) {
        $SWdt = 360; $SHt = 50; $Pad = 4
        $StepX = ($SWdt - 2*$Pad) / ($HistScores.Count - 1)
        $Pts = for ($i = 0; $i -lt $HistScores.Count; $i++) {
            $X = $Pad + ($i * $StepX)
            $Y = $SHt - $Pad - (($HistScores[$i] / 100) * ($SHt - 2*$Pad))
            "$([Math]::Round($X,1)),$([Math]::Round($Y,1))"
        }
        $PolyPts = $Pts -join " "
        $LastColor = Get-SC $HistScores[-1]
        $SparklineHtml = "<div class='spark-wrap'><p class='donuts-label'>Global score trend ($($HistScores.Count) last reports)</p><svg viewBox='0 0 $SWdt $SHt' class='spark-svg'><polyline points='$PolyPts' fill='none' stroke='$LastColor' stroke-width='2' stroke-linejoin='round' stroke-linecap='round'/></svg></div>"
    }
}
catch {}

# ── Alerts ───────────────────────────────────────────────────────────────────
$AlertsHtml = ""
$Probs = $Results | Where-Object { $_.Statut -in @("ERROR","WARNING") }
if ($Probs) {
    foreach ($P in $Probs) {
        $ac = if ($P.Statut -eq "ERROR") {"ae"} else {"aw"}
        $ic = if ($P.Statut -eq "ERROR") {"&#9888;"} else {"&#9728;"}
        $AlertsHtml += "<div class='alert $ac'><span class='aico'>$ic</span><div class='atx'><strong>$(He $P.Categorie) &mdash; $(He $P.Element)</strong><span>$(He $P.Valeur)</span></div></div>"
    }
} else {
    $AlertsHtml = "<div class='alert ag'><span class='aico'>&#10003;</span><div class='atx'><strong>No issues detected</strong><span>All checks passed successfully.</span></div></div>"
}

# ── Sections ──────────────────────────────────────────────────────────────────
$SecDefs = [ordered]@{
    "Connection &amp; Speed" = @{
        Ico  = "M13 10V3L4 14h7v7l9-11h-7z"
        Clr  = "#3b82f6"
        Cats = @("System","Connection","Interfaces","IP","Gateway","Speed","Performance","Network Stats","Routing","IPv6")
    }
    "Internet" = @{
        Ico  = "M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2zm0 0c-1.66 2.5-2.5 5.2-2.5 10s.84 7.5 2.5 10m0-20c1.66 2.5 2.5 5.2 2.5 10s-.84 7.5-2.5 10M2 12h20"
        Clr  = "#06b6d4"
        Cats = @("Internet","Network")
    }
    "DNS &amp; NextDNS" = @{
        Ico  = "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"
        Clr  = "#10b981"
        Cats = @("DNS","NextDNS","DoH Windows","Bypass DNS","DNS Leak","IPv6 Leak","DNS Cache","Hosts File")
    }
    "Network Security" = @{
        Ico  = "M21 2H3v16h5v4l4-4h5l4-4V2zm-11 9H8V7h2v4zm4 0h-2V7h2v4z"
        Clr  = "#f97316"
        Cats = @("Firewall","Network Profile","TCP Ports","UDP Ports","Processes","Connections","Outbound","SMB","Proxy","NetBIOS","ARP","Certificates","ICS")
    }
    "Wi-Fi" = @{
        Ico  = "M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01"
        Clr  = "#8b5cf6"
        Cats = @("Wi-Fi","Wi-Fi History")
    }
    "Evolution" = @{
        Ico  = "M3 3v18h18M18.7 8l-5.1 5.2-2.8-2.7L7 14.3"
        Clr  = "#f59e0b"
        Cats = @("Comparison","Scores","Maintenance")
    }
}

$Cards = ""
foreach ($SN in $SecDefs.Keys) {
    $Def   = $SecDefs[$SN]
    $Clr   = $Def.Clr
    $Path  = $Def.Ico
    $Cats  = $Def.Cats
    $SR    = $Results | Where-Object { $_.Categorie -in $Cats }
    if (-not $SR) { continue }

    $NE  = ($SR | Where-Object { $_.Statut -eq "ERROR" }).Count
    $NW  = ($SR | Where-Object { $_.Statut -eq "WARNING" }).Count
    $NK  = ($SR | Where-Object { $_.Statut -eq "OK" }).Count
    $NI  = ($SR | Where-Object { $_.Statut -eq "INFO" }).Count

    $Pill = if ($NE -gt 0) {"<span class='pill pill-err'>$NE error$(if($NE-gt 1){'s'})</span>"} `
            elseif ($NW -gt 0) {"<span class='pill pill-warn'>$NW warn.</span>"} `
            else {"<span class='pill pill-ok'>$NK OK</span>"}

    $SubCats = $SR | Select-Object -ExpandProperty Categorie -Unique
    $Rows    = ""

    foreach ($Cat in $SubCats) {
        $CR = $SR | Where-Object { $_.Categorie -eq $Cat }
        $Rows += "<tr class='subhead'><td colspan='3'>$(He $Cat)</td></tr>"
        foreach ($Row in $CR) {
            $bc = Get-BC $Row.Statut
            $bt = Get-BT $Row.Statut
            $SearchText = (He "$($Row.Element) $($Row.Valeur)").ToLower()
            $Rows += "<tr class='drow' data-status='$bc' data-text='$SearchText'><td class='col-el'>$(He $Row.Element)</td><td class='col-vl'>$(He $Row.Valeur)</td><td class='col-bd'><span class='badge bdg-$bc'>$bt</span></td></tr>"
        }
    }

    # Built without a heredoc to avoid any conflict with the data
    $CardHtml  = "<div class=`"section`">"
    $CardHtml += "<div class=`"sec-head`" onclick=`"this.parentElement.classList.toggle('collapsed')`">"
    $CardHtml += "<span class=`"sec-icon`" style=`"--c:$Clr`">"
    $CardHtml += "<svg width=`"14`" height=`"14`" viewBox=`"0 0 24 24`" fill=`"none`" stroke=`"currentColor`" stroke-width=`"2`" stroke-linecap=`"round`" stroke-linejoin=`"round`">"
    $CardHtml += "<path d=`"$Path`"/></svg></span>"
    $CardHtml += "<span class=`"sec-title`">$SN</span>"
    $CardHtml += "<span class=`"sec-meta`">$Pill <span class=`"sec-count`">$($SR.Count) checks</span></span>"
    $CardHtml += "<span class=`"sec-chev`">&#8250;</span></div>"
    $CardHtml += "<div class=`"sec-body`"><table class=`"dtable`"><tbody>$Rows</tbody></table></div>"
    $CardHtml += "</div>"
    $Cards    += $CardHtml
}

# ── HTML ──────────────────────────────────────────────────────────────────────
$Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Report — $HtmlDate</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;1,9..40,300&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* ── Reset & base ─────────────────────────────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:    #020617;
  --surf:  #0f172a;
  --surf2: #1e293b;
  --surf3: #334155;
  --t1:    #f1f5f9;
  --t2:    #94a3b8;
  --t3:    #475569;
  --ok:    #10b981;  --ok-a:  rgba(16,185,129,.12);  --ok-b:  rgba(16,185,129,.25);
  --wa:    #f59e0b;  --wa-a:  rgba(245,158,11,.12);   --wa-b:  rgba(245,158,11,.25);
  --er:    #ef4444;  --er-a:  rgba(239,68,68,.12);    --er-b:  rgba(239,68,68,.25);
  --in:    #3b82f6;  --in-a:  rgba(59,130,246,.1);    --in-b:  rgba(59,130,246,.22);
  --r: 10px; --rs: 6px;
  --font: 'DM Sans', system-ui, sans-serif;
  --mono: 'DM Mono', monospace;
}

body {
  font-family: var(--font);
  background: var(--bg);
  color: var(--t1);
  font-size: 13.5px;
  line-height: 1.55;
  padding: 36px 20px 64px;
  max-width: 920px;
  margin: 0 auto;
  -webkit-font-smoothing: antialiased;
}

/* Subtle textured background */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  background:
    radial-gradient(ellipse 80% 60% at 10% 0%,  rgba(59,130,246,.06) 0%, transparent 60%),
    radial-gradient(ellipse 60% 40% at 90% 100%, rgba(16,185,129,.04) 0%, transparent 60%);
  pointer-events: none;
  z-index: 0;
}
body > * { position: relative; z-index: 1; }

/* ── Header ───────────────────────────────────────────────────────────────── */
.hdr {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 20px;
  margin-bottom: 32px;
  padding-bottom: 24px;
  border-bottom: 1px solid var(--surf3);
}

.hdr-left { display: flex; flex-direction: column; gap: 10px; }

.eyebrow {
  font-size: 10.5px;
  font-weight: 500;
  letter-spacing: .13em;
  text-transform: uppercase;
  color: var(--t3);
}

.title {
  font-size: 24px;
  font-weight: 600;
  letter-spacing: -.04em;
  line-height: 1.1;
  color: #fff;
}
.title em { font-style: normal; color: var(--in); }

.meta-row { display: flex; flex-wrap: wrap; gap: 6px; }

.chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  background: var(--surf);
  border: 1px solid var(--surf3);
  border-radius: 99px;
  padding: 3px 11px;
  font-size: 11px;
  color: var(--t2);
}

.hdr-right { text-align: right; padding-top: 4px; }

.gscore {
  font-family: var(--mono);
  font-size: 38px;
  font-weight: 500;
  line-height: 1;
  letter-spacing: -.04em;
}
.gscore sub { font-size: 14px; font-weight: 400; color: var(--t3); vertical-align: baseline; }
.gscore-lbl { font-size: 10.5px; font-weight: 600; letter-spacing: .1em; text-transform: uppercase; margin-top: 5px; }

/* ── Stat strip ───────────────────────────────────────────────────────────── */
.statstrip {
  display: grid;
  grid-template-columns: repeat(4,1fr);
  gap: 8px;
  margin-bottom: 16px;
}

.stat {
  background: var(--surf);
  border: 1px solid var(--surf2);
  border-radius: var(--rs);
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 3px;
  transition: border-color .15s;
}
.stat:hover { border-color: var(--surf3); }

.stat-n {
  font-family: var(--mono);
  font-size: 22px;
  font-weight: 500;
  line-height: 1;
}
.stat-l { font-size: 11px; color: var(--t3); }

/* ── Score donuts ─────────────────────────────────────────────────────────── */
.donuts-wrap {
  background: var(--surf);
  border: 1px solid var(--surf2);
  border-radius: var(--r);
  padding: 20px 24px 16px;
  margin-bottom: 16px;
}

.donuts-label {
  font-size: 10px;
  font-weight: 500;
  letter-spacing: .12em;
  text-transform: uppercase;
  color: var(--t3);
  margin-bottom: 16px;
}

.donuts-row {
  display: flex;
  justify-content: space-around;
  flex-wrap: wrap;
  gap: 8px;
}

.di {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 5px;
  flex: 1;
  min-width: 80px;
}
.di + .di { border-left: 1px solid var(--surf2); }

.di svg { width: 72px; height: 72px; }

.dl {
  font-size: 11px;
  font-weight: 500;
  color: var(--t2);
  white-space: nowrap;
}
.dg {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .08em;
  text-transform: uppercase;
}

/* ── Alerts ──────────────────────────────────────────────────────────────── */
.alerts { display: flex; flex-direction: column; gap: 6px; margin-bottom: 20px; }

.alert {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 11px 16px;
  border-radius: var(--rs);
  border: 1px solid;
  font-size: 13px;
}

.aico {
  font-size: 14px;
  line-height: 1.4;
  flex-shrink: 0;
  width: 20px;
  text-align: center;
}

.atx { display: flex; flex-direction: column; gap: 1px; line-height: 1.45; }
.atx strong { font-weight: 500; color: var(--t1); font-size: 13px; }
.atx span   { font-size: 12px; color: var(--t2); }

.ag  { background: var(--ok-a); border-color: var(--ok-b); } .ag  .aico { color: var(--ok); }
.aw  { background: var(--wa-a); border-color: var(--wa-b); } .aw  .aico { color: var(--wa); }
.ae  { background: var(--er-a); border-color: var(--er-b); } .ae  .aico { color: var(--er); }

/* ── Sections ─────────────────────────────────────────────────────────────── */
.sections { display: flex; flex-direction: column; gap: 8px; }

.section {
  background: var(--surf);
  border: 1px solid var(--surf2);
  border-radius: var(--r);
  overflow: hidden;
  transition: border-color .15s;
}
.section:hover { border-color: var(--surf3); }

.sec-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 18px;
  cursor: pointer;
  user-select: none;
  transition: background .12s;
}
.sec-head:hover { background: rgba(255,255,255,.02); }
.section:not(.collapsed) .sec-head { border-bottom: 1px solid var(--surf2); }

.sec-icon {
  width: 28px;
  height: 28px;
  background: color-mix(in srgb, var(--c) 15%, transparent);
  border: 1px solid color-mix(in srgb, var(--c) 30%, transparent);
  border-radius: var(--rs);
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--c);
  flex-shrink: 0;
}

.sec-title {
  font-size: 13px;
  font-weight: 500;
  color: var(--t1);
  flex: 1;
}

.sec-meta {
  display: flex;
  align-items: center;
  gap: 7px;
}

.sec-count { font-size: 11px; color: var(--t3); }

.pill {
  font-size: 10px;
  font-weight: 600;
  padding: 1px 7px;
  border-radius: 99px;
  border: 1px solid;
  letter-spacing: .03em;
  text-transform: uppercase;
}
.pill-ok   { background: var(--ok-a); color: var(--ok); border-color: var(--ok-b); }
.pill-warn { background: var(--wa-a); color: var(--wa); border-color: var(--wa-b); }
.pill-err  { background: var(--er-a); color: var(--er); border-color: var(--er-b); }

.sec-chev {
  font-size: 18px;
  color: var(--t3);
  transition: transform .2s;
  transform: rotate(90deg);
  line-height: 1;
}
.section.collapsed .sec-chev { transform: rotate(0deg); }

.sec-body { display: block; }
.section.collapsed .sec-body { display: none; }
.spark-wrap { margin: 0 0 20px 0; }
.spark-svg { width: 100%; height: 50px; display: block; }
.filter-bar { display: flex; gap: 12px; align-items: center; margin: 0 0 16px 0; flex-wrap: wrap; }
.search-input { flex: 1; min-width: 200px; padding: 8px 12px; border-radius: var(--rs); border: 1px solid var(--surf2); background: var(--surf); color: var(--t1); font-family: 'DM Sans', sans-serif; font-size: 13px; }
.filter-pills { display: flex; gap: 6px; }
.fp { padding: 6px 12px; border-radius: 999px; border: 1px solid var(--surf2); background: var(--surf); color: var(--t2); font-size: 12px; cursor: pointer; }
.fp.active { background: var(--in); color: #fff; border-color: var(--in); }
.drow.hidden-row { display: none; }

/* ── Table ────────────────────────────────────────────────────────────────── */
.dtable { width: 100%; border-collapse: collapse; }

.subhead td {
  padding: 7px 18px 4px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .1em;
  text-transform: uppercase;
  color: var(--t3);
  background: rgba(0,0,0,.2);
  border-top: 1px solid var(--surf2);
}
.subhead:first-child td { border-top: none; }

.drow { transition: background .1s; }
.drow:hover { background: rgba(255,255,255,.02); }
.drow td { border-bottom: 1px solid rgba(255,255,255,.04); }
.drow:last-child td { border-bottom: none; }

.col-el {
  padding: 9px 10px 9px 18px;
  color: var(--t2);
  font-size: 12px;
  width: 32%;
  vertical-align: top;
}

.col-vl {
  padding: 9px 10px;
  font-family: var(--mono);
  font-size: 11.5px;
  color: var(--t1);
  width: 56%;
  vertical-align: top;
  word-break: break-word;
  line-height: 1.5;
}

.col-bd {
  padding: 9px 18px 9px 6px;
  width: 12%;
  vertical-align: top;
  text-align: right;
  white-space: nowrap;
}

/* ── Badges ───────────────────────────────────────────────────────────────── */
.badge {
  display: inline-flex;
  align-items: center;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 5px;
  border: 1px solid;
  white-space: nowrap;
  letter-spacing: .04em;
  text-transform: uppercase;
}
.bdg-ok   { background: var(--ok-a); color: var(--ok); border-color: var(--ok-b); }
.bdg-warn { background: var(--wa-a); color: var(--wa); border-color: var(--wa-b); }
.bdg-err  { background: var(--er-a); color: var(--er); border-color: var(--er-b); }
.bdg-info { background: var(--in-a); color: var(--in); border-color: var(--in-b); }

/* ── Footer ───────────────────────────────────────────────────────────────── */
.footer {
  margin-top: 48px;
  padding-top: 20px;
  border-top: 1px solid var(--surf2);
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
  font-size: 11px;
  color: var(--t3);
}

/* ── Responsive ───────────────────────────────────────────────────────────── */
 @media (max-width: 600px) {
  .statstrip { grid-template-columns: repeat(2,1fr); }
  .title { font-size: 20px; }
  .gscore { font-size: 28px; }
  .di svg { width: 60px; height: 60px; }
}
</style>
</head>
<body>

<!-- Header -->
<header class="hdr">
  <div class="hdr-left">
    <p class="eyebrow">Network diagnostic · v5.1</p>
    <h1 class="title">Windows <em>Network</em> Report</h1>
    <div class="meta-row">
      <span class="chip">&#128279; $ConnType</span>
      <span class="chip">&#128197; $HtmlDate</span>
      <span class="chip">&#128187; Windows 11</span>
    </div>
  </div>
  <div class="hdr-right">
    <div class="gscore" style="color:$GColor">$ScoreGlobal<sub>/100</sub></div>
    <div class="gscore-lbl" style="color:$GColor">$GLabel</div>
  </div>
</header>

<!-- Stat strip -->
<div class="statstrip">
  <div class="stat"><span class="stat-n" style="color:var(--ok)">$TotalOK</span><span class="stat-l">Checks OK</span></div>
  <div class="stat"><span class="stat-n" style="color:var(--wa)">$TotalWarn</span><span class="stat-l">Warnings</span></div>
  <div class="stat"><span class="stat-n" style="color:var(--er)">$TotalErr</span><span class="stat-l">Errors</span></div>
  <div class="stat"><span class="stat-n" style="color:var(--t2)">$TotalAll</span><span class="stat-l">Total checks</span></div>
</div>

<!-- Donuts -->
<div class="donuts-wrap">
  <p class="donuts-label">Network health scores</p>
  <div class="donuts-row">$Donuts</div>
</div>

$SparklineHtml

<!-- Alertes -->
<div class="alerts">$AlertsHtml</div>

<!-- Filter [NEW 21] -->
<div class="filter-bar">
  <input type="text" id="searchBox" class="search-input" placeholder="Search an item or a value...">
  <div class="filter-pills">
    <button class="fp active" data-filter="all">All</button>
    <button class="fp" data-filter="err">Errors</button>
    <button class="fp" data-filter="warn">Warn.</button>
    <button class="fp" data-filter="ok">OK</button>
  </div>
</div>

<!-- Sections -->
<div class="sections">$Cards</div>

<!-- Footer -->
<footer class="footer">
  <span>Windows Network Report &middot; v5.1</span>
  <span>$HtmlDate &mdash; Read-only</span>
</footer>

<script>
// All sections open by default
document.querySelectorAll('.section').forEach(s => {
  s.querySelector('.sec-head').addEventListener('click', () => s.classList.toggle('collapsed'));
});

// [NEW 21] Live filter: text search + status filter
(function() {
  var searchBox = document.getElementById('searchBox');
  var pills = document.querySelectorAll('.fp');
  var activeFilter = 'all';

  function applyFilter() {
    var term = (searchBox ? searchBox.value : '').toLowerCase().trim();
    document.querySelectorAll('.drow').forEach(function(row) {
      var matchesText = !term || (row.getAttribute('data-text') || '').indexOf(term) !== -1;
      var matchesStatus = (activeFilter === 'all') || (row.getAttribute('data-status') === activeFilter);
      row.classList.toggle('hidden-row', !(matchesText && matchesStatus));
    });
    document.querySelectorAll('.section').forEach(function(sec) {
      var visibleRows = sec.querySelectorAll('.drow:not(.hidden-row)').length;
      sec.style.display = (term || activeFilter !== 'all') && visibleRows === 0 ? 'none' : '';
      if (visibleRows > 0 && (term || activeFilter !== 'all')) { sec.classList.remove('collapsed'); }
    });
  }

  if (searchBox) { searchBox.addEventListener('input', applyFilter); }
  pills.forEach(function(p) {
    p.addEventListener('click', function() {
      pills.forEach(function(x) { x.classList.remove('active'); });
      p.classList.add('active');
      activeFilter = p.getAttribute('data-filter');
      applyFilter();
    });
  });
})();
</script>
</body>
</html>
"@

    # Verify that $Html is populated before writing
    if (-not $Html -or $Html.Length -lt 100) {
        throw "Variable $Html is empty or too short ($($Html.Length) chars)"
    }
    # Verify that the folder exists
    $HtmlDir = Split-Path $HtmlPath -Parent
    if (-not (Test-Path $HtmlDir)) {
        New-Item -ItemType Directory -Path $HtmlDir -Force | Out-Null
    }
    # Make sure the folder exists
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    $Html | Out-File $HtmlPath -Encoding UTF8 -Force
    if (Test-Path $HtmlPath) {
        $HtmlSize = (Get-Item $HtmlPath).Length
        if (-not $Silent) { Write-Host "  [OK] HTML : $(Split-Path $HtmlPath -Leaf) ($HtmlSize bytes)" -ForegroundColor Green }
    }
}
catch {
    Write-Host ""
    Write-Host "  [ERROR HTML] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  [ERROR HTML] Line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    Write-Host ""
}

#endregion



#region FIN

# [NEW 20] Desktop toast — even in -Silent mode (useful for a scheduled task)
Send-NetworkToast -Score $ScoreGlobal -Errors $TotalErr -Warnings $TotalWarn

if (-not $Silent) {
    Write-Host ""
    Write-Host "   »  HTML report    " -NoNewline -ForegroundColor DarkGray
    Write-Host "$HtmlPath" -ForegroundColor Cyan
    Write-Host "   »  CSV export     " -NoNewline -ForegroundColor DarkGray
    Write-Host "$CsvPath" -ForegroundColor Cyan
    Write-Host "   »  JSON export    " -NoNewline -ForegroundColor DarkGray
    Write-Host "$JsonPath" -ForegroundColor Cyan
    Write-Host ("─" * ($BarWidth + 2)) -ForegroundColor DarkCyan
    Write-Host ""

    if (Test-Path $HtmlPath) {
        $OuvrirRep = Read-Host "  Open the HTML report in the browser? [Y/n]"
        if ($OuvrirRep -eq '' -or $OuvrirRep -match '^[YyOo]') { Start-Process $HtmlPath }
    }

    Write-Host ""
    $ExitBar  = 51
    Write-Host ("  ╔" + ("═" * $ExitBar) + "╗") -ForegroundColor Cyan
    Write-Host "  ║" -ForegroundColor Cyan -NoNewline
    Write-Host ("  Press ENTER to close this window...").PadRight($ExitBar) -ForegroundColor Yellow -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host ("  ╚" + ("═" * $ExitBar) + "╝") -ForegroundColor Cyan
    Read-Host | Out-Null
}

# SIG # Begin signature block
# MIIFwgYJKoZIhvcNAQcCoIIFszCCBa8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDma6JDKkhqAQ2H
# 9l4k8kWxBRAX+OhFo/thOP1DBn9ZTqCCAygwggMkMIICDKADAgECAhB6X4r8AlBU
# p0MV3JpMuQ6sMA0GCSqGSIb3DQEBCwUAMCoxKDAmBgNVBAMMH05lcGhyZW4gUG93
# ZXJTaGVsbCBDb2RlIFNpZ25pbmcwHhcNMjYwNzA0MDIzMzIwWhcNMzEwNzA0MDI0
# MzIwWjAqMSgwJgYDVQQDDB9OZXBocmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5n
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JnV5AocUnAMNIG3nYF9
# 5mOQz5NzMYJqc9D6mq3pjRlmuYIgvYEuJL5dvt8eoAiUKd+XHTaY5wl+zt7LUon+
# TmEldVwfrYvROpI+5TDyBRc5BzY4uACsA4JUM4ienjX04BBKT3uH6JwHzBluWqcG
# Xrg16NqzDiae7WNzVrev+BME00mgSvBo3hKp3sHIvFQaAmjGXLyJd+llfnBpmoD9
# JnOxMKO7VFIlhAz5cEUnFu/xDLHgARdBUfXA5odScWKiDvygNZsH1vHo07Oo7pDK
# awR3bT6lcXWRXSUmawgE1mZra+b9qpeNol+5J+86zN83RccBKZBUtQQoyy+cv20x
# VQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# HQYDVR0OBBYEFNxVaDYoNv8UXQWnbtEy/DTaQHjYMA0GCSqGSIb3DQEBCwUAA4IB
# AQCE4NqZbeximmbNEORyLxvIYiMQwP59B9R95blQQ/zugPSt4wab61yBbgO1E3mH
# mUdN0fCHhN/u0uB7h7ZBYw1w4hnzoiBac4UYzsXH4/D41gBjutbtDllRy6/zs3dl
# /hbbHAmwKXdjNVLG9cPkpWlkvKR1DJLMugU2uj+S6k+U7DfHo76sbAKqiu3biXtd
# mao6PP99EU7JBYZjsJ+BsnYcZ2KcnZ8TKiRuhSXoxAyPman7Z0BVo1H2O+fxd96b
# 4W8VclmpFh7T2CyRAHolwEy5coFYyueisO0PZg+nKwXr66+m1T1CBLQYwh79/SKO
# wGUJyU5RtTryD+hfLwkTQKVCMYIB8DCCAewCAQEwPjAqMSgwJgYDVQQDDB9OZXBo
# cmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nAhB6X4r8AlBUp0MV3JpMuQ6sMA0G
# CWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIAAeI/Whf45Y+NrCQlhzYQQJl4NBTcr9j7UnpFu3
# Y9vsMA0GCSqGSIb3DQEBAQUABIIBADNsaAMC5zSyCcWTCGMx7fou+M9uVS6G7i5e
# 6CCO7a4r1mFNKD2Yck3RADz78eosA31t/DPUvRiwz5dVjIyeBFxAXZ92upB6v5Ce
# BZb0EJtKmAZLIOi+cdd5e7S3gJWlU00SNnekal/o/0QZX5UbHSgGSM8cXeA7MXM8
# jwmZZ01ulenjCr/aZL4D9OamFzZGCIX2t14C2u1IMztaaqx2rRiS4zKKXW3qBLRQ
# 2FpOA5gYqu1mveZI/FDS2zrW3OCLcdBuVd9GjLoI9YATLnIPcW/2b+6g8g4uJosv
# AcmjeLnK7aXsi+C9nV6BUEslA8clMz92oRDe+pb26PDcJfYz9Js=
# SIG # End signature block
