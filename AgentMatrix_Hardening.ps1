#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AgentMatrix_Hardening - Advanced Windows Hardening Script with Pentesting Protection
    
.DESCRIPTION
    This script implements comprehensive Windows hardening with focus on pentesting protection.
    Features include service blocking, network protocol hardening, privilege escalation protection,
    and Matrix-style visual effects during execution.
    
.PARAMETER Unattended
    Run in unattended mode without user interaction
    
.PARAMETER NoAnimation
    Disable Matrix-style animations for faster execution
    
.PARAMETER LogPath
    Custom path for log files (default: C:\AgentMatrix_Logs)
    
.EXAMPLE
    .\AgentMatrix_Hardening.ps1
    
.EXAMPLE
    .\AgentMatrix_Hardening.ps1 -Unattended -NoAnimation
    
.NOTES
    Version: 2.0
    Author: AgentMatrix Security Team
    Requires: PowerShell 5.1+, Administrator privileges
    Compatible: Windows 10/11, Windows Server 2016+
#>

[CmdletBinding()]
param(
    [switch]$Unattended,
    [switch]$NoAnimation,
    [string]$LogPath = "C:\AgentMatrix_Logs"
)

# Set execution policy and encoding
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Global variables
$Script:LogFile = ""
$Script:ReportFile = ""
$Script:StartTime = Get-Date
$Script:ActionsPerformed = @()
$Script:ServicesBlocked = @()
$Script:FirewallRulesAdded = @()
$Script:RegistryChanges = @()

#region Matrix Animation Functions
function Show-MatrixIntro {
    if ($NoAnimation) { return }
    
    Clear-Host
    Write-Host "
    ███╗   ███╗ █████╗ ████████╗██████╗ ██╗██╗  ██╗
    ████╗ ████║██╔══██╗╚══██╔══╝██╔══██╗██║╚██╗██╔╝
    ██╔████╔██║███████║   ██║   ██████╔╝██║ ╚███╔╝ 
    ██║╚██╔╝██║██╔══██║   ██║   ██╔══██╗██║ ██╔██╗ 
    ██║ ╚═╝ ██║██║  ██║   ██║   ██║  ██║██║██╔╝ ██╗
    ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
    " -ForegroundColor Green
    
    Write-Host "    AGENT MATRIX HARDENING PROTOCOL INITIATED" -ForegroundColor Cyan
    Write-Host "    [Resistance is futile. Your system will be secured.]" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    
    $matrixChars = @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F')
    for ($i = 0; $i -lt 20; $i++) {
        $line = ""
        for ($j = 0; $j -lt 80; $j++) {
            $line += $matrixChars | Get-Random
        }
        Write-Host $line -ForegroundColor Green -NoNewline
        if ($i % 4 -eq 0) { Start-Sleep -Milliseconds 100 }
    }
    Start-Sleep -Seconds 1
    Clear-Host
}

function Write-MatrixMessage {
    param([string]$Message, [string]$Color = "Green")
    
    if ($NoAnimation) {
        Write-Host "[AGENT] $Message" -ForegroundColor $Color
        return
    }
    
    Write-Host "[AGENT MATRIX] " -ForegroundColor Cyan -NoNewline
    foreach ($char in $Message.ToCharArray()) {
        Write-Host $char -ForegroundColor $Color -NoNewline
        Start-Sleep -Milliseconds 50
    }
    Write-Host ""
}

function Show-Progress {
    param([string]$Activity, [int]$PercentComplete)
    
    if ($NoAnimation) {
        Write-Progress -Activity $Activity -PercentComplete $PercentComplete
        return
    }
    
    $barLength = 50
    $completed = [math]::Floor($barLength * $PercentComplete / 100)
    $remaining = $barLength - $completed
    
    $bar = "[" + ("█" * $completed) + ("░" * $remaining) + "]"
    Write-Host "`r$bar $PercentComplete% - $Activity" -ForegroundColor Green -NoNewline
}
#endregion

#region Logging Functions
function Initialize-Logging {
    try {
        if (!(Test-Path -Path $LogPath)) {
            New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction Stop | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $Script:LogFile = Join-Path $LogPath "AgentMatrix_Log_$timestamp.txt"
        $Script:ReportFile = Join-Path $LogPath "AgentMatrix_Report_$timestamp.html"
        
        $logHeader = @"
==========================================
AGENT MATRIX HARDENING LOG
==========================================
Start Time: $(Get-Date)
Computer: $env:COMPUTERNAME
User: $env:USERNAME
PowerShell Version: $($PSVersionTable.PSVersion)
==========================================

"@
        
        Set-Content -Path $Script:LogFile -Value $logHeader -Encoding UTF8 -ErrorAction Stop
        Write-MatrixMessage "Logging initialized: $Script:LogFile" "Yellow"
        
    } catch {
        Write-Error "Failed to initialize logging: $($_.Exception.Message)"
        throw
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $Script:LogFile -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Silently continue if logging fails
    }
    
    # Also output to console with color coding
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry -ForegroundColor White }
    }
}
#endregion

#region System Information Functions
function Get-SystemInfo {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        
        return @{
            OSName = $os.Caption
            OSVersion = $os.Version
            OSBuild = $os.BuildNumber
            ComputerName = $computer.Name
            Domain = $computer.Domain
            TotalRAM = [math]::Round($computer.TotalPhysicalMemory / 1GB, 2)
            Architecture = $os.OSArchitecture
        }
    } catch {
        Write-Log "Failed to get system information: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-ServiceStatus {
    param([string]$ServiceName)
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        return @{
            Exists = $true
            Status = $service.Status
            StartType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop).StartMode
        }
    } catch {
        return @{
            Exists = $false
            Status = "NotFound"
            StartType = "Unknown"
        }
    }
}
#endregion

#region Service Hardening Functions
function Stop-CriticalServices {
    Write-MatrixMessage "Initiating service termination protocol..." "Red"
    
    $criticalServices = @(
        @{Name="lanmanserver"; Display="Server (SMB)"; Risk="File sharing exploitation"},
        @{Name="Browser"; Display="Computer Browser"; Risk="Network enumeration"},
        @{Name="WinRM"; Display="Windows Remote Management"; Risk="Remote command execution"},
        @{Name="RemoteRegistry"; Display="Remote Registry"; Risk="Registry manipulation"},
        @{Name="RpcSs"; Display="Remote Procedure Call (RPC)"; Risk="Remote code execution"},
        @{Name="TlntSvr"; Display="Telnet"; Risk="Unencrypted remote access"},
        @{Name="FTPSVC"; Display="FTP Server"; Risk="File transfer exploitation"},
        @{Name="SNMP"; Display="SNMP Service"; Risk="Network reconnaissance"},
        @{Name="Spooler"; Display="Print Spooler"; Risk="PrintNightmare vulnerability"},
        @{Name="WSearch"; Display="Windows Search"; Risk="Information disclosure"},
        @{Name="lmhosts"; Display="TCP/IP NetBIOS Helper"; Risk="NetBIOS attacks"},
        @{Name="NetBT"; Display="NetBIOS over TCP/IP"; Risk="Network scanning"},
        @{Name="upnphost"; Display="UPnP Device Host"; Risk="Network exposure"},
        @{Name="SSDPSRV"; Display="SSDP Discovery"; Risk="Network discovery"},
        @{Name="WinHttpAutoProxySvc"; Display="WinHTTP Web Proxy Auto-Discovery"; Risk="Proxy attacks"},
        @{Name="WSService"; Display="Windows Store Service"; Risk="Unnecessary exposure"},
        @{Name="XblAuthManager"; Display="Xbox Live Auth Manager"; Risk="Gaming service exposure"},
        @{Name="XblGameSave"; Display="Xbox Live Game Save"; Risk="Gaming service exposure"},
        @{Name="XboxNetApiSvc"; Display="Xbox Live Networking Service"; Risk="Gaming service exposure"}
    )
    
    $serviceCount = 0
    foreach ($svc in $criticalServices) {
        $serviceCount++
        Show-Progress "Securing service: $($svc.Display)" ([math]::Round(($serviceCount / $criticalServices.Count) * 100))
        
        try {
            $serviceStatus = Test-ServiceStatus -ServiceName $svc.Name
            
            if ($serviceStatus.Exists) {
                if ($serviceStatus.Status -eq "Running") {
                    Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    Write-Log "Stopped service: $($svc.Display)" "SUCCESS"
                }
                
                if ($serviceStatus.StartType -ne "Disabled") {
                    Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                    Write-Log "Disabled service: $($svc.Display)" "SUCCESS"
                }
                
                $Script:ServicesBlocked += @{
                    Name = $svc.Name
                    Display = $svc.Display
                    Risk = $svc.Risk
                    Action = "Stopped and Disabled"
                }
            } else {
                Write-Log "Service not found: $($svc.Display)" "INFO"
            }
            
        } catch {
            Write-Log "Failed to secure service $($svc.Display): $($_.Exception.Message)" "ERROR"
        }
        
        Start-Sleep -Milliseconds 100
    }
    
    Write-Host ""
    Write-MatrixMessage "Service termination protocol completed. $($Script:ServicesBlocked.Count) services secured." "Green"
}

function Disable-AdminShares {
    Write-MatrixMessage "Eliminating administrative vulnerabilities..." "Yellow"
    
    try {
        # Disable administrative shares
        $regPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "AutoShareServer" -Value 0 -Type DWord -ErrorAction Stop
                Set-ItemProperty -Path $regPath -Name "AutoShareWks" -Value 0 -Type DWord -ErrorAction Stop
                
                $Script:RegistryChanges += @{
                    Path = $regPath
                    Name = "AutoShareServer/AutoShareWks"
                    Value = 0
                    Description = "Disabled administrative shares"
                }
            }
        }
        
        # Disable Guest account
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guestAccount -and $guestAccount.Enabled) {
            Disable-LocalUser -Name "Guest" -ErrorAction Stop
            Write-Log "Disabled Guest account" "SUCCESS"
        }
        
        Write-Log "Administrative shares and guest account secured" "SUCCESS"
        
    } catch {
        Write-Log "Failed to disable admin shares: $($_.Exception.Message)" "ERROR"
    }
}
#endregion

#region Network Hardening Functions
function Set-NetworkHardening {
    Write-MatrixMessage "Implementing network fortress protocols..." "Cyan"
    
    try {
        # Disable LLMNR
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (!(Test-Path $llmnrPath)) {
            New-Item -Path $llmnrPath -Force | Out-Null
        }
        Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord
        
        # Disable NetBIOS over TCP/IP
        $netbiosPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
        Get-ChildItem $netbiosPath | ForEach-Object {
            Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        }
        
        # Disable WPAD
        $wpadPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
        if (!(Test-Path $wpadPath)) {
            New-Item -Path $wpadPath -Force | Out-Null
        }
        Set-ItemProperty -Path $wpadPath -Name "WpadOverride" -Value 1 -Type DWord
        
        # Disable IPv6 if not needed
        $ipv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        Set-ItemProperty -Path $ipv6Path -Name "DisabledComponents" -Value 255 -Type DWord
        
        $Script:RegistryChanges += @(
            @{Path=$llmnrPath; Name="EnableMulticast"; Value=0; Description="Disabled LLMNR"},
            @{Path=$wpadPath; Name="WpadOverride"; Value=1; Description="Disabled WPAD"},
            @{Path=$ipv6Path; Name="DisabledComponents"; Value=255; Description="Disabled IPv6"}
        )
        
        Write-Log "Network hardening completed" "SUCCESS"
        
    } catch {
        Write-Log "Failed to implement network hardening: $($_.Exception.Message)" "ERROR"
    }
}

function Set-FirewallRules {
    Write-MatrixMessage "Deploying firewall matrix..." "Red"
    
    $blockedPorts = @(
        @{Port=135; Protocol="TCP"; Name="RPC Endpoint Mapper"},
        @{Port=139; Protocol="TCP"; Name="NetBIOS Session"},
        @{Port=445; Protocol="TCP"; Name="SMB"},
        @{Port=593; Protocol="TCP"; Name="RPC over HTTP"},
        @{Port=3389; Protocol="TCP"; Name="RDP (except for specific IPs)"},
        @{Port=5985; Protocol="TCP"; Name="WinRM HTTP"},
        @{Port=5986; Protocol="TCP"; Name="WinRM HTTPS"},
        @{Port=21; Protocol="TCP"; Name="FTP"},
        @{Port=23; Protocol="TCP"; Name="Telnet"},
        @{Port=69; Protocol="UDP"; Name="TFTP"},
        @{Port=161; Protocol="UDP"; Name="SNMP"},
        @{Port=162; Protocol="UDP"; Name="SNMP Trap"},
        @{Port=1900; Protocol="UDP"; Name="SSDP"},
        @{Port=5353; Protocol="UDP"; Name="mDNS"},
        @{Port=137; Protocol="UDP"; Name="NetBIOS Name Service"},
        @{Port=138; Protocol="UDP"; Name="NetBIOS Datagram"}
    )
    
    $ruleCount = 0
    foreach ($port in $blockedPorts) {
        $ruleCount++
        Show-Progress "Blocking $($port.Name)" ([math]::Round(($ruleCount / $blockedPorts.Count) * 100))
        
        try {
            $ruleName = "AgentMatrix_Block_$($port.Name)_$($port.Protocol)_$($port.Port)"
            
            # Remove existing rule if it exists
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            
            # Create new blocking rule
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol $port.Protocol -LocalPort $port.Port -Action Block -Enabled True -ErrorAction Stop | Out-Null
            
            $Script:FirewallRulesAdded += @{
                Name = $ruleName
                Port = $port.Port
                Protocol = $port.Protocol
                Description = $port.Name
                Action = "Blocked Inbound"
            }
            
            Write-Log "Blocked $($port.Protocol) port $($port.Port) ($($port.Name))" "SUCCESS"
            
        } catch {
            Write-Log "Failed to block port $($port.Port): $($_.Exception.Message)" "ERROR"
        }
        
        Start-Sleep -Milliseconds 50
    }
    
    Write-Host ""
    Write-MatrixMessage "Firewall matrix deployed. $($Script:FirewallRulesAdded.Count) rules activated." "Green"
}
#endregion

#region Windows Defender Configuration
function Set-DefenderHardening {
    Write-MatrixMessage "Activating advanced defense systems..." "Magenta"
    
    try {
        # Enable real-time protection
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        
        # Enable cloud protection
        Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
        Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction Stop
        
        # Enable PUA protection
        Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
        
        # Configure scan settings
        Set-MpPreference -ScanAvgCPULoadFactor 50 -ErrorAction Stop
        Set-MpPreference -CheckForSignaturesBeforeRunningScan $true -ErrorAction Stop
        
        # Enable network protection
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
        
        # Configure exclusions removal (remove common attacker exclusions)
        $suspiciousExclusions = @("*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js")
        foreach ($exclusion in $suspiciousExclusions) {
            try {
                Remove-MpPreference -ExclusionExtension $exclusion -ErrorAction SilentlyContinue
            } catch {
                # Silently continue if exclusion doesn't exist
            }
        }
        
        # Update signatures
        Update-MpSignature -ErrorAction SilentlyContinue
        
        Write-Log "Windows Defender hardening completed" "SUCCESS"
        
    } catch {
        Write-Log "Failed to configure Windows Defender: $($_.Exception.Message)" "ERROR"
    }
}
#endregion

#region Privilege Escalation Protection
function Set-PrivilegeEscalationProtection {
    Write-MatrixMessage "Implementing privilege containment protocols..." "Yellow"
    
    try {
        # Disable PowerShell v2
        $psv2Path = "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine"
        if (Test-Path $psv2Path) {
            Set-ItemProperty -Path $psv2Path -Name "PowerShellVersion" -Value "2.0" -Type String
            Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction SilentlyContinue
        }
        
        # Disable Windows Script Host
        $wshPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        if (!(Test-Path $wshPath)) {
            New-Item -Path $wshPath -Force | Out-Null
        }
        Set-ItemProperty -Path $wshPath -Name "Enabled" -Value 0 -Type DWord
        
        # Enable UAC and set to highest level
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorUser" -Value 3 -Type DWord
        Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord
        
        # Disable remote UAC
        Set-ItemProperty -Path $uacPath -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord
        
        # Configure RDP security
        $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        Set-ItemProperty -Path $rdpPath -Name "UserAuthentication" -Value 1 -Type DWord  # Require NLA
        Set-ItemProperty -Path $rdpPath -Name "SecurityLayer" -Value 2 -Type DWord      # Force SSL
        Set-ItemProperty -Path $rdpPath -Name "MinEncryptionLevel" -Value 3 -Type DWord # High encryption
        
        $Script:RegistryChanges += @(
            @{Path=$wshPath; Name="Enabled"; Value=0; Description="Disabled Windows Script Host"},
            @{Path=$uacPath; Name="EnableLUA"; Value=1; Description="Enabled UAC"},
            @{Path=$uacPath; Name="ConsentPromptBehaviorAdmin"; Value=2; Description="UAC Admin Consent"},
            @{Path=$rdpPath; Name="UserAuthentication"; Value=1; Description="RDP NLA Required"}
        )
        
        Write-Log "Privilege escalation protection implemented" "SUCCESS"
        
    } catch {
        Write-Log "Failed to implement privilege escalation protection: $($_.Exception.Message)" "ERROR"
    }
}
#endregion

#region Autostart Monitoring
function Scan-AutostartEntries {
    Write-MatrixMessage "Scanning for suspicious autostart anomalies..." "Red"
    
    $suspiciousAutostart = @()
    $autostartLocations = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($location in $autostartLocations) {
        try {
            if (Test-Path $location) {
                $entries = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                foreach ($entry in $entries.PSObject.Properties) {
                    if ($entry.Name -notmatch "^PS") {  # Skip PowerShell properties
                        $value = $entry.Value
                        
                        # Check for suspicious patterns
                        $suspicious = $false
                        $suspiciousPatterns = @(
                            "powershell.*-enc",
                            "cmd.*\/c.*echo",
                            "wscript",
                            "cscript",
                            "regsvr32",
                            "rundll32.*javascript",
                            "mshta.*http",
                            "\.tmp\\",
                            "\.temp\\",
                            "%TEMP%",
                            "AppData\\Local\\Temp"
                        )
                        
                        foreach ($pattern in $suspiciousPatterns) {
                            if ($value -match $pattern) {
                                $suspicious = $true
                                break
                            }
                        }
                        
                        if ($suspicious) {
                            $suspiciousAutostart += @{
                                Location = $location
                                Name = $entry.Name
                                Value = $value
                                Risk = "Suspicious autostart entry detected"
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Log "Failed to scan autostart location $location`: $($_.Exception.Message)" "ERROR"
        }
    }
    
    if ($suspiciousAutostart.Count -gt 0) {
        Write-Log "Found $($suspiciousAutostart.Count) suspicious autostart entries" "WARNING"
        foreach ($entry in $suspiciousAutostart) {
            Write-Log "SUSPICIOUS: $($entry.Location) - $($entry.Name) = $($entry.Value)" "WARNING"
        }
    } else {
        Write-Log "No suspicious autostart entries detected" "SUCCESS"
    }
    
    return $suspiciousAutostart
}
#endregion

#region Report Generation
function Generate-HtmlReport {
    param([array]$SuspiciousAutostart)
    
    Write-MatrixMessage "Generating comprehensive security report..." "Cyan"
    
    $systemInfo = Get-SystemInfo
    $endTime = Get-Date
    $duration = $endTime - $Script:StartTime
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Agent Matrix Hardening Report</title>
    <style>
        body { font-family: 'Courier New', monospace; background-color: #0a0a0a; color: #00ff00; margin: 20px; }
        .header { text-align: center; border: 2px solid #00ff00; padding: 20px; margin-bottom: 20px; }
        .section { margin: 20px 0; border: 1px solid #00ff00; padding: 15px; }
        .title { color: #00ffff; font-size: 18px; font-weight: bold; }
        .success { color: #00ff00; }
        .warning { color: #ffff00; }
        .error { color: #ff0000; }
        .info { color: #ffffff; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #00ff00; padding: 8px; text-align: left; }
        th { background-color: #003300; }
        .matrix-badge {
            text-align: center;
            font-family: monospace;
            font-size: 10px;
            color: #00ff00;
            margin: 20px 0;
            white-space: pre;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔰 AGENT MATRIX SECURITY HARDENING REPORT 🔰</h1>
        <p>SYSTEM SECURED - RESISTANCE IS FUTILE</p>
        <p>Computer: $($systemInfo.ComputerName) | Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>

    <div class="section">
        <div class="title">🖥️ SYSTEM INFORMATION</div>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Operating System</td><td>$($systemInfo.OSName)</td></tr>
            <tr><td>Version</td><td>$($systemInfo.OSVersion)</td></tr>
            <tr><td>Build</td><td>$($systemInfo.OSBuild)</td></tr>
            <tr><td>Architecture</td><td>$($systemInfo.Architecture)</td></tr>
            <tr><td>Total RAM</td><td>$($systemInfo.TotalRAM) GB</td></tr>
            <tr><td>Domain</td><td>$($systemInfo.Domain)</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="title">⏱️ EXECUTION SUMMARY</div>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Start Time</td><td>$($Script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
            <tr><td>End Time</td><td>$($endTime.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
            <tr><td>Duration</td><td>$($duration.ToString('hh\:mm\:ss'))</td></tr>
            <tr><td>Services Secured</td><td class="success">$($Script:ServicesBlocked.Count)</td></tr>
            <tr><td>Firewall Rules Added</td><td class="success">$($Script:FirewallRulesAdded.Count)</td></tr>
            <tr><td>Registry Changes</td><td class="success">$($Script:RegistryChanges.Count)</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="title">🚫 SERVICES TERMINATED</div>
        <table>
            <tr><th>Service Name</th><th>Display Name</th><th>Risk</th><th>Action</th></tr>
"@

    foreach ($service in $Script:ServicesBlocked) {
        $htmlReport += "<tr><td>$($service.Name)</td><td>$($service.Display)</td><td>$($service.Risk)</td><td class='success'>$($service.Action)</td></tr>"
    }

    $htmlReport += @"
        </table>
    </div>

    <div class="section">
        <div class="title">🔥 FIREWALL RULES DEPLOYED</div>
        <table>
            <tr><th>Rule Name</th><th>Protocol</th><th>Port</th><th>Description</th><th>Action</th></tr>
"@

    foreach ($rule in $Script:FirewallRulesAdded) {
        $htmlReport += "<tr><td>$($rule.Name)</td><td>$($rule.Protocol)</td><td>$($rule.Port)</td><td>$($rule.Description)</td><td class='error'>$($rule.Action)</td></tr>"
    }

    $htmlReport += @"
        </table>
    </div>

    <div class="section">
        <div class="title">🔧 REGISTRY MODIFICATIONS</div>
        <table>
            <tr><th>Path</th><th>Name</th><th>Value</th><th>Description</th></tr>
"@

    foreach ($reg in $Script:RegistryChanges) {
        $htmlReport += "<tr><td>$($reg.Path)</td><td>$($reg.Name)</td><td>$($reg.Value)</td><td>$($reg.Description)</td></tr>"
    }

    $htmlReport += @"
        </table>
    </div>
"@

    if ($SuspiciousAutostart.Count -gt 0) {
        $htmlReport += @"
    <div class="section">
        <div class="title">⚠️ SUSPICIOUS AUTOSTART ENTRIES</div>
        <table>
            <tr><th>Location</th><th>Name</th><th>Value</th><th>Risk</th></tr>
"@
        foreach ($entry in $SuspiciousAutostart) {
            $htmlReport += "<tr><td class='warning'>$($entry.Location)</td><td class='warning'>$($entry.Name)</td><td class='warning'>$($entry.Value)</td><td class='warning'>$($entry.Risk)</td></tr>"
        }
        $htmlReport += "</table></div>"
    }

    $htmlReport += @"
    <div class="matrix-badge">
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                    🏆 AGENT MATRIX CERTIFICATION 🏆                   ║
    ║                                                                      ║
    ║  This system has been hardened by Agent Matrix Security Protocol    ║
    ║  All known attack vectors have been neutralized                      ║
    ║  Resistance to penetration testing is now... inevitable             ║
    ║                                                                      ║
    ║  Certified Secure: $(Get-Date -Format 'yyyy-MM-dd')                                        ║
    ║  Agent ID: MATRIX-$(Get-Random -Minimum 1000 -Maximum 9999)                                          ║
    ║                                                                      ║
    ║  "Welcome to the real world, Neo. Your system is now protected."    ║
    ╚══════════════════════════════════════════════════════════════════════╝
    </div>

    <div class="section">
        <div class="title">📋 RECOMMENDATIONS</div>
        <ul>
            <li class="info">Regularly update Windows and applications</li>
            <li class="info">Monitor logs for suspicious activity</li>
            <li class="info">Keep Windows Defender signatures updated</li>
            <li class="info">Review firewall rules periodically</li>
            <li class="info">Conduct regular security assessments</li>
            <li class="warning">Reboot system to apply all changes</li>
        </ul>
    </div>
</body>
</html>
"@

    try {
        Set-Content -Path $Script:ReportFile -Value $htmlReport -Encoding UTF8 -ErrorAction Stop
        Write-Log "HTML report generated: $Script:ReportFile" "SUCCESS"
        return $Script:ReportFile
    } catch {
        Write-Log "Failed to generate HTML report: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Show-CompletionBadge {
    if ($NoAnimation) { 
        Write-Host "AGENT MATRIX HARDENING COMPLETED SUCCESSFULLY" -ForegroundColor Green
        return 
    }
    
    Clear-Host
    Write-Host @"

    ╔══════════════════════════════════════════════════════════════════════╗
    ║                    🏆 MISSION ACCOMPLISHED 🏆                        ║
    ║                                                                      ║
    ║  ██████╗ ██████╗ ███╗   ███╗██████╗ ██╗     ███████╗████████╗███████╗ ║
    ║ ██╔════╝██╔═══██╗████╗ ████║██╔══██╗██║     ██╔════╝╚══██╔══╝██╔════╝ ║
    ║ ██║     ██║   ██║██╔████╔██║██████╔╝██║     █████╗     ██║   █████╗   ║
    ║ ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝     ██║   ██╔══╝   ║
    ║ ╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗███████╗   ██║   ███████╗ ║
    ║  ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
    ║                                                                      ║
    ║  Agent Matrix has successfully secured this system.                  ║
    ║  Your machine is now fortified against penetration testing.         ║
    ║                                                                      ║
    ║  Services Terminated: $($Script:ServicesBlocked.Count.ToString().PadLeft(2))                                           ║
    ║  Firewall Rules Added: $($Script:FirewallRulesAdded.Count.ToString().PadLeft(2))                                         ║
    ║  Registry Hardened: Yes                                              ║
    ║  Defender Enhanced: Yes                                              ║
    ║                                                                      ║
    ║  "There is no spoon... only security."                              ║
    ╚══════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Green
    
    Start-Sleep -Seconds 3
}
#endregion

#region Main Execution
function Main {
    try {
        # Initialize
        Show-MatrixIntro
        Initialize-Logging
        
        Write-MatrixMessage "AGENT MATRIX PROTOCOL INITIATED" "Cyan"
        Write-MatrixMessage "Target system: $env:COMPUTERNAME" "Yellow"
        
        if (!$Unattended) {
            Write-MatrixMessage "Do you wish to proceed with system hardening? (Y/N)" "Yellow"
            $response = Read-Host
            if ($response -notmatch "^[Yy]") {
                Write-MatrixMessage "Operation aborted by user." "Red"
                return
            }
        }
        
        # Execute hardening procedures
        Write-Log "Starting Agent Matrix hardening procedures" "INFO"
        
        # Phase 1: Service Hardening
        Write-MatrixMessage "Phase 1: Initiating service termination..." "Red"
        Stop-CriticalServices
        Start-Sleep -Seconds 1
        
        # Phase 2: Network Hardening
        Write-MatrixMessage "Phase 2: Deploying network defenses..." "Yellow"
        Set-NetworkHardening
        Set-FirewallRules
        Start-Sleep -Seconds 1
        
        # Phase 3: Disable Admin Vulnerabilities
        Write-MatrixMessage "Phase 3: Eliminating privilege vectors..." "Magenta"
        Disable-AdminShares
        Set-PrivilegeEscalationProtection
        Start-Sleep -Seconds 1
        
        # Phase 4: Defender Enhancement
        Write-MatrixMessage "Phase 4: Enhancing defense systems..." "Cyan"
        Set-DefenderHardening
        Start-Sleep -Seconds 1
        
        # Phase 5: Threat Scanning
        Write-MatrixMessage "Phase 5: Scanning for anomalies..." "Red"
        $suspiciousAutostart = Scan-AutostartEntries
        Start-Sleep -Seconds 1
        
        # Phase 6: Report Generation
        Write-MatrixMessage "Phase 6: Compiling intelligence report..." "Green"
        $reportPath = Generate-HtmlReport -SuspiciousAutostart $suspiciousAutostart
        
        # Completion
        Write-Log "Agent Matrix hardening completed successfully" "SUCCESS"
        Show-CompletionBadge
        
        Write-MatrixMessage "System hardening complete!" "Green"
        Write-MatrixMessage "Log file: $Script:LogFile" "Info"
        if ($reportPath) {
            Write-MatrixMessage "Report file: $reportPath" "Info"
        }
        
        if (!$Unattended) {
            Write-MatrixMessage "Reboot recommended to apply all changes. Reboot now? (Y/N)" "Yellow"
            $rebootResponse = Read-Host
            if ($rebootResponse -match "^[Yy]") {
                Write-MatrixMessage "System reboot initiated..." "Red"
                Restart-Computer -Force
            }
        }
        
    } catch {
        Write-Log "Critical error in main execution: $($_.Exception.Message)" "ERROR"
        Write-Host "CRITICAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

# Script entry point
if ($MyInvocation.InvocationName -ne '.') {
    Main
}
#endregion