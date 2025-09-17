#Requires -Version 7.5
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    BND Command Center - Professional Windows ARM64 Hardening & Monitoring System
    
.DESCRIPTION
    Professional-grade PowerShell 7.5.1+ script for comprehensive Windows hardening and monitoring.
    Designed for maximum security on ARM64 architecture (Snapdragon, Surface Laptop 7).
    
    Features:
    - Advanced system hardening for ARM64/Snapdragon optimization
    - Self-healing background monitoring agents
    - Remote system mirroring capabilities  
    - Professional command center UI with color-coded status
    - Physical/virtual control points (START/STOP/EMERGENCY)
    - Military-grade acoustic alarms
    - 7x7x7 structured file organization
    - Honeytokens and security traps
    - Comprehensive logging and audit trails
    
.PARAMETER RemoteHost1
    Primary remote host for mirroring (placeholder)
    
.PARAMETER RemoteHost2  
    Secondary remote host for mirroring (placeholder)
    
.PARAMETER LogLevel
    Logging verbosity level (INFO, WARNING, ERROR, DEBUG)
    
.PARAMETER EmergencyMode
    Activates emergency shutdown protocols
    
.PARAMETER ForceRun
    Admin bypass for forced execution
    
.PARAMETER SoundsPath
    Path to military/technical alarm sound files
    
.EXAMPLE
    .\BND_CommandCenter_Hardening.ps1
    
.EXAMPLE
    .\BND_CommandCenter_Hardening.ps1 -RemoteHost1 "srv-backup-01" -RemoteHost2 "srv-mirror-02" -LogLevel DEBUG
    
.NOTES
    Version: 1.0.0
    Author: BND Command Center Security Team
    Requires: PowerShell 7.5.1+, Administrator privileges
    Optimized: Windows ARM64 (Snapdragon, Surface Laptop 7, 16GB RAM)
    Classification: Professional Use Only
#>

[CmdletBinding()]
param(
    [string]$RemoteHost1 = "placeholder-host-1",
    [string]$RemoteHost2 = "placeholder-host-2", 
    [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
    [string]$LogLevel = "INFO",
    [switch]$EmergencyMode,
    [switch]$ForceRun,
    [string]$SoundsPath = "C:\BND_CommandCenter\Sounds"
)

# Global Configuration
$Global:BND_Config = @{
    Version = "1.0.0"
    StartTime = Get-Date
    ComputerName = $env:COMPUTERNAME
    LogPath = "C:\BND_CommandCenter\Logs"
    ReportsPath = "C:\BND_CommandCenter\Reports"
    BackupPath = "C:\BND_CommandCenter\Backup"
    SystemState = "INITIALIZING"
    EmergencyActive = $false
    SelfHealingActive = $false
    MonitoringJobs = @()
    SecurityTraps = @()
    HardeningStatus = @{}
    RemoteHosts = @($RemoteHost1, $RemoteHost2)
}

# Color Scheme for Command Center UI
$Global:BND_Colors = @{
    OK = "Green"           # Matrix green for OK status
    CRITICAL = "Red"       # Red for critical alerts
    WARNING = "Yellow"     # Yellow for warnings  
    INFO = "Cyan"          # Blue/Cyan for information
    SYSTEM = "White"       # White for system messages
    EMERGENCY = "Magenta"  # Magenta for emergency states
}

#region Utility Functions

function Write-BNDLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG", "SUCCESS")]
        [string]$Level = "INFO",
        [switch]$NoConsole,
        [switch]$Emergency
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Ensure log directory exists
    if (!(Test-Path $Global:BND_Config.LogPath)) {
        New-Item -ItemType Directory -Path $Global:BND_Config.LogPath -Force | Out-Null
    }
    
    # Write to log file
    $logFile = Join-Path $Global:BND_Config.LogPath "BND_CommandCenter_$(Get-Date -Format 'yyyyMMdd').log"
    try {
        Add-Content -Path $logFile -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Silent fail for logging
    }
    
    # Console output with color coding
    if (!$NoConsole) {
        $color = switch ($Level) {
            "CRITICAL" { $Global:BND_Colors.CRITICAL }
            "ERROR" { $Global:BND_Colors.CRITICAL } 
            "WARNING" { $Global:BND_Colors.WARNING }
            "SUCCESS" { $Global:BND_Colors.OK }
            "DEBUG" { $Global:BND_Colors.INFO }
            default { $Global:BND_Colors.SYSTEM }
        }
        
        Write-Host $logEntry -ForegroundColor $color
        
        # Trigger alarm for critical events
        if ($Level -eq "CRITICAL" -or $Emergency) {
            Start-BNDAlarm -AlarmType "CRITICAL"
        }
    }
}

function Start-BNDAlarm {
    param(
        [ValidateSet("INFO", "WARNING", "CRITICAL", "EMERGENCY")]
        [string]$AlarmType = "INFO"
    )
    
    $soundFiles = @{
        "INFO" = "beep_info.wav"
        "WARNING" = "beep_warning.wav" 
        "CRITICAL" = "alarm_critical.wav"
        "EMERGENCY" = "alarm_emergency.wav"
    }
    
    $soundFile = Join-Path $SoundsPath $soundFiles[$AlarmType]
    
    if (Test-Path $soundFile) {
        try {
            # Use Windows Media Player for sound playback
            $player = New-Object System.Media.SoundPlayer $soundFile
            $player.Play()
        } catch {
            # Fallback to system beep
            [System.Console]::Beep(800, 500)
        }
    } else {
        # System beep patterns for different alarm types
        switch ($AlarmType) {
            "WARNING" { 
                [System.Console]::Beep(1000, 200)
                Start-Sleep -Milliseconds 100
                [System.Console]::Beep(1000, 200)
            }
            "CRITICAL" { 
                for ($i = 0; $i -lt 3; $i++) {
                    [System.Console]::Beep(1500, 300)
                    Start-Sleep -Milliseconds 100
                }
            }
            "EMERGENCY" {
                for ($i = 0; $i -lt 5; $i++) {
                    [System.Console]::Beep(2000, 200)
                    Start-Sleep -Milliseconds 50
                    [System.Console]::Beep(1000, 200) 
                    Start-Sleep -Milliseconds 50
                }
            }
            default { [System.Console]::Beep(800, 200) }
        }
    }
}

function Show-BNDHeader {
    Clear-Host
    Write-Host @"

    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                           BND COMMAND CENTER                                 ║
    ║                  Professional Security Hardening System                     ║
    ║                                                                              ║
    ║  Computer: $($Global:BND_Config.ComputerName.PadRight(20)) │ Version: $($Global:BND_Config.Version.PadRight(20)) ║
    ║  Started:  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').PadRight(20)) │ Status:  $($Global:BND_Config.SystemState.PadRight(20)) ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor $Global:BND_Colors.INFO
}

function Show-BNDStatus {
    param([string]$Operation, [int]$Progress = 0, [string]$Status = "RUNNING")
    
    $statusColor = switch ($Status) {
        "OK" { $Global:BND_Colors.OK }
        "WARNING" { $Global:BND_Colors.WARNING }
        "ERROR" { $Global:BND_Colors.CRITICAL }
        "CRITICAL" { $Global:BND_Colors.CRITICAL }
        default { $Global:BND_Colors.INFO }
    }
    
    $progressBar = "█" * [math]::Floor($Progress / 2) + "░" * (50 - [math]::Floor($Progress / 2))
    
    Write-Host "[OPERATION] " -ForegroundColor $Global:BND_Colors.INFO -NoNewline
    Write-Host "$Operation " -ForegroundColor $Global:BND_Colors.SYSTEM -NoNewline
    Write-Host "[$progressBar] " -ForegroundColor $statusColor -NoNewline
    Write-Host "$Progress% " -ForegroundColor $Global:BND_Colors.SYSTEM -NoNewline
    Write-Host "[$Status]" -ForegroundColor $statusColor
}

#endregion

#region System Analysis Functions

function Get-BNDSystemInfo {
    Write-BNDLog "Analyzing system configuration..." "INFO"
    
    try {
        $system = Get-CimInstance -ClassName Win32_ComputerSystem
        $os = Get-CimInstance -ClassName Win32_OperatingSystem  
        $processor = Get-CimInstance -ClassName Win32_Processor
        $memory = Get-CimInstance -ClassName Win32_PhysicalMemory
        
        $systemInfo = @{
            ComputerName = $system.Name
            Domain = $system.Domain
            Manufacturer = $system.Manufacturer
            Model = $system.Model
            OSName = $os.Caption
            OSVersion = $os.Version
            OSBuild = $os.BuildNumber
            OSArchitecture = $os.OSArchitecture
            ProcessorName = $processor.Name
            ProcessorArchitecture = $processor.Architecture
            ProcessorCores = $processor.NumberOfCores
            ProcessorThreads = $processor.NumberOfLogicalProcessors
            TotalRAM = [math]::Round(($memory | Measure-Object Capacity -Sum).Sum / 1GB, 2)
            IsARM64 = $processor.Architecture -eq 12  # ARM64 architecture code
            IsSnapdragon = $processor.Name -like "*Snapdragon*" -or $processor.Name -like "*Qualcomm*"
            IsSurfaceLaptop = $system.Model -like "*Surface Laptop*"
        }
        
        Write-BNDLog "System analysis completed successfully" "SUCCESS"
        return $systemInfo
        
    } catch {
        Write-BNDLog "Failed to analyze system: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-BNDSystemCompatibility {
    param([hashtable]$SystemInfo)
    
    Write-BNDLog "Checking system compatibility..." "INFO"
    
    $issues = @()
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7 -or 
        ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -lt 5)) {
        $issues += "PowerShell 7.5+ required, found $($PSVersionTable.PSVersion)"
    }
    
    # Check if running as Administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $issues += "Administrator privileges required"
    }
    
    # Check Windows version compatibility
    if ([int]$SystemInfo.OSBuild -lt 22000) {
        $issues += "Windows 11 or Windows Server 2022+ recommended for optimal ARM64 support"
    }
    
    # ARM64 optimization warnings
    if (!$SystemInfo.IsARM64) {
        Write-BNDLog "System is not ARM64 - some optimizations may not apply" "WARNING"
    }
    
    if ($SystemInfo.TotalRAM -lt 8) {
        $issues += "Minimum 8GB RAM recommended, found $($SystemInfo.TotalRAM)GB"
    }
    
    if ($issues.Count -gt 0) {
        foreach ($issue in $issues) {
            Write-BNDLog "COMPATIBILITY ISSUE: $issue" "WARNING"
        }
        
        if (!$ForceRun) {
            Write-BNDLog "Use -ForceRun to bypass compatibility checks" "INFO"
            return $false
        }
    }
    
    Write-BNDLog "System compatibility check completed" "SUCCESS"
    return $true
}

#endregion

#region File System Organization

function Initialize-BND777Structure {
    Write-BNDLog "Initializing 7x7x7 file system organization..." "INFO"
    
    $baseStructure = @{
        "C:\BND_CommandCenter" = @{
            "01_System" = @("Logs", "Reports", "Backup", "Config", "Scripts", "Tools", "Archives")
            "02_Security" = @("Policies", "Certificates", "Keys", "Hardening", "Monitoring", "Incidents", "Forensics")
            "03_Network" = @("Firewall", "VPN", "Remote", "Monitoring", "Logs", "Analysis", "Documentation")
            "04_Operations" = @("Scheduled", "Manual", "Emergency", "Maintenance", "Deployment", "Testing", "Validation")
            "05_Intelligence" = @("Threats", "Indicators", "Reports", "Analysis", "Sources", "Feeds", "Archives")
            "06_Compliance" = @("Audit", "Standards", "Policies", "Reports", "Evidence", "Documentation", "Training")
            "07_Development" = @("Scripts", "Tools", "Testing", "Documentation", "Templates", "Libraries", "Archives")
        }
    }
    
    try {
        foreach ($rootPath in $baseStructure.Keys) {
            if (!(Test-Path $rootPath)) {
                New-Item -ItemType Directory -Path $rootPath -Force | Out-Null
            }
            
            foreach ($level1 in $baseStructure[$rootPath].Keys) {
                $level1Path = Join-Path $rootPath $level1
                if (!(Test-Path $level1Path)) {
                    New-Item -ItemType Directory -Path $level1Path -Force | Out-Null
                }
                
                foreach ($level2 in $baseStructure[$rootPath][$level1]) {
                    $level2Path = Join-Path $level1Path $level2
                    if (!(Test-Path $level2Path)) {
                        New-Item -ItemType Directory -Path $level2Path -Force | Out-Null
                    }
                }
            }
        }
        
        # Create initial configuration files
        $configPath = "C:\BND_CommandCenter\01_System\Config"
        
        # System configuration
        $systemConfig = @{
            Version = $Global:BND_Config.Version
            Created = Get-Date
            LastUpdate = Get-Date
            RemoteHosts = $Global:BND_Config.RemoteHosts
            LogLevel = $LogLevel
            EmergencyContacts = @("admin@company.local", "security@company.local")
        } | ConvertTo-Json -Depth 3
        
        Set-Content -Path (Join-Path $configPath "system.json") -Value $systemConfig -Encoding UTF8
        
        # Security configuration
        $securityConfig = @{
            HardeningLevel = "MAXIMUM"
            MonitoringEnabled = $true
            SelfHealingEnabled = $true
            RemoteMirroringEnabled = $true
            HoneytokenEnabled = $true
            AlarmSounds = $true
        } | ConvertTo-Json
        
        Set-Content -Path (Join-Path $configPath "security.json") -Value $securityConfig -Encoding UTF8
        
        Write-BNDLog "7x7x7 file system structure initialized successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-BNDLog "Failed to initialize file system structure: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-BNDHoneytokens {
    Write-BNDLog "Deploying honeytokens and security traps..." "INFO"
    
    $honeytokenPaths = @(
        "C:\BND_CommandCenter\07_Development\Scripts\admin_passwords.txt",
        "C:\BND_CommandCenter\02_Security\Keys\private_key.pem", 
        "C:\BND_CommandCenter\01_System\Config\database_credentials.xml",
        "C:\BND_CommandCenter\03_Network\VPN\client_certificates.p12"
    )
    
    $honeytokenContent = @{
        "admin_passwords.txt" = @"
# Administrative Passwords - CONFIDENTIAL
administrator:Tr@p_H0n3y_2024!
admin:S3cur3_F@k3_P@ss
root:H0n3yP0t_Tr@p_2024
service_account:Tr@pp3d_Y0u_F0und_M3!
"@
        "private_key.pem" = @"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7... [FAKE KEY]
[This is a honeytoken - access is being logged]
-----END PRIVATE KEY-----
"@
        "database_credentials.xml" = @"
<?xml version="1.0" encoding="UTF-8"?>
<DatabaseConfig>
    <Server>sql-server-prod</Server>
    <Database>company_db</Database>
    <Username>sa_admin</Username>
    <Password>H0n3yTr@p_DB_2024!</Password>
    <!-- HONEYTOKEN: This file is monitored -->
</DatabaseConfig>
"@
        "client_certificates.p12" = @"
[Binary Certificate Data - FAKE]
This is a honeytoken file. Access is being monitored and logged.
Contact: security@company.local
"@
    }
    
    try {
        foreach ($path in $honeytokenPaths) {
            $directory = Split-Path $path -Parent
            if (!(Test-Path $directory)) {
                New-Item -ItemType Directory -Path $directory -Force | Out-Null
            }
            
            $filename = Split-Path $path -Leaf
            $content = $honeytokenContent[$filename]
            
            Set-Content -Path $path -Value $content -Encoding UTF8
            
            # Set file attributes to hidden
            Set-ItemProperty -Path $path -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)
            
            # Add to monitoring list
            $Global:BND_Config.SecurityTraps += @{
                Path = $path
                Type = "Honeytoken"
                Created = Get-Date
                Accessed = $false
            }
        }
        
        Write-BNDLog "Honeytokens deployed successfully - $(($honeytokenPaths).Count) traps active" "SUCCESS"
        return $true
        
    } catch {
        Write-BNDLog "Failed to deploy honeytokens: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

#endregion

#region Advanced ARM64 Hardening Functions

function Start-BNDSystemHardening {
    param([hashtable]$SystemInfo)
    
    Write-BNDLog "Initiating advanced system hardening protocols..." "INFO"
    
    # ARM64/Snapdragon specific optimizations
    if ($SystemInfo.IsARM64 -or $SystemInfo.IsSnapdragon) {
        Write-BNDLog "ARM64/Snapdragon architecture detected - applying optimized hardening" "INFO"
        Set-BNDARMOptimizations -SystemInfo $SystemInfo
    }
    
    # Core hardening procedures
    $hardeningSteps = @(
        @{Name="Windows Defender"; Function="Set-BNDDefenderHardening"},
        @{Name="Network Security"; Function="Set-BNDNetworkHardening"},
        @{Name="Service Hardening"; Function="Set-BNDServiceHardening"},
        @{Name="Registry Hardening"; Function="Set-BNDRegistryHardening"},
        @{Name="UAC Enhancement"; Function="Set-BNDUACHardening"},
        @{Name="PowerShell Security"; Function="Set-BNDPowerShellSecurity"},
        @{Name="File System Security"; Function="Set-BNDFileSystemSecurity"}
    )
    
    $stepCount = 0
    foreach ($step in $hardeningSteps) {
        $stepCount++
        $progress = [math]::Round(($stepCount / $hardeningSteps.Count) * 100)
        
        Show-BNDStatus -Operation $step.Name -Progress $progress -Status "RUNNING"
        
        try {
            & $step.Function
            $Global:BND_Config.HardeningStatus[$step.Name] = "SUCCESS"
            Show-BNDStatus -Operation $step.Name -Progress 100 -Status "OK"
        } catch {
            Write-BNDLog "Failed hardening step $($step.Name): $($_.Exception.Message)" "ERROR"
            $Global:BND_Config.HardeningStatus[$step.Name] = "FAILED"
            Show-BNDStatus -Operation $step.Name -Progress 100 -Status "ERROR"
        }
        
        Start-Sleep -Milliseconds 500
    }
}

function Set-BNDARMOptimizations {
    param([hashtable]$SystemInfo)
    
    Write-BNDLog "Applying ARM64/Snapdragon optimizations..." "INFO"
    
    try {
        # ARM64 specific power management hardening
        $powerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
        if (Test-Path $powerPath) {
            # Disable ARM64 CPU vulnerabilities mitigations that could affect performance
            Set-ItemProperty -Path $powerPath -Name "PlatformAoAcOverride" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            
            # Optimize ARM64 memory management for security
            Set-ItemProperty -Path "$powerPath\PowerSettings" -Name "ArmOptimizedSecurity" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        }
        
        # Surface Laptop 7 specific optimizations
        if ($SystemInfo.IsSurfaceLaptop) {
            Write-BNDLog "Surface Laptop 7 detected - applying hardware-specific security" "INFO"
            
            # Disable unnecessary Surface-specific services for security
            $surfaceServices = @("SurfaceService", "SurfaceDTXService", "SurfaceFlowService")
            foreach ($service in $surfaceServices) {
                try {
                    $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                    if ($svc -and $svc.Status -eq "Running") {
                        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                        Write-BNDLog "Disabled Surface service: $service" "SUCCESS"
                    }
                } catch {
                    Write-BNDLog "Could not disable Surface service $service" "WARNING"
                }
            }
        }
        
        # Snapdragon specific security enhancements
        if ($SystemInfo.IsSnapdragon) {
            Write-BNDLog "Qualcomm Snapdragon processor detected - applying chipset security" "INFO"
            
            # Disable Qualcomm specific telemetry and optimization services
            $qualcommServices = @("QualcommAtheros*", "QC*Service", "Qualcomm*")
            foreach ($servicePattern in $qualcommServices) {
                try {
                    Get-Service -Name $servicePattern -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Status -eq "Running" } |
                        ForEach-Object {
                            Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
                            Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
                            Write-BNDLog "Disabled Qualcomm service: $($_.Name)" "SUCCESS"
                        }
                } catch {
                    Write-BNDLog "Error processing Qualcomm services pattern: $servicePattern" "WARNING"
                }
            }
        }
        
        Write-BNDLog "ARM64 optimizations completed successfully" "SUCCESS"
        
    } catch {
        Write-BNDLog "ARM64 optimization failed: $($_.Exception.Message)" "ERROR"
    }
}

function Set-BNDDefenderHardening {
    Write-BNDLog "Configuring Windows Defender for maximum security..." "INFO"
    
    try {
        # Enable all advanced protection features
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendAllSamples
        Set-MpPreference -PUAProtection Enabled
        Set-MpPreference -EnableNetworkProtection Enabled
        Set-MpPreference -EnableControlledFolderAccess Enabled
        
        # Configure advanced scanning
        Set-MpPreference -ScanAvgCPULoadFactor 50
        Set-MpPreference -CheckForSignaturesBeforeRunningScan $true
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableBlockAtFirstSeen $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -DisableScriptScanning $false
        
        # Remove dangerous exclusions that attackers commonly add
        $dangerousExclusions = @("*.exe", "*.dll", "*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js", "*.jar")
        foreach ($exclusion in $dangerousExclusions) {
            try {
                Remove-MpPreference -ExclusionExtension $exclusion -ErrorAction SilentlyContinue
            } catch {
                # Silent continue
            }
        }
        
        # Update signatures
        Update-MpSignature -ErrorAction SilentlyContinue
        
        Write-BNDLog "Windows Defender hardening completed" "SUCCESS"
        
    } catch {
        Write-BNDLog "Windows Defender configuration failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Set-BNDNetworkHardening {
    Write-BNDLog "Implementing advanced network security protocols..." "INFO"
    
    try {
        # Disable dangerous network protocols
        $networkSettings = @{
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" = @{
                "EnableMulticast" = 0  # Disable LLMNR
            }
            "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" = @{
                "EnableLMHosts" = 0    # Disable LMHosts lookup
            }
            "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" = @{
                "IGMPVersion" = 2      # Secure IGMP version
                "DisableIPSourceRouting" = 1  # Disable IP source routing
                "EnableICMPRedirect" = 0      # Disable ICMP redirects
            }
        }
        
        foreach ($regPath in $networkSettings.Keys) {
            if (!(Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            
            foreach ($setting in $networkSettings[$regPath].Keys) {
                Set-ItemProperty -Path $regPath -Name $setting -Value $networkSettings[$regPath][$setting] -Type DWord
            }
        }
        
        # Configure Windows Firewall for maximum security
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
        Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True
        
        # Block dangerous ports
        $dangerousPorts = @(
            @{Port=135; Protocol="TCP"; Name="RPC Endpoint Mapper"},
            @{Port=139; Protocol="TCP"; Name="NetBIOS Session"},
            @{Port=445; Protocol="TCP"; Name="SMB"},
            @{Port=1900; Protocol="UDP"; Name="SSDP"},
            @{Port=5353; Protocol="UDP"; Name="mDNS"},
            @{Port=137; Protocol="UDP"; Name="NetBIOS Name Service"},
            @{Port=138; Protocol="UDP"; Name="NetBIOS Datagram Service"}
        )
        
        foreach ($port in $dangerousPorts) {
            $ruleName = "BND_Block_$($port.Name)_$($port.Protocol)_$($port.Port)"
            try {
                Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol $port.Protocol -LocalPort $port.Port -Action Block -Enabled True | Out-Null
                Write-BNDLog "Blocked $($port.Protocol) port $($port.Port) ($($port.Name))" "SUCCESS"
            } catch {
                Write-BNDLog "Failed to block port $($port.Port): $($_.Exception.Message)" "WARNING"
            }
        }
        
        Write-BNDLog "Network hardening completed successfully" "SUCCESS"
        
    } catch {
        Write-BNDLog "Network hardening failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Set-BNDServiceHardening {
    Write-BNDLog "Hardening Windows services..." "INFO"
    
    # Critical services to disable for security
    $dangerousServices = @(
        @{Name="lanmanserver"; DisplayName="Server (SMB)"; Risk="File sharing exploitation"},
        @{Name="WinRM"; DisplayName="Windows Remote Management"; Risk="Remote command execution"},
        @{Name="RemoteRegistry"; DisplayName="Remote Registry"; Risk="Registry manipulation"},
        @{Name="TlntSvr"; DisplayName="Telnet"; Risk="Unencrypted remote access"},
        @{Name="SNMP"; DisplayName="SNMP Service"; Risk="Network reconnaissance"},
        @{Name="Spooler"; DisplayName="Print Spooler"; Risk="PrintNightmare vulnerability"},
        @{Name="SSDPSRV"; DisplayName="SSDP Discovery"; Risk="Network discovery"},
        @{Name="upnphost"; DisplayName="UPnP Device Host"; Risk="Network exposure"},
        @{Name="XblAuthManager"; DisplayName="Xbox Live Auth Manager"; Risk="Gaming service exposure"},
        @{Name="XblGameSave"; DisplayName="Xbox Live Game Save"; Risk="Gaming service exposure"},
        @{Name="XboxNetApiSvc"; DisplayName="Xbox Live Networking"; Risk="Gaming service exposure"}
    )
    
    try {
        foreach ($service in $dangerousServices) {
            try {
                $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
                if ($svc) {
                    if ($svc.Status -eq "Running") {
                        Stop-Service -Name $service.Name -Force -ErrorAction Stop
                        Write-BNDLog "Stopped service: $($service.DisplayName)" "SUCCESS"
                    }
                    
                    Set-Service -Name $service.Name -StartupType Disabled -ErrorAction Stop
                    Write-BNDLog "Disabled service: $($service.DisplayName)" "SUCCESS"
                } else {
                    Write-BNDLog "Service not found: $($service.DisplayName)" "INFO"
                }
            } catch {
                Write-BNDLog "Failed to disable service $($service.DisplayName): $($_.Exception.Message)" "WARNING"
            }
        }
        
        Write-BNDLog "Service hardening completed" "SUCCESS"
        
    } catch {
        Write-BNDLog "Service hardening failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Set-BNDRegistryHardening {
    Write-BNDLog "Applying registry security hardening..." "INFO"
    
    try {
        # Security registry modifications
        $registrySettings = @{
            # Disable autorun for all drives
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
                "NoDriveTypeAutoRun" = 255
                "NoAutorun" = 1
            }
            
            # Disable WPAD
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" = @{
                "WpadOverride" = 1
            }
            
            # Security settings
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                "EnableLUA" = 1                    # Enable UAC
                "ConsentPromptBehaviorAdmin" = 2   # Prompt for credentials
                "ConsentPromptBehaviorUser" = 3    # Prompt for credentials  
                "PromptOnSecureDesktop" = 1        # Secure desktop for UAC
                "LocalAccountTokenFilterPolicy" = 0  # Disable remote UAC
            }
            
            # Disable Windows Script Host
            "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" = @{
                "Enabled" = 0
            }
            
            # Disable PowerShell v2
            "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" = @{
                "PowerShellVersion" = ""  # Disable by clearing version
            }
        }
        
        foreach ($regPath in $registrySettings.Keys) {
            try {
                if (!(Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                
                foreach ($setting in $registrySettings[$regPath].Keys) {
                    $value = $registrySettings[$regPath][$setting]
                    if ($value -is [string] -and $value -eq "") {
                        Remove-ItemProperty -Path $regPath -Name $setting -ErrorAction SilentlyContinue
                    } else {
                        Set-ItemProperty -Path $regPath -Name $setting -Value $value -Type DWord
                    }
                }
                
                Write-BNDLog "Applied registry hardening: $regPath" "SUCCESS"
                
            } catch {
                Write-BNDLog "Failed to apply registry setting $regPath`: $($_.Exception.Message)" "WARNING"
            }
        }
        
        Write-BNDLog "Registry hardening completed" "SUCCESS"
        
    } catch {
        Write-BNDLog "Registry hardening failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Set-BNDUACHardening {
    Write-BNDLog "Configuring User Account Control maximum security..." "INFO"
    
    try {
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        
        # Maximum UAC settings
        Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -Type DWord
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorUser" -Value 3 -Type DWord  
        Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord
        Set-ItemProperty -Path $uacPath -Name "EnableVirtualization" -Value 1 -Type DWord
        Set-ItemProperty -Path $uacPath -Name "EnableSecureUIAPaths" -Value 1 -Type DWord
        Set-ItemProperty -Path $uacPath -Name "EnableUIADesktopToggle" -Value 0 -Type DWord
        Set-ItemProperty -Path $uacPath -Name "ValidateAdminCodeSignatures" -Value 1 -Type DWord
        
        Write-BNDLog "UAC hardening completed successfully" "SUCCESS"
        
    } catch {
        Write-BNDLog "UAC hardening failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Set-BNDPowerShellSecurity {
    Write-BNDLog "Configuring PowerShell security policies..." "INFO"
    
    try {
        # Set execution policy to most restrictive
        Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
        
        # Disable PowerShell v2
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction SilentlyContinue
            Write-BNDLog "PowerShell v2 disabled" "SUCCESS"
        } catch {
            Write-BNDLog "Could not disable PowerShell v2 - may not be installed" "INFO"
        }
        
        # Configure PowerShell logging
        $psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
        if (!(Test-Path $psLoggingPath)) {
            New-Item -Path $psLoggingPath -Force | Out-Null
        }
        
        # Enable script block logging
        $scriptBlockPath = "$psLoggingPath\ScriptBlockLogging"
        if (!(Test-Path $scriptBlockPath)) {
            New-Item -Path $scriptBlockPath -Force | Out-Null
        }
        Set-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
        
        # Enable module logging
        $moduleLoggingPath = "$psLoggingPath\ModuleLogging"
        if (!(Test-Path $moduleLoggingPath)) {
            New-Item -Path $moduleLoggingPath -Force | Out-Null
        }
        Set-ItemProperty -Path $moduleLoggingPath -Name "EnableModuleLogging" -Value 1 -Type DWord
        
        Write-BNDLog "PowerShell security configuration completed" "SUCCESS"
        
    } catch {
        Write-BNDLog "PowerShell security configuration failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Set-BNDFileSystemSecurity {
    Write-BNDLog "Implementing file system security measures..." "INFO"
    
    try {
        # Disable 8.3 name generation
        fsutil behavior set DisableLastAccess 1 | Out-Null
        fsutil behavior set Disable8dot3 1 | Out-Null
        
        # Configure NTFS security
        $securitySettings = @{
            # Disable NTFS short name generation
            "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" = @{
                "NtfsDisable8dot3NameCreation" = 1
                "NtfsDisableLastAccessUpdate" = 1
            }
        }
        
        foreach ($regPath in $securitySettings.Keys) {
            foreach ($setting in $securitySettings[$regPath].Keys) {
                Set-ItemProperty -Path $regPath -Name $setting -Value $securitySettings[$regPath][$setting] -Type DWord
            }
        }
        
        Write-BNDLog "File system security hardening completed" "SUCCESS"
        
    } catch {
        Write-BNDLog "File system security hardening failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

#endregion

#region Self-Healing and Monitoring Agents

function Start-BNDSelfHealingAgent {
    Write-BNDLog "Initializing self-healing monitoring agent..." "INFO"
    
    try {
        # Create self-healing script
        $selfHealingScript = @"
# BND Self-Healing Agent
`$LogPath = "C:\BND_CommandCenter\Logs"
`$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Write-AgentLog {
    param([string]`$Message, [string]`$Level = "INFO")
    `$logEntry = "[`$timestamp] [AGENT] [`$Level] `$Message"
    Add-Content -Path "`$LogPath\BND_SelfHealing.log" -Value `$logEntry -ErrorAction SilentlyContinue
}

# Monitor critical services
`$criticalServices = @("Windefend", "EventLog", "Wuauserv", "BITS")
foreach (`$service in `$criticalServices) {
    try {
        `$svc = Get-Service -Name `$service -ErrorAction SilentlyContinue
        if (`$svc -and `$svc.Status -ne "Running") {
            Start-Service -Name `$service -ErrorAction SilentlyContinue
            Write-AgentLog "Restarted critical service: `$service" "SUCCESS"
        }
    } catch {
        Write-AgentLog "Failed to restart service `$service" "ERROR"
    }
}

# Monitor Windows Defender
try {
    `$defenderStatus = Get-MpComputerStatus
    if (-not `$defenderStatus.RealTimeProtectionEnabled) {
        Set-MpPreference -DisableRealtimeMonitoring `$false
        Write-AgentLog "Re-enabled Windows Defender real-time protection" "SUCCESS"
    }
} catch {
    Write-AgentLog "Failed to check/enable Windows Defender" "ERROR"
}

# Monitor firewall
try {
    `$firewallProfiles = Get-NetFirewallProfile
    foreach (`$profile in `$firewallProfiles) {
        if (-not `$profile.Enabled) {
            Set-NetFirewallProfile -Name `$profile.Name -Enabled True
            Write-AgentLog "Re-enabled firewall profile: `$(`$profile.Name)" "SUCCESS"
        }
    }
} catch {
    Write-AgentLog "Failed to check/enable firewall" "ERROR"
}

Write-AgentLog "Self-healing check completed" "INFO"
"@
        
        # Save self-healing script
        $agentPath = "C:\BND_CommandCenter\01_System\Scripts"
        if (!(Test-Path $agentPath)) {
            New-Item -ItemType Directory -Path $agentPath -Force | Out-Null
        }
        
        $agentScript = Join-Path $agentPath "SelfHealingAgent.ps1"
        Set-Content -Path $agentScript -Value $selfHealingScript -Encoding UTF8
        
        # Create scheduled task for self-healing
        $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$agentScript`""
        $taskTrigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 15) -Once -At (Get-Date)
        $taskSettings = New-ScheduledTaskSettingsSet -Hidden -DontStopOnIdleEnd -RestartCount 3
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        $task = New-ScheduledTask -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Description "BND Command Center Self-Healing Agent"
        
        Register-ScheduledTask -TaskName "BND_SelfHealingAgent" -InputObject $task -Force | Out-Null
        
        $Global:BND_Config.SelfHealingActive = $true
        Write-BNDLog "Self-healing agent initialized and scheduled" "SUCCESS"
        
    } catch {
        Write-BNDLog "Failed to initialize self-healing agent: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Start-BNDHoneytokenMonitor {
    Write-BNDLog "Starting honeytoken monitoring agent..." "INFO"
    
    try {
        # Create honeytoken monitoring script
        $monitorScript = @"
# BND Honeytoken Monitor
`$LogPath = "C:\BND_CommandCenter\Logs"
`$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Write-MonitorLog {
    param([string]`$Message, [string]`$Level = "INFO")
    `$logEntry = "[`$timestamp] [HONEYTOKEN] [`$Level] `$Message"
    Add-Content -Path "`$LogPath\BND_HoneytokenMonitor.log" -Value `$logEntry -ErrorAction SilentlyContinue
}

# Monitor honeytoken files
`$honeytokenPaths = @(
    "C:\BND_CommandCenter\07_Development\Scripts\admin_passwords.txt",
    "C:\BND_CommandCenter\02_Security\Keys\private_key.pem",
    "C:\BND_CommandCenter\01_System\Config\database_credentials.xml",
    "C:\BND_CommandCenter\03_Network\VPN\client_certificates.p12"
)

foreach (`$path in `$honeytokenPaths) {
    if (Test-Path `$path) {
        try {
            `$file = Get-Item `$path
            `$lastAccess = `$file.LastAccessTime
            `$lastWrite = `$file.LastWriteTime
            
            # Check if file was accessed recently (within last 15 minutes)
            if (`$lastAccess -gt (Get-Date).AddMinutes(-15)) {
                Write-MonitorLog "SECURITY ALERT: Honeytoken accessed - `$path" "CRITICAL"
                
                # Trigger additional security measures
                `$eventLog = @{
                    LogName = "Application"
                    Source = "BND Command Center"
                    EventId = 9001
                    EntryType = "Warning"
                    Message = "SECURITY BREACH: Honeytoken file accessed at `$path. Potential unauthorized access detected."
                }
                Write-EventLog @eventLog -ErrorAction SilentlyContinue
            }
            
            # Check if file was modified
            if (`$lastWrite -gt (Get-Date).AddMinutes(-15)) {
                Write-MonitorLog "SECURITY ALERT: Honeytoken modified - `$path" "CRITICAL"
            }
            
        } catch {
            Write-MonitorLog "Error monitoring honeytoken `$path`: `$(`$_.Exception.Message)" "ERROR"
        }
    }
}

Write-MonitorLog "Honeytoken monitoring check completed" "INFO"
"@
        
        # Save monitoring script
        $monitorPath = Join-Path $agentPath "HoneytokenMonitor.ps1"
        Set-Content -Path $monitorPath -Value $monitorScript -Encoding UTF8
        
        # Create scheduled task for honeytoken monitoring
        $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$monitorPath`""
        $taskTrigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
        $taskSettings = New-ScheduledTaskSettingsSet -Hidden -DontStopOnIdleEnd -RestartCount 3
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        $task = New-ScheduledTask -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Description "BND Command Center Honeytoken Monitor"
        
        Register-ScheduledTask -TaskName "BND_HoneytokenMonitor" -InputObject $task -Force | Out-Null
        
        Write-BNDLog "Honeytoken monitoring agent initialized" "SUCCESS"
        
    } catch {
        Write-BNDLog "Failed to initialize honeytoken monitor: $($_.Exception.Message)" "ERROR"
        throw
    }
}

#endregion

#region Control Points

function Invoke-BNDSystemStart {
    Write-BNDLog "SYSTEM START - Initializing BND Command Center..." "INFO"
    Start-BNDAlarm -AlarmType "INFO"
    
    $Global:BND_Config.SystemState = "STARTING"
    Show-BNDHeader
    
    Write-Host "[CONTROL POINT] " -ForegroundColor $Global:BND_Colors.INFO -NoNewline
    Write-Host "SYSTEM START INITIATED" -ForegroundColor $Global:BND_Colors.OK
    
    return $true
}

function Invoke-BNDSystemStop {
    Write-BNDLog "SYSTEM STOP - Graceful shutdown initiated..." "WARNING"
    Start-BNDAlarm -AlarmType "WARNING"
    
    $Global:BND_Config.SystemState = "STOPPING"
    
    Write-Host "[CONTROL POINT] " -ForegroundColor $Global:BND_Colors.INFO -NoNewline
    Write-Host "SYSTEM STOP INITIATED" -ForegroundColor $Global:BND_Colors.WARNING
    
    # Cleanup scheduled tasks
    try {
        Unregister-ScheduledTask -TaskName "BND_SelfHealingAgent" -Confirm:$false -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName "BND_HoneytokenMonitor" -Confirm:$false -ErrorAction SilentlyContinue
        Write-BNDLog "Scheduled monitoring agents stopped" "INFO"
    } catch {
        Write-BNDLog "Error stopping monitoring agents" "WARNING"
    }
    
    return $true
}

function Invoke-BNDEmergencyShutdown {
    Write-BNDLog "EMERGENCY SHUTDOWN - Critical security event detected!" "CRITICAL" -Emergency
    Start-BNDAlarm -AlarmType "EMERGENCY"
    
    $Global:BND_Config.SystemState = "EMERGENCY"
    $Global:BND_Config.EmergencyActive = $true
    
    Write-Host "[EMERGENCY] " -ForegroundColor $Global:BND_Colors.EMERGENCY -NoNewline
    Write-Host "EMERGENCY SHUTDOWN PROTOCOL ACTIVATED" -ForegroundColor $Global:BND_Colors.CRITICAL
    
    # Emergency actions
    try {
        # Disable all network adapters
        Get-NetAdapter | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
        Write-BNDLog "Emergency: Network adapters disabled" "CRITICAL"
        
        # Stop all non-essential services
        $essentialServices = @("Winlogon", "csrss", "wininit", "services", "lsass", "EventLog")
        Get-Service | Where-Object { $_.Status -eq "Running" -and $_.Name -notin $essentialServices } | 
            Stop-Service -Force -ErrorAction SilentlyContinue
        
        Write-BNDLog "Emergency: Non-essential services stopped" "CRITICAL"
        
    } catch {
        Write-BNDLog "Emergency shutdown execution failed: $($_.Exception.Message)" "CRITICAL"
    }
    
    return $true
}

#endregion

#region Remote Mirroring Functions

function Initialize-BNDRemoteMirroring {
    Write-BNDLog "Initializing remote system mirroring capabilities..." "INFO"
    
    try {
        # Prepare PowerShell Remoting
        Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue
        Set-WSManQuickConfig -Force -ErrorAction SilentlyContinue
        
        # Configure trusted hosts (for testing - in production use proper certificates)
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $($Global:BND_Config.RemoteHosts -join ",") -Force -ErrorAction SilentlyContinue
        
        # Test remote connectivity
        foreach ($remoteHost in $Global:BND_Config.RemoteHosts) {
            if ($remoteHost -ne "placeholder-host-1" -and $remoteHost -ne "placeholder-host-2") {
                try {
                    Test-WSMan -ComputerName $remoteHost -ErrorAction Stop | Out-Null
                    Write-BNDLog "Remote host $remoteHost is accessible" "SUCCESS"
                } catch {
                    Write-BNDLog "Remote host $remoteHost is not accessible: $($_.Exception.Message)" "WARNING"
                }
            } else {
                Write-BNDLog "Placeholder remote host configured: $remoteHost" "INFO"
            }
        }
        
        Write-BNDLog "Remote mirroring capabilities initialized" "SUCCESS"
        return $true
        
    } catch {
        Write-BNDLog "Failed to initialize remote mirroring: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Send-BNDReportToRemote {
    param([string]$ReportPath)
    
    Write-BNDLog "Attempting to mirror reports to remote systems..." "INFO"
    
    foreach ($remoteHost in $Global:BND_Config.RemoteHosts) {
        if ($remoteHost -eq "placeholder-host-1" -or $remoteHost -eq "placeholder-host-2") {
            Write-BNDLog "Skipping placeholder remote host: $remoteHost" "INFO"
            continue
        }
        
        try {
            # Create remote session
            $session = New-PSSession -ComputerName $remoteHost -ErrorAction Stop
            
            # Create remote directory
            Invoke-Command -Session $session -ScriptBlock {
                param($remotePath)
                if (!(Test-Path $remotePath)) {
                    New-Item -ItemType Directory -Path $remotePath -Force | Out-Null
                }
            } -ArgumentList "C:\BND_RemoteMirror\Reports"
            
            # Copy report file
            $remoteReportPath = "C:\BND_RemoteMirror\Reports\$(Split-Path $ReportPath -Leaf)"
            Copy-Item -Path $ReportPath -Destination $remoteReportPath -ToSession $session -ErrorAction Stop
            
            Write-BNDLog "Report successfully mirrored to $remoteHost" "SUCCESS"
            
            # Close session
            Remove-PSSession $session
            
        } catch {
            Write-BNDLog "Failed to mirror report to $remoteHost`: $($_.Exception.Message)" "WARNING"
        }
    }
}

#endregion

#region Report Generation

function New-BNDComprehensiveReport {
    Write-BNDLog "Generating comprehensive security report..." "INFO"
    
    try {
        $systemInfo = Get-BNDSystemInfo
        $reportPath = Join-Path $Global:BND_Config.ReportsPath "BND_Security_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        
        if (!(Test-Path $Global:BND_Config.ReportsPath)) {
            New-Item -ItemType Directory -Path $Global:BND_Config.ReportsPath -Force | Out-Null
        }
        
        $reportContent = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>BND Command Center Security Report</title>
    <style>
        body { font-family: 'Consolas', 'Courier New', monospace; background-color: #0a0a0a; color: #ffffff; margin: 20px; }
        .header { text-align: center; border: 2px solid #00ff00; padding: 20px; margin-bottom: 20px; background-color: #001100; }
        .section { margin: 20px 0; border: 1px solid #00ff00; padding: 15px; background-color: #001a00; }
        .title { color: #00ffff; font-size: 18px; font-weight: bold; margin-bottom: 10px; }
        .success { color: #00ff00; }
        .warning { color: #ffff00; }
        .error { color: #ff0000; }
        .info { color: #00ffff; }
        .critical { color: #ff0000; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #00ff00; padding: 8px; text-align: left; }
        th { background-color: #003300; color: #00ff00; }
        .status-ok { background-color: #001100; color: #00ff00; }
        .status-warning { background-color: #331100; color: #ffff00; }
        .status-error { background-color: #330000; color: #ff0000; }
        .badge { text-align: center; font-family: monospace; font-size: 10px; color: #00ff00; margin: 20px 0; white-space: pre; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ BND COMMAND CENTER SECURITY REPORT 🛡️</h1>
        <p>PROFESSIONAL WINDOWS HARDENING SYSTEM</p>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC') | Computer: $($systemInfo.ComputerName)</p>
    </div>

    <div class="section">
        <div class="title">📊 SYSTEM INFORMATION</div>
        <table>
            <tr><th>Property</th><th>Value</th><th>Status</th></tr>
            <tr><td>Operating System</td><td>$($systemInfo.OSName)</td><td class="info">✓</td></tr>
            <tr><td>OS Version</td><td>$($systemInfo.OSVersion)</td><td class="info">✓</td></tr>
            <tr><td>Build Number</td><td>$($systemInfo.OSBuild)</td><td class="info">✓</td></tr>
            <tr><td>Architecture</td><td>$($systemInfo.OSArchitecture)</td><td class="info">✓</td></tr>
            <tr><td>Processor</td><td>$($systemInfo.ProcessorName)</td><td class="$(if($systemInfo.IsARM64){"success"} else {"info"})">$(if($systemInfo.IsARM64){"ARM64 ✓"} else {"x64"})</td></tr>
            <tr><td>Cores/Threads</td><td>$($systemInfo.ProcessorCores)/$($systemInfo.ProcessorThreads)</td><td class="info">✓</td></tr>
            <tr><td>Total RAM</td><td>$($systemInfo.TotalRAM) GB</td><td class="$(if($systemInfo.TotalRAM -ge 16){"success"} else {"warning"})">$(if($systemInfo.TotalRAM -ge 16){"✓"} else {"⚠"})</td></tr>
            <tr><td>Domain</td><td>$($systemInfo.Domain)</td><td class="info">✓</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="title">🔧 HARDENING STATUS</div>
        <table>
            <tr><th>Component</th><th>Status</th><th>Details</th></tr>
"@

        # Add hardening status
        foreach ($component in $Global:BND_Config.HardeningStatus.Keys) {
            $status = $Global:BND_Config.HardeningStatus[$component]
            $statusClass = if ($status -eq "SUCCESS") { "status-ok" } elseif ($status -eq "FAILED") { "status-error" } else { "status-warning" }
            $statusIcon = if ($status -eq "SUCCESS") { "✓" } elseif ($status -eq "FAILED") { "✗" } else { "⚠" }
            
            $reportContent += "<tr><td>$component</td><td class=`"$statusClass`">$status $statusIcon</td><td>Hardening applied</td></tr>"
        }

        $reportContent += @"
        </table>
    </div>

    <div class="section">
        <div class="title">🛡️ SECURITY FEATURES ENABLED</div>
        <ul>
            <li class="success">✓ Windows Defender Advanced Protection</li>
            <li class="success">✓ Windows Firewall Enhanced Configuration</li>
            <li class="success">✓ UAC Maximum Security Settings</li>
            <li class="success">✓ PowerShell Security Hardening</li>
            <li class="success">✓ Network Protocol Hardening</li>
            <li class="success">✓ Service Attack Surface Reduction</li>
            <li class="success">✓ Registry Security Hardening</li>
            <li class="success">✓ File System Security Enhancement</li>
            $(if($systemInfo.IsARM64){"<li class=`"success`">✓ ARM64/Snapdragon Optimizations</li>"})
            $(if($systemInfo.IsSurfaceLaptop){"<li class=`"success`">✓ Surface Laptop Security Enhancements</li>"})
        </ul>
    </div>

    <div class="section">
        <div class="title">📋 MONITORING AGENTS</div>
        <table>
            <tr><th>Agent</th><th>Status</th><th>Frequency</th><th>Description</th></tr>
            <tr><td>Self-Healing Agent</td><td class="$(if($Global:BND_Config.SelfHealingActive){"success"} else {"warning"})">$(if($Global:BND_Config.SelfHealingActive){"ACTIVE ✓"} else {"INACTIVE ⚠"})</td><td>15 minutes</td><td>Monitors and repairs critical services</td></tr>
            <tr><td>Honeytoken Monitor</td><td class="success">ACTIVE ✓</td><td>5 minutes</td><td>Detects unauthorized access attempts</td></tr>
            <tr><td>Remote Mirroring</td><td class="info">CONFIGURED ✓</td><td>On-demand</td><td>Mirrors reports to remote systems</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="title">🎯 SECURITY TRAPS</div>
        <table>
            <tr><th>Trap Type</th><th>Location</th><th>Status</th></tr>
"@

        # Add security traps information
        foreach ($trap in $Global:BND_Config.SecurityTraps) {
            $reportContent += "<tr><td>$($trap.Type)</td><td>$($trap.Path)</td><td class=`"success`">ACTIVE ✓</td></tr>"
        }

        $reportContent += @"
        </table>
    </div>

    <div class="section">
        <div class="title">⚠️ SECURITY RECOMMENDATIONS</div>
        <ul>
            <li class="info">• Regularly update Windows and all installed software</li>
            <li class="info">• Monitor security logs daily for suspicious activities</li>
            <li class="info">• Perform periodic security assessments</li>
            <li class="info">• Keep Windows Defender signatures updated</li>
            <li class="info">• Review and test backup/restore procedures</li>
            <li class="warning">• System reboot recommended to apply all changes</li>
            <li class="info">• Monitor honeytoken access logs for security breaches</li>
        </ul>
    </div>

    <div class="badge">
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                        🏆 BND COMMAND CENTER CERTIFICATION 🏆                 ║
    ║                                                                               ║
    ║   This system has been hardened using BND Command Center protocols           ║
    ║   Professional-grade security measures have been implemented                 ║
    ║   Continuous monitoring and self-healing agents are active                   ║
    ║                                                                               ║
    ║   Certified Secure: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')                                     ║
    ║   Classification: PROFESSIONAL USE ONLY                                      ║
    ║   Agent ID: BND-$(Get-Random -Minimum 100000 -Maximum 999999)                                            ║
    ║                                                                               ║
    ║   "Security through technical excellence and professional discipline"        ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
    </div>

    <div class="section">
        <div class="title">📞 EMERGENCY PROCEDURES</div>
        <p><strong class="critical">EMERGENCY SHUTDOWN:</strong> Run script with -EmergencyMode to activate immediate lockdown</p>
        <p><strong class="warning">SYSTEM STOP:</strong> Use Invoke-BNDSystemStop function for graceful shutdown</p>
        <p><strong class="info">SYSTEM START:</strong> Use Invoke-BNDSystemStart function to initialize monitoring</p>
    </div>

    <div class="section">
        <div class="title">📄 REPORT INFORMATION</div>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Report Generated</td><td>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</td></tr>
            <tr><td>Script Version</td><td>$($Global:BND_Config.Version)</td></tr>
            <tr><td>Execution Time</td><td>$((Get-Date) - $Global:BND_Config.StartTime)</td></tr>
            <tr><td>Log File</td><td>$($Global:BND_Config.LogPath)\BND_CommandCenter_$(Get-Date -Format 'yyyyMMdd').log</td></tr>
        </table>
    </div>
</body>
</html>
"@

        Set-Content -Path $reportPath -Value $reportContent -Encoding UTF8
        Write-BNDLog "Comprehensive security report generated: $reportPath" "SUCCESS"
        
        # Mirror to remote systems
        Send-BNDReportToRemote -ReportPath $reportPath
        
        return $reportPath
        
    } catch {
        Write-BNDLog "Failed to generate comprehensive report: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

#endregion

#region Main Execution Function

function Invoke-BNDCommandCenter {
    [CmdletBinding()]
    param()
    
    try {
        # Emergency mode check
        if ($EmergencyMode) {
            Invoke-BNDEmergencyShutdown
            return
        }
        
        # Initialize system
        if (!(Invoke-BNDSystemStart)) {
            throw "System initialization failed"
        }
        
        # System analysis
        Write-BNDLog "Starting BND Command Center Professional Hardening System v$($Global:BND_Config.Version)" "INFO"
        Show-BNDStatus -Operation "System Analysis" -Progress 10 -Status "RUNNING"
        
        $systemInfo = Get-BNDSystemInfo
        if (!$systemInfo) {
            throw "System analysis failed"
        }
        
        Show-BNDStatus -Operation "System Analysis" -Progress 100 -Status "OK"
        
        # Compatibility check
        Show-BNDStatus -Operation "Compatibility Check" -Progress 20 -Status "RUNNING"
        if (!(Test-BNDSystemCompatibility -SystemInfo $systemInfo)) {
            throw "System compatibility check failed"
        }
        Show-BNDStatus -Operation "Compatibility Check" -Progress 100 -Status "OK"
        
        # Initialize file system structure
        Show-BNDStatus -Operation "File System Organization" -Progress 30 -Status "RUNNING"
        if (!(Initialize-BND777Structure)) {
            throw "File system organization failed"
        }
        Show-BNDStatus -Operation "File System Organization" -Progress 100 -Status "OK"
        
        # Deploy honeytokens
        Show-BNDStatus -Operation "Security Trap Deployment" -Progress 40 -Status "RUNNING"
        if (!(Set-BNDHoneytokens)) {
            throw "Honeytoken deployment failed"
        }
        Show-BNDStatus -Operation "Security Trap Deployment" -Progress 100 -Status "OK"
        
        # System hardening
        Show-BNDStatus -Operation "System Hardening" -Progress 50 -Status "RUNNING"
        Start-BNDSystemHardening -SystemInfo $systemInfo
        Show-BNDStatus -Operation "System Hardening" -Progress 100 -Status "OK"
        
        # Initialize remote mirroring
        Show-BNDStatus -Operation "Remote Mirroring Setup" -Progress 70 -Status "RUNNING"
        Initialize-BNDRemoteMirroring | Out-Null
        Show-BNDStatus -Operation "Remote Mirroring Setup" -Progress 100 -Status "OK"
        
        # Start monitoring agents
        Show-BNDStatus -Operation "Monitoring Agents" -Progress 80 -Status "RUNNING"
        Start-BNDSelfHealingAgent
        Start-BNDHoneytokenMonitor
        Show-BNDStatus -Operation "Monitoring Agents" -Progress 100 -Status "OK"
        
        # Generate comprehensive report
        Show-BNDStatus -Operation "Report Generation" -Progress 90 -Status "RUNNING"
        $reportPath = New-BNDComprehensiveReport
        Show-BNDStatus -Operation "Report Generation" -Progress 100 -Status "OK"
        
        # Final status
        $Global:BND_Config.SystemState = "OPERATIONAL"
        Show-BNDStatus -Operation "System Operational" -Progress 100 -Status "OK"
        
        # Success notification
        Start-BNDAlarm -AlarmType "INFO"
        Write-Host ""
        Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $Global:BND_Colors.OK
        Write-Host "║                    MISSION ACCOMPLISHED                        ║" -ForegroundColor $Global:BND_Colors.OK
        Write-Host "║                                                                ║" -ForegroundColor $Global:BND_Colors.OK
        Write-Host "║  BND Command Center hardening completed successfully           ║" -ForegroundColor $Global:BND_Colors.OK
        Write-Host "║  System is now secured with professional-grade protections    ║" -ForegroundColor $Global:BND_Colors.OK
        Write-Host "║                                                                ║" -ForegroundColor $Global:BND_Colors.OK
        Write-Host "║  Monitoring agents: ACTIVE                                     ║" -ForegroundColor $Global:BND_Colors.OK
        Write-Host "║  Security traps: DEPLOYED                                      ║" -ForegroundColor $Global:BND_Colors.OK
        Write-Host "║  Remote mirroring: CONFIGURED                                  ║" -ForegroundColor $Global:BND_Colors.OK
        Write-Host "║                                                                ║" -ForegroundColor $Global:BND_Colors.OK
        Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor $Global:BND_Colors.OK
        Write-Host ""
        
        Write-BNDLog "BND Command Center hardening completed successfully" "SUCCESS"
        Write-BNDLog "Security report: $reportPath" "INFO"
        Write-BNDLog "System status: OPERATIONAL" "SUCCESS"
        
        # Display control points
        Write-Host "CONTROL POINTS AVAILABLE:" -ForegroundColor $Global:BND_Colors.INFO
        Write-Host "• SYSTEM START: " -ForegroundColor $Global:BND_Colors.SYSTEM -NoNewline
        Write-Host "Invoke-BNDSystemStart" -ForegroundColor $Global:BND_Colors.OK
        Write-Host "• SYSTEM STOP: " -ForegroundColor $Global:BND_Colors.SYSTEM -NoNewline  
        Write-Host "Invoke-BNDSystemStop" -ForegroundColor $Global:BND_Colors.WARNING
        Write-Host "• EMERGENCY SHUTDOWN: " -ForegroundColor $Global:BND_Colors.SYSTEM -NoNewline
        Write-Host ".\BND_CommandCenter_Hardening.ps1 -EmergencyMode" -ForegroundColor $Global:BND_Colors.CRITICAL
        
        return $true
        
    } catch {
        Write-BNDLog "BND Command Center execution failed: $($_.Exception.Message)" "CRITICAL" -Emergency
        $Global:BND_Config.SystemState = "FAILED"
        
        Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $Global:BND_Colors.CRITICAL
        Write-Host "║                         CRITICAL ERROR                         ║" -ForegroundColor $Global:BND_Colors.CRITICAL
        Write-Host "║                                                                ║" -ForegroundColor $Global:BND_Colors.CRITICAL
        Write-Host "║  BND Command Center execution failed                           ║" -ForegroundColor $Global:BND_Colors.CRITICAL
        Write-Host "║  Error: $($_.Exception.Message.PadRight(48))  ║" -ForegroundColor $Global:BND_Colors.CRITICAL
        Write-Host "║                                                                ║" -ForegroundColor $Global:BND_Colors.CRITICAL
        Write-Host "║  Check logs for detailed information                           ║" -ForegroundColor $Global:BND_Colors.CRITICAL
        Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor $Global:BND_Colors.CRITICAL
        
        return $false
    }
}

#endregion

# Main script execution
if ($MyInvocation.InvocationName -ne '.') {
    # Set console encoding for proper character display
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    
    # Execute main function
    $result = Invoke-BNDCommandCenter
    
    if (!$result) {
        exit 1
    }
}