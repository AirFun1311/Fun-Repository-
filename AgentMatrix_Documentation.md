# AgentMatrix_Hardening.ps1 - Advanced Windows Security Hardening

## 🎯 Overview

**AgentMatrix_Hardening.ps1** is a comprehensive Windows security hardening script designed with pentesting protection in mind. The script implements advanced security measures while featuring Matrix-style visual effects and comprehensive reporting.

## 🚀 Features

### 🔒 Pentesting Hardening
- **Critical Service Blocking**: Disables vulnerable services (SMB, NetBIOS, WMI, WinRM, Remote Registry, RPC, Telnet, FTP, Print Spooler, etc.)
- **Network Protocol Hardening**: Blocks LLMNR, mDNS, SSDP, SNMP, and other discovery protocols
- **Privilege Escalation Protection**: Implements UAC hardening, disables PowerShell v2, Windows Script Host
- **Admin Share Elimination**: Disables administrative shares and guest accounts
- **RDP Security**: Enforces Network Level Authentication and SSL encryption
- **Firewall Matrix**: Comprehensive inbound/outbound port blocking for both TCP and UDP

### 🛡️ Windows Defender Enhancement
- **Advanced Cloud Protection**: Enables Microsoft MAPS reporting and sample submission
- **PUA Protection**: Blocks potentially unwanted applications
- **Network Protection**: Prevents network-based attacks
- **Real-time Monitoring**: Ensures continuous protection
- **Signature Updates**: Automatically updates threat definitions

### 🕵️ Threat Detection
- **Autostart Monitoring**: Scans for suspicious startup entries
- **Pattern Recognition**: Detects common attack patterns in autostart locations
- **Risk Assessment**: Identifies potentially malicious entries

### 🎬 Matrix-Style Experience
- **ASCII Art Animations**: Matrix-inspired visual effects during execution
- **Agent Messages**: Themed progress messages throughout execution
- **Dynamic Progress Bars**: Visual feedback with Matrix-style characters
- **Digital Certification Badge**: ASCII art completion certificate

### 📊 Comprehensive Reporting
- **HTML Reports**: Professional security assessment reports
- **UTF-8 Support**: Proper character encoding for all outputs
- **Detailed Logs**: Complete audit trail of all actions
- **Service Inventory**: Lists all disabled services and their risks
- **Firewall Rules**: Documents all firewall changes
- **Registry Modifications**: Tracks all security-related registry changes

## 📋 Requirements

- **Operating System**: Windows 10/11, Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator rights required
- **Execution Policy**: Must allow script execution

## 🔧 Installation

1. Download the script to a local directory
2. Open PowerShell as Administrator
3. Navigate to the script directory
4. Run the script with desired parameters

## 🎮 Usage

### Basic Execution
```powershell
.\AgentMatrix_Hardening.ps1
```

### Unattended Mode
```powershell
.\AgentMatrix_Hardening.ps1 -Unattended
```

### Fast Mode (No Animations)
```powershell
.\AgentMatrix_Hardening.ps1 -NoAnimation
```

### Custom Log Path
```powershell
.\AgentMatrix_Hardening.ps1 -LogPath "D:\SecurityLogs"
```

### Combined Parameters
```powershell
.\AgentMatrix_Hardening.ps1 -Unattended -NoAnimation -LogPath "C:\CustomLogs"
```

## 📝 Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `-Unattended` | Switch | Runs without user interaction | False |
| `-NoAnimation` | Switch | Disables Matrix-style animations | False |
| `-LogPath` | String | Custom directory for log files | C:\AgentMatrix_Logs |

## 🛠️ Security Measures Implemented

### Services Disabled/Blocked
- **Server (SMB)** - File sharing exploitation prevention
- **Computer Browser** - Network enumeration protection
- **Windows Remote Management** - Remote command execution blocking
- **Remote Registry** - Registry manipulation prevention
- **RPC Endpoint Mapper** - Remote code execution protection
- **Telnet** - Unencrypted access prevention
- **FTP Server** - File transfer exploitation blocking
- **SNMP Service** - Network reconnaissance prevention
- **Print Spooler** - PrintNightmare vulnerability mitigation
- **Windows Search** - Information disclosure prevention
- **TCP/IP NetBIOS Helper** - NetBIOS attack prevention
- **UPnP Device Host** - Network exposure reduction
- **SSDP Discovery** - Network discovery prevention
- **Xbox Services** - Gaming service exposure elimination

### Network Ports Blocked
| Port | Protocol | Service | Risk |
|------|----------|---------|------|
| 135 | TCP | RPC Endpoint Mapper | Remote code execution |
| 139 | TCP | NetBIOS Session | Network scanning |
| 445 | TCP | SMB | File sharing attacks |
| 593 | TCP | RPC over HTTP | Remote exploitation |
| 3389 | TCP | RDP | Unauthorized remote access |
| 5985/5986 | TCP | WinRM | Remote management |
| 21 | TCP | FTP | File transfer attacks |
| 23 | TCP | Telnet | Unencrypted access |
| 69 | UDP | TFTP | Trivial file transfer |
| 161/162 | UDP | SNMP | Network reconnaissance |
| 1900 | UDP | SSDP | Service discovery |
| 5353 | UDP | mDNS | Multicast DNS |
| 137/138 | UDP | NetBIOS | Network enumeration |

### Registry Hardening
- **LLMNR Disabled**: Prevents link-local multicast name resolution attacks
- **NetBIOS Disabled**: Blocks NetBIOS over TCP/IP vulnerabilities
- **WPAD Disabled**: Prevents Web Proxy Auto-Discovery attacks
- **UAC Enforcement**: Maximum UAC protection settings
- **PowerShell v2 Disabled**: Removes legacy PowerShell vulnerabilities
- **Windows Script Host Disabled**: Prevents script-based attacks
- **RDP Security**: Enforces Network Level Authentication and encryption

## 📊 Output Files

### Log File
- **Location**: `[LogPath]\AgentMatrix_Log_YYYYMMDD_HHMMSS.txt`
- **Content**: Detailed execution log with timestamps
- **Format**: UTF-8 encoded text file

### HTML Report
- **Location**: `[LogPath]\AgentMatrix_Report_YYYYMMDD_HHMMSS.html`
- **Content**: Comprehensive security assessment report
- **Features**: 
  - System information summary
  - Service modification details
  - Firewall rule documentation
  - Registry change tracking
  - Suspicious autostart entry detection
  - Digital certification badge
  - Security recommendations

## ⚠️ Important Notes

### Pre-Execution Considerations
- **Backup**: Create system restore point before execution
- **Testing**: Test in non-production environment first
- **Network Impact**: Some network services will be disabled
- **Application Compatibility**: Some applications may require re-configuration

### Post-Execution
- **Reboot Required**: System restart recommended for all changes to take effect
- **Service Dependencies**: Some applications may need service re-enablement
- **Firewall Rules**: Review and adjust firewall rules if needed
- **Monitoring**: Regularly monitor logs for security events

## 🔍 Troubleshooting

### Common Issues
1. **Script Execution Policy**: Run `Set-ExecutionPolicy RemoteSigned` as Administrator
2. **Insufficient Privileges**: Ensure PowerShell is running as Administrator
3. **Service Dependencies**: Some applications may fail if dependent services are disabled
4. **Network Connectivity**: Certain network functions may be impacted

### Recovery
- **Service Recovery**: Use `services.msc` to manually re-enable required services
- **Firewall Recovery**: Use Windows Firewall console to modify rules
- **Registry Recovery**: Use system restore or manual registry editing

## 🤝 Support

### Best Practices
- Run on test systems first
- Document any custom requirements
- Monitor system behavior post-hardening
- Keep logs for audit purposes

### Compatibility
- Tested on Windows 10 (1903+)
- Tested on Windows 11
- Compatible with Windows Server 2016+
- Requires PowerShell 5.1+

## 🎯 Security Impact

This script significantly hardens Windows systems against common penetration testing techniques including:
- **Network Enumeration**: Blocks discovery protocols
- **Lateral Movement**: Disables remote management services
- **Privilege Escalation**: Implements UAC and script execution controls
- **Persistence Mechanisms**: Monitors and detects suspicious autostart entries
- **Remote Exploitation**: Blocks vulnerable network services

The Matrix-themed interface provides an engaging user experience while implementing enterprise-grade security measures.

---

**"Welcome to the real world, Neo. Your system is now protected."** 🕶️