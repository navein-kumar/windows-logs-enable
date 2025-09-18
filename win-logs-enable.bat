@echo off

echo ========================================
echo Complete Enterprise SOC Logging Setup
echo (Sysmon + Wazuh + Windows Logs)
echo ========================================

REM Check admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as administrator!
    echo Please right-click and select "Run as administrator"
    pause & exit /b 1
)

echo.
echo [1] PowerShell Logging (CRITICAL)...
echo ------------------------------------
echo [1] PowerShell Logging (CRITICAL)...
echo ------------------------------------
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f >nul 2>&1
if not exist "C:\Windows\Logs\PowerShell" mkdir "C:\Windows\Logs\PowerShell" >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\Windows\Logs\PowerShell" /f >nul 2>&1
if %errorLevel% equ 0 (
    echo ✓ PowerShell logging configured successfully
) else (
    echo ⚠ PowerShell logging partially configured
)
echo   Events: 4103, 4104 + Transcripts

echo.
echo [2] Authentication & Privilege Monitoring...
echo --------------------------------------------
auditpol /set /category:"Account Logon" /success:enable /failure:enable >nul 2>&1
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable >nul 2>&1
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable >nul 2>&1
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable >nul 2>&1
auditpol /set /category:"Account Management" /success:enable /failure:enable >nul 2>&1
echo ✓ Authentication logging configured successfully
echo   Events: 4624, 4625, 4768, 4769

echo.
echo [3] Network Share Access Monitoring...
echo --------------------------------------
auditpol /set /subcategory:"File Share" /success:enable /failure:enable >nul 2>&1
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable >nul 2>&1
auditpol /set /subcategory:"File System" /success:enable /failure:enable >nul 2>&1
echo ✓ Network share logging configured successfully
echo   Events: 5140, 5145, 5168

echo.
echo [4] WMI Activity Monitoring...
echo ------------------------------
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable >nul
wevtutil sl "Microsoft-Windows-WMI-Activity/Operational" /e:true >nul
echo ✓ WMI logging enabled (Events: 5857-5861)

echo.
echo [5] Scheduled Task Monitoring...
echo --------------------------------
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true >nul
echo ✓ Task logging enabled (Events: 4698-4702)

echo.
echo [6] Service Installation Monitoring...
echo --------------------------------------
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable >nul
echo ✓ Service logging enabled (Event: 4697)

echo.
echo [7] RDP/Remote Access Monitoring...
echo -----------------------------------
wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /e:true >nul
wevtutil sl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" /e:true >nul
echo ✓ RDP logging enabled (Events: 21, 25, 1149)

echo.
echo [8] Windows Defender Integration...
echo -----------------------------------
wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /e:true >nul
wevtutil sl "Microsoft-Windows-Windows Defender/WHC" /e:true >nul
echo ✓ Antivirus logging enabled (Events: 1116, 1117, 1118)

echo.
echo [9] Firewall Activity Monitoring...
echo -----------------------------------
wevtutil sl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" /e:true >nul
netsh advfirewall set allprofiles logging droppedconnections enable >nul 2>&1
netsh advfirewall set allprofiles logging allowedconnections enable >nul 2>&1
netsh advfirewall set allprofiles logging filename %%systemroot%%\system32\LogFiles\Firewall\pfirewall.log >nul 2>&1
echo ✓ Firewall logging enabled (Events + Text logs)

echo.
echo [10] DNS Query Monitoring...
echo ----------------------------
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true >nul
echo ✓ DNS logging enabled (Events: 3008, 3020)

echo.
echo [11] USB/Device Control...
echo --------------------------
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable >nul
wevtutil sl "Microsoft-Windows-Kernel-PnP/Configuration" /e:true >nul
echo ✓ USB logging enabled (Events: 20001, 20003)

echo.
echo [12] System Events...
echo --------------------
auditpol /set /category:"System" /success:enable /failure:enable >nul
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable >nul
echo ✓ System logging enabled (Events: 1074, 6005, 6006)

echo.
echo [13] Registry Persistence Monitoring...
echo ---------------------------------------
auditpol /set /subcategory:"Registry" /success:enable /failure:enable >nul
icacls "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /audit Everyone:(OI)(CI)(F) >nul 2>&1
icacls "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /audit Everyone:(OI)(CI)(F) >nul 2>&1
echo ✓ Registry logging enabled (Event: 4657)

echo.
echo [14] AppLocker (if available)...
echo --------------------------------
wevtutil sl "Microsoft-Windows-AppLocker/EXE and DLL" /e:true >nul 2>&1
wevtutil sl "Microsoft-Windows-AppLocker/MSI and Script" /e:true >nul 2>&1
echo ✓ AppLocker logging enabled (Events: 8003, 8004)

echo.
echo [15] Process Command Line Auditing...
echo -------------------------------------
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f >nul
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable >nul
echo ✓ Command line auditing enabled (Event: 4688)

echo.
echo [16] Additional Network Monitoring...
echo -------------------------------------
wevtutil sl "Microsoft-Windows-DHCP-Client/Operational" /e:true >nul 2>&1
wevtutil sl "Microsoft-Windows-WLAN-AutoConfig/Operational" /e:true >nul 2>&1
echo ✓ Network services logging enabled

echo.
echo [17] Print Spooler Security...
echo -----------------------------
wevtutil sl "Microsoft-Windows-PrintService/Operational" /e:true >nul 2>&1
echo ✓ Print service logging enabled

echo.
echo [18] Directory Services & Domain Controller...
echo ----------------------------------------------
auditpol /set /category:"Directory Service Access" /success:enable /failure:enable >nul 2>&1
auditpol /set /category:"Directory Service Changes" /success:enable /failure:enable >nul 2>&1
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable >nul 2>&1
echo ✓ Active Directory logging enabled (Events: 4662, 5136, 4780)

echo.
echo [19] Certificate & PKI Services...
echo ----------------------------------
wevtutil sl "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" /e:true >nul 2>&1
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable >nul 2>&1
echo ✓ PKI/Certificate logging enabled (Events: 4876, 4887, 4888)

echo.
echo [20] Group Policy Monitoring...
echo -------------------------------
wevtutil sl "Microsoft-Windows-GroupPolicy/Operational" /e:true >nul 2>&1
echo ✓ Group Policy logging enabled

echo.
echo [21] Enhanced Event Log Sizes for Enterprise SOC...
echo --------------------------------------------------
echo [INFO] Setting optimal log sizes for SOC operations...
wevtutil sl Security /ms:524288000 >nul 2>&1
wevtutil sl System /ms:104857600 >nul 2>&1
wevtutil sl Application /ms:104857600 >nul 2>&1
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824 >nul 2>&1
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:209715200 >nul 2>&1
wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /ms:209715200 >nul 2>&1
wevtutil sl "Microsoft-Windows-WMI-Activity/Operational" /ms:52428800 >nul 2>&1
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /ms:52428800 >nul 2>&1
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /ms:52428800 >nul 2>&1
wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /ms:52428800 >nul 2>&1
wevtutil sl "Microsoft-Windows-GroupPolicy/Operational" /ms:52428800 >nul 2>&1
wevtutil sl "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" /ms:52428800 >nul 2>&1
echo ✓ Enterprise log sizes optimized

echo.
echo ===============================================
echo COMPLETE ENTERPRISE SOC CONFIGURATION FINISHED!
echo ===============================================
echo.
echo ENABLED LOG SOURCES (21 Categories):
echo ====================================
echo.
echo 🔥 THREAT HUNTING CORE:
echo   ✓ PowerShell Scripts (4103, 4104)
echo   ✓ Authentication (4624, 4625, 4768, 4769)
echo   ✓ Network Shares (5140, 5145, 5168)
echo   ✓ WMI Activity (5857-5861)
echo   ✓ Scheduled Tasks (4698-4702)
echo   ✓ Service Installs (4697)
echo.
echo 🌐 NETWORK & ACCESS:
echo   ✓ RDP Connections (21, 25, 1149)
echo   ✓ Firewall Events + Text Logs
echo   ✓ DNS Queries (3008, 3020)
echo   ✓ DHCP/WiFi Events
echo.
echo 🛡️ SECURITY PRODUCTS:
echo   ✓ Windows Defender (1116-1118)
echo   ✓ AppLocker Blocks (8003, 8004)
echo.
echo 💻 SYSTEM & DEVICE:
echo   ✓ Process Creation (4688)
echo   ✓ USB Devices (20001, 20003)
echo   ✓ System Events (1074, 6005, 6006)
echo   ✓ Registry Changes (4657)
echo   ✓ Active Directory (4662, 5136)
echo   ✓ Certificates/PKI (4876, 4887)
echo   ✓ Group Policy Changes
echo   ✓ Print Services
echo.
echo 📊 OPTIMIZED FOR ENTERPRISE SOC:
echo   • Security Log: 500MB (7-30 days retention)
echo   • Sysmon Log: 1GB (process/network monitoring)  
echo   • PowerShell Log: 200MB (15-60 days retention)
echo   • Windows Defender: 200MB (15-60 days retention)
echo   • System/Application: 100MB each
echo   • Other Logs: 50MB each
echo.
echo 🎯 KEY EVENTS TO MONITOR:
echo ========================
echo CRITICAL: 4104, 4624/4625, 5140, 5857, 4698, 4697, 4662
echo HIGH: 1149, 1116, 4688, 20001, 3008, 5136, 4876
echo MEDIUM: 4657, 8003, 1074, 6005, 4887
echo.
echo NEXT STEPS:
echo ==========
echo 1. Restart Wazuh agent: net stop wazuh ^& net start wazuh
echo 2. Verify log collection in Wazuh dashboard
echo 3. Configure Wazuh rules for your environment
echo 4. Set up SIEM alerting and dashboards
echo 5. Test incident response procedures
echo.
echo NOTE: System restart recommended for all changes
echo.

pause
