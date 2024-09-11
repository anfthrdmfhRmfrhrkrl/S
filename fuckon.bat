@echo off

:: Re-enable and start services
sc config Browser start= auto
sc start Browser
sc config Dhcp start= auto
sc start Dhcp
sc config Dnscache start= auto
sc start Dnscache
sc config Eventlog start= auto
sc start Eventlog
sc config Schedule start= auto
sc start Schedule
sc config AudioEndpointBuilder start= auto
sc start AudioEndpointBuilder
sc config Audiosrv start= auto
sc start Audiosrv
sc config msiserver start= auto
sc start msiserver
sc config winmgmt start= auto
sc start winmgmt
sc config wuauserv start= auto
sc start wuauserv
sc config RemoteRegistry start= auto
sc start RemoteRegistry
sc config BITS start= auto
sc start BITS
sc config ShellHWDetection start= auto
sc start ShellHWDetection
sc config sppsvc start= auto
sc start sppsvc
sc config TrustedInstaller start= auto
sc start TrustedInstaller
sc config wbengine start= auto
sc start wbengine
sc config wscsvc start= auto
sc start wscsvc
sc config WinDefend start= auto
sc start WinDefend
sc config wudfsvc start= auto
sc start wudfsvc
sc config MpsSvc start= auto
sc start MpsSvc
sc config TabletInputService start= auto
sc start TabletInputService
sc config SysMain start= auto
sc start SysMain
sc config DiagTrack start= auto
sc start DiagTrack
sc config EventLog start= auto
sc start EventLog
sc config WSearch start= auto
sc start WSearch
sc config w32time start= auto
sc start w32time
sc config stisvc start= auto
sc start stisvc
sc config VSS start= auto
sc start VSS
sc config AxInstSV start= auto
sc start AxInstSV
sc config AarSvc_5b8f3 start= auto
sc start AarSvc_5b8f3
sc config AJRouter start= auto
sc start AJRouter
sc config AppReadiness start= auto
sc start AppReadiness
sc config AppIDSvc start= auto
sc start AppIDSvc
sc config Appinfo start= auto
sc start Appinfo
sc config ALG start= auto
sc start ALG
sc config AppMgmt start= auto
sc start AppMgmt
sc config AppXSvc start= auto
sc start AppXSvc
sc config MpsSvc start= auto
sc start MpsSvc
sc config wscsvc start= auto
sc start wscsvc
sc config WinRM start= auto
sc start WinRM
sc config SharedAccess start= auto
sc start SharedAccess
sc config icssvc start= auto
sc start icssvc

:: Re-enable Recovery Environment
reagentc /enable
reagentc /setreimage /path c:\recovery\windowsre /target c:\windows

:: Restore power settings
powercfg -CHANGE -monitor-timeout-ac 10
powercfg -CHANGE -standby-timeout-ac 15
powercfg -CHANGE -hibernate-timeout-ac 30
powercfg -CHANGE -monitor-timeout-dc 10
powercfg -CHANGE -standby-timeout-dc 15
powercfg -CHANGE -hibernate-timeout-dc 30
powercfg -CHANGE -disk-timeout-ac 20
powercfg -CHANGE -disk-timeout-dc 20

:: Restore registry settings
reg delete "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoProblemReports /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\KeysNotToRestore" /v "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems\Windows" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\KeysNotToRestore" /v "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryEnvironment" /v "CommandPromptFontColor" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartScheduledMaintenance" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartWithLoggedOnUsers" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutoRebootOnCrash" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "EnablePeriodicBackup" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "DisableSR" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /f
bcdedit /set {default} recoveryenabled yes
bcdedit /set {default} bootstatuspolicy default
bcdedit /set {default} custom:30000006 false
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" /v "SetCommand" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvancedInstallersNeedResolving" /v "ATFInstallInProgress" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\recdisc.exe" /v "Debugger" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\recimg.exe" /v "Debugger" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\winreboot.exe" /v "Debugger" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bootsect.exe" /v "Debugger" /f

:: Uninstall unwanted software
wmic product where "Name like 'Antivirus%'" call install
wmic product where "Name like 'Security%'" call install

:: Check if system restore is enabled
wmic /namespace:\\root\default Path SystemRestore call Enable

reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v DisplayParameters /t REG_DWORD /d 0x00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v LogEvent /t REG_DWORD /d 0x00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v SendAlert /t REG_DWORD /d 0x00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AutoReboot /t REG_DWORD /d 0x00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0x00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\AutoReboot" /v Enabled /t REG_DWORD /d 0x00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\AutoReboot\RebootCount" /v 1 /t REG_DWORD /d 0x00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpOptions" /v DumpFile /t REG_EXPAND_SZ /d "%%SystemRoot%%\MEMORY.DMP" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpOptions" /v Overwrite /t REG_DWORD /d 0x00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpOptions" /v LogEvent /t REG_DWORD /d 0x00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpOptions" /v SendAlert /t REG_DWORD /d 0x00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpOptions" /v NumberOfCrashes /t REG_DWORD /d 0x00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpOptions" /v AutoReboot /t REG_DWORD /d 0x00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpOptions" /v DumpType /t REG_DWORD /d 0x00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpOptions" /v MinidumpDir /t REG_EXPAND_SZ /d "%%SystemRoot%%\Minidump" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpOptions" /v ProcessorRegisters /t REG_DWORD /d 0x00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpOptions" /v AllPagesOnMemory /t REG_DWORD /d 0x00000001 /f

:: HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System 값 복구
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCMD /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 0 /f

:: HKCU\Control Panel\Desktop 값 복구
reg add "HKCU\Control Panel\Desktop" /v PaintDesktopVersion /t REG_SZ /d "1" /f

:: HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushButton\Advanced 값 복구
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushButton\Advanced" /v NoAdvancedTab /t REG_DWORD /d 0 /f

:: 서비스 시작
sc config "Mouclass" start= demand
sc start "Mouclass"

:: 기타 레지스트리 값 복구
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideIcons /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Firewall\Policy" /v "DisableInboundIpSec" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Firewall\Policy" /v "DisableOutboundIpSec" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Firewall\Policy" /v "DisableInboundSecurityMonitoring" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Firewall\Policy" /v "DisableOutboundSecurityMonitoring" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Firewall\Policy" /v "DisableNotifications" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDesktop" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "TaskbarNoTrayContextMenu" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWinKeys" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoControlPanel" /t REG_DWORD /d 0 /f

:: 기본 레지스트리 값 복구
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe" /v "Debugger" /t REG_SZ /d "" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v Nocurrentdisplaytoast /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background" /v "OEMBackground" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background" /v "PicturePath" /t REG_SZ /d "" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v "DisableRenegoOnServer" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnOnPost" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\UIPI" /v "EnableUIPI" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /v "debugger" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Firewall\Policy" /v "DisableInboundIpSec" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Firewall\Policy" /v "DisableOutboundIpSec" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Firewall\Policy" /v "DisableInboundSecurityMonitoring" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Firewall\Policy" /v "DisableOutboundSecurityMonitoring" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Firewall\Policy" /v "DisableNotifications" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDesktop" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "TaskbarNoTrayContextMenu" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWinKeys" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoControlPanel" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowRun" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarLockAll" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarNoDrag" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarNoResize" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoDispCPL" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoDispBackgroundPage" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoDispScrSavPage" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoDispSettingsPage" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoSecCPL" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\GuardedFolders" /v AllowFullScanOfMappedNetworkDrives /f
netsh advfirewall set allprofiles state on

:: Restore USB Storage settings
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR" /v "Start" /t REG_DWORD /d "3" /f

:: Restore Network Adapter
for /f "tokens=3 delims=: " %%a in ('netsh interface show interface ^| findstr /c:"이더넷"') do set adapterName=%%a
netsh interface set interface "%adapterName%" admin=enable

:: Restore UAC settings
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f

:: Restore Keyboard Layout
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layout" /v "Scancode Map" /f

:: Restore Group Policy Settings
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowDomainPINLogon /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v UseHelloForBusiness /t REG_DWORD /d 1 /f

:: Restore Windows Update
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DisableOSUpgrade /f

:: Restore DismHostSvc
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DismHostSvc" /v Start /t REG_DWORD /d 2 /f

:: Restore SafeBoot settings
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MSConfig" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\MSConfig" /f

:: Restore Start Menu and Control Panel settings
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoStartMenu" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoConnectedUser /t REG_DWORD /d 1 /f

:: Restore Auto Logon settings
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f

:: Restore Device Guard settings
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f

:: Restore Mouse settings
reg delete "HKCU\Control Panel\Mouse" /v "MouseTrails" /f
reg delete "HKCU\Control Panel\Mouse" /v "MouseSpeed" /f
reg delete "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /f
reg delete "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /f
reg delete "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /f
reg delete "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /f
reg delete "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /f
:: Restore ProfileList
reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\%Username% /f

:: Restore PowerShell ISE Description
reg delete HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShellISE /v Description /f

:: Restore Run Policy
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRun" /f

:: Restore Search Box Taskbar Mode
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /f

:: Restore Hide ShutDown button
reg delete "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Start\HideShutDown" /v value /f

:: Restore Control Panel and Display settings
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoPropertiesMyComputer /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispAppearancePage /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispBackgroundPage /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispCPL /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispScrSavPage /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispSettingsPage /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoSecCPL /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoAdminPage /f

:: Restore AppCompat Flags
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "C:\Program Files\*" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "C:\Program Files (x86)\*" /f

:: Restore Boot Driver Flags
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "BootDriverFlags" /f

:: Restore sfc.exe Debugger
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sfc.exe" /v Debugger /f

:: Restore Windows Defender settings
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableBehaviorMonitoring /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableBlockAtFirstSeen /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableIOAVProtection /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRealtimeMonitoring /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableScanOnRealtimeEnable /f

:: Restore Immersive Color settings
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\ImmersiveColor\Scrnsave.exe" /v "UseWallpaperBlur" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\ImmersiveColor\Scrnsave.exe" /v "AccentColorMenu" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\ImmersiveColor\Scrnsave.exe" /v "ColorPrevalence" /f

:: Restore System Restore settings
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f

:: Restore MiniNT settings
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MiniNT" /v "NoLKG" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MiniNT" /v "NoRebootPrompt" /f

:: Restore LogonUI settings
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v ButtonSet /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v dontdisplaylastusername /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v DontDisplayLockedUserId /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v LogonType /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v UserSwitchEnabled /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v ScheduledToastNotifications /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v LastLoggedOnUser /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v LastLoggedOnSAMUser /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v LastLoggedOnDisplayName /f

:: Restore BIOS Change settings
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceManagement" /v "AllowBIOSChange" /f

:: Restore Interactive Services
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Windows" /v "NoInteractiveServices" /f

:: Restore PCI and USB Services
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pci" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pciide" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcmcia" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbccgp" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbehci" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbohci" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbuhci" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbhub" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbprint" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbstor" /v "Start" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PlugPlay" /v "Start" /t REG_DWORD /d 3 /f

:: Restore Windows Error Reporting
reg delete "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /f
:: Restore Device Manager settings
devcon.exe enable *PNP0C02

:: Restore Memory Configuration Data
reg delete "HKLM\HARDWARE\DESCRIPTION\System\Memory" /v "Configuration Data" /f

:: Restore Driver Searching settings
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DriverUpdateWizardWuSearchEnabled" /f

:: Restore Device Install settings
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall" /v "DisableDeviceInstall" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceIDs" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceIDsRetroactive" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceClasses" /f

:: Restore PlugPlay service
set KEY="HKLM\SYSTEM\CurrentControlSet\Services\PlugPlay"
set VALUE=Start
set DATA=3
reg add %KEY% /v %VALUE% /t REG_DWORD /d %DATA% /f

:: Restore USB storage service
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsbStor" /v "Start" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR" /v "Start" /f

:: Restore StorageDevicePolicies settings
set key3="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
set value2="WriteProtect"
set data1="0"
reg add %key3% /v %value2% /t REG_DWORD /d %data1% /f

:: Restore SFC settings
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "SFCDisable" /f

:: Restore Windows Update settings
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "UseWUServer" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /f

:: Restore System Restore settings
wmic.exe /Namespace:\\root\default Path SystemRestore Call Enable

:: Restore Crash Control settings
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /v "DisableMemoryDumps" /f

:: Restore OneDrive settings
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /f

:: Restore Account settings
reg delete "HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\Settings\AllowYourAccount" /v "value" /f

:: Restore Registry Tools settings
reg delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /f

:: Restore Scaling settings
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Scaling" /v "Scaling" /t REG_DWORD /d 1 /f

:: Restore OPENCL_ENABLE_GPU environment variable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Environment" /v "OPENCL_ENABLE_GPU" /t REG_SZ /d "" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "OPENCL_ENABLE_GPU" /t REG_SZ /d "" /f

:: Restore BackupRestore settings
reg delete "HKEY_LOCAL_MACHINE\BackupRestore\FilesNotToBackup" /v "boot.sdi" /f

:: Restore Windows Installer settings
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "DisableBrowse" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "DisableMsi" /f

:: Restore SystemStartOptions settings
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemStartOptions" /v "NoRecoveryConsole" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemStartOptions" /v "BootSafe" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemStartOptions" /v "BootLogging" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemStartOptions" /v "SafeBootAlternateShell" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemStartOptions" /v "SafeBootMinimal" /f
:: Enable System Restore
wmic.exe /Namespace:\\root\default Path SystemRestore Call Enable

:: Verify that System Restore is enabled
wmic.exe /Namespace:\\root\default Path SystemRestore Call Enable true
:: Re-enable System Restore
wmic.exe /Namespace:\\root\default Path SystemRestore call Enable

:: Enable Windows Defender Real-time Monitoring and other features
wmic.exe /namespace:\\root\Microsoft\Windows\Defender Path MSFT_MpPreference set DisableRealtimeMonitoring=false
wmic.exe /namespace:\\root\Microsoft\Windows\Defender Path MSFT_MpPreference set DisableBehaviorMonitoring=false
wmic.exe /namespace:\\root\Microsoft\Windows\Defender Path MSFT_MpPreference set DisableOnAccessProtection=false
wmic.exe /namespace:\\root\Microsoft\Windows\Defender Path MSFT_MpPreference set DisableScanOnRealtimeEnable=false
wmic.exe /namespace:\\root\Microsoft\Windows\Defender Path MSFT_MpPreference set DisableScanOnScheduleDisable=false

:: Restore VSS settings
vssadmin.exe Resize ShadowStorage /For=C: /On=C: /MaxSize=5%

:: Restore Windows Update service
wmic path win32_service where "name='wuauserv'" call changeStartmode Automatic
sc start wuauserv

:: Restore automatic crash dumps
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "SendAlert" /t REG_DWORD /d "1" /f

:: Restore registry settings
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sfc.exe" /v "Debugger" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v DisableSR /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DisableAutomaticRebootOnCrash" /f

:: Restore registry settings for Explorer
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDevices" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPrinters" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoSound" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDispCPL" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAddPrinter" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoFileAssociate" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /f

:: Restore mouse and desktop settings
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "6" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "10" /f
reg add "HKCU\Control Panel\Mouse" /v "CursorBlinkRate" /t REG_SZ /d "530" /f
reg add "HKCU\Control Panel\Desktop" /v "CursorBlinkRate" /t REG_SZ /d "530" /f
reg add "HKCU\Control Panel\Desktop" /v "CursorShadow" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "CursorTrailWidth" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "MouseTrails" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9C,12,03,80" /f

:: Restore Windows Update settings
echo Windows Registry Editor Version 5.00 > %temp%\restore_update.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate] >> %temp%\restore_update.reg
echo "DisableOSUpgrade"=dword:00000000 >> %temp%\restore_update.reg
regedit /s %temp%\restore_update.reg
del /q %temp%\restore_update.reg

:: Restore USB storage settings
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies" /v "WriteCacheEnabled" /f

:: Restore PnP BIOS settings
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\SystemResources\PnP BIOS" /v Start /f
:: Enable Paging Executive
echo Windows Registry Editor Version 5.00 > %temp%\restore_paging_exec.reg
echo [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management] >> %temp%\restore_paging_exec.reg
echo "DisablePagingExecutive"=dword:00000000 >> %temp%\restore_paging_exec.reg
regedit /s %temp%\restore_paging_exec.reg
del /q %temp%\restore_paging_exec.reg

:: Uninstall specific hotfixes
:: Note: Replace 'KB' with the actual KB number(s) you want to uninstall.
wmic qfe where "HotfixID='KB' or HotfixID='anotherKB'" call uninstall /quiet /norestart

:: Re-enable antivirus and antispyware
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct where "displayName='AVG Free'" call enable
wmic /namespace:\\root\SecurityCenter2 path AntiSpywareProduct where "displayName='Windows Defender'" call enable

:: Re-enable network interface
netsh interface set interface Ethernet admin=enable

:: Allow Terminal Services connections
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d "0" /f

:: Restore shutdown reason and UI
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonOn" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonUI" /t REG_DWORD /d "1" /f

:: Restore PXE boot
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PXE" /v "SkipBoot" /f

:: Restore in-place sharing settings
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInplaceSharing" /f

:: Show Administrator account in logon screen
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v "Administrator" /f

:: Restore Safe Mode settings
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Network" /v "AlternateShell" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\Network" /v "Enabled" /f

:: Enable USB storage
reg delete HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR /v "Start" /f

:: Restore drive visibility
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDrives /t REG_DWORD /d 0 /f

:: Re-add and reassign partition letter (Note: Ensure correct partition handling)
set partition=
for /f "tokens=2 delims=: " %%a in ('echo list volume ^| diskpart ^| findstr "Windows"') do set partition=%%a
if defined partition (
    echo select volume %partition% > %temp%\diskpart_script.txt
    echo assign letter=C >> %temp%\diskpart_script.txt
    echo exit >> %temp%\diskpart_script.txt
    diskpart /s %temp%\diskpart_script.txt
    del %temp%\diskpart_script.txt
)

:: Unblock Advanced Options
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAdvancedOptions /f
reg delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAdvancedOptions /f

:: Restore System Restore settings
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\MiniNT" /v "UseSystemRestore" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t REG_DWORD /d 0 /f

:: Restore SystemStartOptions
REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control" /v "SystemStartOptions" /f

:: Allow automatic restart sign on
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /f

:: Restore Advanced Options in Registry
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAdvancedOptions" /f

:: Restore keyboard crash settings
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters" /v CrashOnCtrlScroll /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters" /v CrashOnCtrlScroll /f
:: Restore USB storage service
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsbStor" /v "Start" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR" /v "Start" /f

:: Restore Device Installation policies
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DriverUpdateWizardWuSearchEnabled" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall" /v "DisableDeviceInstall" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceIDs" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceIDsRetroactive" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceClasses" /f

:: Restore Plug and Play service
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PlugPlay" /v "Start" /f

:: Restore PCI service settings
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pci" /v "Start" /f

:: Restore WriteProtect setting (assuming default is 0)
set key="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
set value="WriteProtect"
set data="0"
reg add %key% /v %value% /t REG_DWORD /d %data% /f

echo System settings have been restored.
pause
