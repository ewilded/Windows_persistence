
# App init process injection registry keys:

## App init DLLS:
 - HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
 - HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
 
 Description: DLLs specified by this value are loaded in all applications with User32.dll linked (very few do not).
 Interestingly, it seems there is another registry value that defines the registry HKLM\Software subbranch whereas App init DLLs should be searched for:
 Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\win.ini\Windows\APPINIT_DLLS
 the default value (Win10 x64): SYS:MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINDOWS
 
 Also, there is a Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs key (default value 0x0), suggesting a switch for this feature.
 
 External resources: https://support.microsoft.com/en-us/help/197571/working-with-the-appinit-dlls-registry-value
 Remark: What about HKCU?
 
## App cert DLLs
 - HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls
 
 Description: DLLs specified by this value are loaded into any application that makes use of the following API functions: CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, WinExec
 
 External resources: https://attack.mitre.org/techniques/T1182/
 

# Image file execution options
  - HKLM\Software\Microsoft\Windows NT\currentversion\image file execution options
 
 Description:
 Contains subkeys corresponding to individual executable names, with custom execution options. 
 If "Debugger" option is defined, it points to the binary that is called by the OS instead of the target executable, passing the path to the original executable (along with its command line parameters) as command line parameters (this feature is intended for defining application-custom debugger). Hence, it is a great persistence method.
 
 External resources: 
 https://blogs.msdn.microsoft.com/junfeng/2004/04/28/image-file-execution-options/
 https://support.microsoft.com/en-us/help/238788/how-to-debug-common-gateway-interface-applications-running-under-iis-b
 
 
# Winlogon packages

 reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
/t REG_SZ /d "C:\Some\Evil\Binary.exe","C:\Windows\system32\userinit.exe"

[HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
Userinit    REG_SZ    C:\Windows\system32\userinit.exe

 External resources:
 https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/registry-entries
 
 
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Userinit /t REG_SZ /d "c:\users\nina\appdata\local\temp\low\nina.exe","C:\Windows\system32\userinit.exe"


[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce]
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices]
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce]

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce]
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices]
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce]


HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

Other, more exotic:
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages
HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
HKLM\SOFTWARE\Classes\Htmlfile\Shell\Open\Command\(Default)
HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks


 - BAM
BAM is a Windows service that Controls activity of background applications. This service exists in Windows 10 only after Fall Creators update – version 1709 (contains a list of executables run):
HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}

- RecentApps
Windows 10:
HKCU\Software\Microsoft\Windows\Current Version\Search\RecentApps

- ShimCache:
Last 1024 apps
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache

- Image Execution Options
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v "Debugger" /t REG_SZ /d "\"...\path\to\nppLauncher.bat"" /f




[Cortana]
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\Microsoft.Windows.Cortana_1.10.7.17134_neutral_neutral_cw5n1h2txyewy /d "C:\windows\system32\cmd.exe"
OR
reg add HKCU\Software\Classes\ActivatableClasses\Package\Microsoft.Windows.Cortana_1.10.7.17134_neutral_neutral_cw5n1h2txyewy\DebugInformation\CortanaUI.AppXy7vb4pc2dr3kc93kfc509b1d0arkfb2x.mca /v DebugPath /d "C:\windows\system32\cmd.exe"

[People app]
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\Microsoft.People_10.1807.2131.0_x64__8wekyb3d8bbwe /d "C:\windows\system32\cmd.exe"
OR
reg add HKCU\Software\Classes\ActivatableClasses\Package\Microsoft.People_10.1807.2131.0_x64__8wekyb3d8bbwe\DebugInformation\x4c7a3b7dy2188y46d4ya362y19ac5a5805e5x.AppX368sbpk1kx658x0p332evjk2v0y02kxp.mca /v DebugPath /d "C:\windows\system32\cmd.exe"




People app:

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\Microsoft.People_10.1807.2131.0_x64__8wekyb3d8bbwe /d "C:\windows\system32\cmd.exe"
OR
reg add HKCU\Software\Classes\ActivatableClasses\Package\Microsoft.People_10.1807.2131.0_x64__8wekyb3d8bbwe\DebugInformation\x4c7a3b7dy2188y46d4ya362y19ac5a5805e5x.AppX368sbpk1kx658x0p332evjk2v0y02kxp.mca /v DebugPath /d "C:\windows\system32\cmd.exe"





