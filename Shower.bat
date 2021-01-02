cd %CD%/Scripts
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File unlock.ps1" /StartDirectory %CD% /RunAs 8 /Run
timeout 3
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File disableDefender.ps1" /StartDirectory %CD% /RunAs 8 /Run
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File disableTasksFeatures.ps1" /StartDirectory %CD% /RunAs 8 /Run
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File randomFeatures.ps1" /StartDirectory %CD% /RunAs 8 /Run      
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File registryRemove.ps1" /StartDirectory %CD% /RunAs 8 /Run      
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File registrySet.ps1" /StartDirectory %CD% /RunAs 8 /Run
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File registrySetPrivacy.ps1" /StartDirectory %CD% /RunAs 8 /Run
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File settings.ps1" /StartDirectory %CD% /RunAs 8 /Run  
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File removeApps.ps1" /StartDirectory %CD% /RunAs 8 /Run
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File removeOnedriveDelta.ps1" /StartDirectory %CD% /RunAs 8 /Run 
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File telemetry.ps1" /StartDirectory %CD% /RunAs 8 /Run
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File uiOptimise.ps1" /StartDirectory %CD% /RunAs 8 /Run
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File uninstallOneDrive.ps1" /StartDirectory %CD% /RunAs 8 /Run   
AdvancedRun.exe /EXEFilename "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /CommandLine "-NoLogo -ExecutionPolicy Bypass -File update.ps1" /StartDirectory %CD% /RunAs 8 /Run

taskkill /F /IM SearchUI.exe
move "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy.bak"

