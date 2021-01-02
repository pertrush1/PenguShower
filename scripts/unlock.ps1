if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

Import-Module -DisableNameChecking $PSScriptRoot\take-own.psm1
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)
ls -Recurse *.ps*1 | Unblock-File -ErrorAction SilentlyContinue
Set-ExecutionPolicy Unrestricted -Scope CurrentUser

Set-ExecutionPolicy Unrestricted -Force
Set-ExecutionPolicy Unrestricted -s cu -f
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0