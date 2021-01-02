if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

Import-Module -DisableNameChecking $PSScriptRoot\take-own.psm1
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

If (Test-Path "$env:USERPROFILE\OneDrive\*") {
          
    If (Test-Path "$env:USERPROFILE\Desktop\OneDriveBackupFiles") {
    }
    else {
        If (!(Test-Path "$env:USERPROFILE\Desktop\OneDriveBackupFiles")) {
            New-item -Path "$env:USERPROFILE\Desktop" -Name "OneDriveBackupFiles"-ItemType Directory -Force
        }
    }
    Move-Item -Path "$env:USERPROFILE\OneDrive\*" -Destination "$env:USERPROFILE\Desktop\OneDriveBackupFiles" -Force
}
Else {
    $OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
    If (!(Test-Path $OneDriveKey)) {
        Mkdir $OneDriveKey
        Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
    }
    Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
}



New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
$ExplorerReg1 = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
$ExplorerReg2 = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Stop-Process -Name "OneDrive*"
If (!(Test-Path $onedrive)) {
    $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"

    New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    $ExplorerReg1 = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    $ExplorerReg2 = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    Stop-Process -Name "OneDrive*"
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
    Write-Output "Stopping explorer"
    taskkill.exe /F /IM explorer.exe
    Write-Output "Removing leftover files"

    Write-Output "Removing OneDrive from windows explorer"
    If (!(Test-Path $ExplorerReg1)) {
        New-Item $ExplorerReg1
    }
    Set-ItemProperty $ExplorerReg1 System.IsPinnedToNameSpaceTree -Value 0 
    If (!(Test-Path $ExplorerReg2)) {
        New-Item $ExplorerReg2
    }
    Set-ItemProperty $ExplorerReg2 System.IsPinnedToNameSpaceTree -Value 0
    Write-Output "Restarting Explorer that was shut down before."
    Start-Process explorer.exe -NoNewWindow

    $OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
    If (!(Test-Path $OneDriveKey)) {
        Mkdir $OneDriveKey 
    }
    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
    taskkill.exe /F /IM explorer.exe
    If (Test-Path "$env:USERPROFILE\OneDrive") {
        Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse
    }
    If (Test-Path "$env:LOCALAPPDATA\Microsoft\OneDrive") {
        Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
    }
    If (Test-Path "$env:PROGRAMDATA\Microsoft OneDrive") {
        Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
    }
    If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
        Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse
    }
    If (!(Test-Path $ExplorerReg1)) {
        New-Item $ExplorerReg1
    }
    Set-ItemProperty $ExplorerReg1 System.IsPinnedToNameSpaceTree -Value 0 
    If (!(Test-Path $ExplorerReg2)) {
        New-Item $ExplorerReg2
    }
    Set-ItemProperty $ExplorerReg2 System.IsPinnedToNameSpaceTree -Value 0

    
    Remove-item env:OneDrive
}