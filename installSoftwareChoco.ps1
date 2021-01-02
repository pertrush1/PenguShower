#   Description:
# This script will use Windows package manager to bootstrap Chocolatey and
# install a list of packages. Script will also install Sysinternals Utilities
# into your default drive's root directory.

$packages = @(
    "7zip.install"
    "audacity"
    "putty"
    "python"
    "qbittorrent"
    "vlc"
    "windirstat"
    "wireshark"
    "discord"
    "dnspy"
    "firefox-dev --pre"
    "ilspy"
    "pstools"
    "steam"
    "teamviewer"
    "geforce-experience"
    "hxd"
    "obs"
    #"sysinternals"
    "rufus"
    "dogtail.dotnet3.5sp1"
    "netfx-4.5.2-devpack"
    "dotnetcoresdk"
    "dotnet"
    "nirlauncher"
    "bulk-crap-uninstaller"
    "jdk11"
    "jdk8"
    "cutter"
    "treesizefree"
)

echo "Setting up Chocolatey software package manager"
Get-PackageProvider -Name chocolatey -Force

echo "Setting up Full Chocolatey Install"
Install-Package -Name Chocolatey -Force -ProviderName chocolatey
$chocopath = (Get-Package chocolatey | ?{$_.Name -eq "chocolatey"} | Select @{N="Source";E={((($a=($_.Source -split "\\"))[0..($a.length - 2)]) -join "\"),"Tools\chocolateyInstall" -join "\"}} | Select -ExpandProperty Source)
& $chocopath "upgrade all -y"

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco install chocolatey-core.extension --force

echo "Creating daily task to automatically upgrade Chocolatey packages"
# adapted from https://blogs.technet.microsoft.com/heyscriptingguy/2013/11/23/using-scheduled-tasks-and-scheduled-jobs-in-powershell/
$ScheduledJob = @{
    Name = "Chocolatey Daily Upgrade"
    ScriptBlock = {choco upgrade all -y}
    Trigger = New-JobTrigger -Daily -at 2am
    ScheduledJobOption = New-ScheduledJobOption -RunElevated -MultipleInstancePolicy StopExisting -RequireNetwork
}
Register-ScheduledJob @ScheduledJob

echo "Installing Packages"
$packages | %{choco install $_ --force -y}

echo "Installing Sysinternals Utilities to C:\Sysinternals"
$download_uri = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$wc = new-object net.webclient
$wc.DownloadFile($download_uri, "/SysinternalsSuite.zip")
Add-Type -AssemblyName "system.io.compression.filesystem"
[io.compression.zipfile]::ExtractToDirectory("/SysinternalsSuite.zip", "/Sysinternals")
echo "Removing zipfile"
rm "/SysinternalsSuite.zip"

start-process "cmd.exe" "/k cd $PSScriptRoot/VC && install_all.bat"