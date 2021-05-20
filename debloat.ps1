Write-Output "Elevating Terminal"

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
Write-Output "Terminal elevated"
$ErrorActionPreference= 'silentlycontinue'

#ls -Recurse *.ps*1 | Unblock-File -ErrorAction SilentlyContinue
Set-ExecutionPolicy Unrestricted -Scope CurrentUser

Set-ExecutionPolicy Unrestricted -Force
Set-ExecutionPolicy Unrestricted -s cu -f
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0

function New-FolderForced {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
		[Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
		[string]
        $Path
    )

    process {
        if (-not (Test-Path $Path)) {
            Write-Verbose "-- Creating full path to:  $Path"
            New-Item -Path $Path -ItemType Directory -Force
        }
    }
}

function Takeown-Registry($key) {
    # TODO does not work for all root keys yet
    switch ($key.split('\')[0]) {
        "HKEY_CLASSES_ROOT" {
            $reg = [Microsoft.Win32.Registry]::ClassesRoot
            $key = $key.substring(18)
        }
        "HKEY_CURRENT_USER" {
            $reg = [Microsoft.Win32.Registry]::CurrentUser
            $key = $key.substring(18)
        }
        "HKEY_LOCAL_MACHINE" {
            $reg = [Microsoft.Win32.Registry]::LocalMachine
            $key = $key.substring(19)
        }
    }

    # get administraor group
    $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $admins = $admins.Translate([System.Security.Principal.NTAccount])

    # set owner
    $key = $reg.OpenSubKey($key, "ReadWriteSubTree", "TakeOwnership")
    $acl = $key.GetAccessControl()
    $acl.SetOwner($admins)
    $key.SetAccessControl($acl)

    # set FullControl
    $acl = $key.GetAccessControl()
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admins, "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    $key.SetAccessControl($acl)
}

function Takeown-File($path) {
    takeown.exe /A /F $path
    $acl = Get-Acl $path

    # get administraor group
    $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $admins = $admins.Translate([System.Security.Principal.NTAccount])

    # add NT Authority\SYSTEM
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admins, "FullControl", "None", "None", "Allow")
    $acl.AddAccessRule($rule)

    Set-Acl -Path $path -AclObject $acl
}

function Takeown-Folder($path) {
    Takeown-File $path
    foreach ($item in Get-ChildItem $path) {
        if (Test-Path $item -PathType Container) {
            Takeown-Folder $item.FullName
        } else {
            Takeown-File $item.FullName
        }
    }
}
function New-FolderForced {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
		[Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
		[string]
        $Path
    )

    process {
        if (-not (Test-Path $Path)) {
            Write-Verbose "-- Creating full path to:  $Path"
            New-Item -Path $Path -ItemType Directory -Force
        }
    }
}
function Elevate-Privileges {
    param($Privilege)
    $Definition = @"
    using System;
    using System.Runtime.InteropServices;

    public class AdjPriv {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
            internal struct TokPriv1Luid {
                public int Count;
                public long Luid;
                public int Attr;
            }

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        public static bool EnablePrivilege(long processHandle, string privilege) {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }
"@
    $ProcessHandle = (Get-Process -id $pid).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege)
}


do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

taskkill.exe /F /IM "explorer.exe"

#   Description:
# This script blocks telemetry related domains via the hosts file and related
# IPs via Windows Firewall.
#
# Please note that adding these domains may break certain software like iTunes
# or Skype. As this issue is location dependent for some domains, they are not
# commented by default. The domains known to cause issues marked accordingly.
# Please see the related issue:
# <https://github.com/W4RH4WK/Debloat-Windows-10/issues/79>

Import-Module -DisableNameChecking $PSScriptRoot\New-FolderForced.psm1

Write-Output "Disabling telemetry via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

# Entries related to Akamai have been reported to cause issues with Widevine
# DRM.

Write-Output "Adding telemetry domains to hosts file"
$hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
$domains = @(
    "184-86-53-99.deploy.static.akamaitechnologies.com"
    "a-0001.a-msedge.net"
    "a-0002.a-msedge.net"
    "a-0003.a-msedge.net"
    "a-0004.a-msedge.net"
    "a-0005.a-msedge.net"
    "a-0006.a-msedge.net"
    "a-0007.a-msedge.net"
    "a-0008.a-msedge.net"
    "a-0009.a-msedge.net"
    "a1621.g.akamai.net"
    "a1856.g2.akamai.net"
    "a1961.g.akamai.net"
    #"a248.e.akamai.net"            # makes iTunes download button disappear (#43)
    "a978.i6g1.akamai.net"
    "a.ads1.msn.com"
    "a.ads2.msads.net"
    "a.ads2.msn.com"
    "ac3.msn.com"
    "ad.doubleclick.net"
    "adnexus.net"
    "adnxs.com"
    "ads1.msads.net"
    "ads1.msn.com"
    "ads.msn.com"
    "aidps.atdmt.com"
    "aka-cdn-ns.adtech.de"
    "a-msedge.net"
    "any.edge.bing.com"
    "a.rad.msn.com"
    "az361816.vo.msecnd.net"
    "az512334.vo.msecnd.net"
    "b.ads1.msn.com"
    "b.ads2.msads.net"
    "bingads.microsoft.com"
    "b.rad.msn.com"
    "bs.serving-sys.com"
    "c.atdmt.com"
    "cdn.atdmt.com"
    "cds26.ams9.msecn.net"
    "choice.microsoft.com"
    "choice.microsoft.com.nsatc.net"
    "compatexchange.cloudapp.net"
    "corpext.msitadfs.glbdns2.microsoft.com"
    "corp.sts.microsoft.com"
    "cs1.wpc.v0cdn.net"
    "db3aqu.atdmt.com"
    "df.telemetry.microsoft.com"
    "diagnostics.support.microsoft.com"
    "e2835.dspb.akamaiedge.net"
    "e7341.g.akamaiedge.net"
    "e7502.ce.akamaiedge.net"
    "e8218.ce.akamaiedge.net"
    "ec.atdmt.com"
    "fe2.update.microsoft.com.akadns.net"
    "feedback.microsoft-hohm.com"
    "feedback.search.microsoft.com"
    "feedback.windows.com"
    "flex.msn.com"
    "g.msn.com"
    "h1.msn.com"
    "h2.msn.com"
    "hostedocsp.globalsign.com"
    "i1.services.social.microsoft.com"
    "i1.services.social.microsoft.com.nsatc.net"
    "ipv6.msftncsi.com"
    "ipv6.msftncsi.com.edgesuite.net"
    "lb1.www.ms.akadns.net"
    "live.rads.msn.com"
    "m.adnxs.com"
    "msedge.net"
    "msftncsi.com"
    "msnbot-65-55-108-23.search.msn.com"
    "msntest.serving-sys.com"
    "oca.telemetry.microsoft.com"
    "oca.telemetry.microsoft.com.nsatc.net"
    "onesettings-db5.metron.live.nsatc.net"
    "pre.footprintpredict.com"
    "preview.msn.com"
    "rad.live.com"
    "rad.msn.com"
    "redir.metaservices.microsoft.com"
    "reports.wes.df.telemetry.microsoft.com"
    "schemas.microsoft.akadns.net"
    "secure.adnxs.com"
    "secure.flashtalking.com"
    "services.wes.df.telemetry.microsoft.com"
    "settings-sandbox.data.microsoft.com"
    #"settings-win.data.microsoft.com"       # may cause issues with Windows Updates
    "sls.update.microsoft.com.akadns.net"
    #"sls.update.microsoft.com.nsatc.net"    # may cause issues with Windows Updates
    "sqm.df.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com.nsatc.net"
    "ssw.live.com"
    "static.2mdn.net"
    "statsfe1.ws.microsoft.com"
    "statsfe2.update.microsoft.com.akadns.net"
    "statsfe2.ws.microsoft.com"
    "survey.watson.microsoft.com"
    "telecommand.telemetry.microsoft.com"
    "telecommand.telemetry.microsoft.com.nsatc.net"
    "telemetry.appex.bing.net"
    "telemetry.microsoft.com"
    "telemetry.urs.microsoft.com"
    "vortex-bn2.metron.live.com.nsatc.net"
    "vortex-cy2.metron.live.com.nsatc.net"
    "vortex.data.microsoft.com"
    "vortex-sandbox.data.microsoft.com"
    "vortex-win.data.microsoft.com"
    "cy2.vortex.data.microsoft.com.akadns.net"
    "watson.live.com"
    "watson.microsoft.com"
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "wes.df.telemetry.microsoft.com"
    "win10.ipv6.microsoft.com"
    "www.bingads.microsoft.com"
    "www.go.microsoft.akadns.net"
    "www.msftncsi.com"
    "client.wns.windows.com"
    #"wdcp.microsoft.com"                       # may cause issues with Windows Defender Cloud-based protection
    #"dns.msftncsi.com"                         # This causes Windows to think it doesn't have internet
    #"storeedgefd.dsx.mp.microsoft.com"         # breaks Windows Store
    "wdcpalt.microsoft.com"
    "settings-ssl.xboxlive.com"
    "settings-ssl.xboxlive.com-c.edgekey.net"
    "settings-ssl.xboxlive.com-c.edgekey.net.globalredir.akadns.net"
    "e87.dspb.akamaidege.net"
    "insiderservice.microsoft.com"
    "insiderservice.trafficmanager.net"
    "e3843.g.akamaiedge.net"
    "flightingserviceweurope.cloudapp.net"
    #"sls.update.microsoft.com"                 # may cause issues with Windows Updates
    "static.ads-twitter.com"                    # may cause issues with Twitter login
    "www-google-analytics.l.google.com"
    "p.static.ads-twitter.com"                  # may cause issues with Twitter login
    "hubspot.net.edge.net"
    "e9483.a.akamaiedge.net"

    #"www.google-analytics.com"
    #"padgead2.googlesyndication.com"
    #"mirror1.malwaredomains.com"
    #"mirror.cedia.org.ec"
    "stats.g.doubleclick.net"
    "stats.l.doubleclick.net"
    "adservice.google.de"
    "adservice.google.com"
    "googleads.g.doubleclick.net"
    "pagead46.l.doubleclick.net"
    "hubspot.net.edgekey.net"
    "insiderppe.cloudapp.net"                   # Feedback-Hub
    "livetileedge.dsx.mp.microsoft.com"

    # extra
    "fe2.update.microsoft.com.akadns.net"
    "s0.2mdn.net"
    "statsfe2.update.microsoft.com.akadns.net"
    "survey.watson.microsoft.com"
    "view.atdmt.com"
    "watson.microsoft.com"
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "wes.df.telemetry.microsoft.com"
    "m.hotmail.com"

    # can cause issues with Skype (#79) or other services (#171)
    "apps.skype.com"
    "c.msn.com"
    # "login.live.com"                  # prevents login to outlook and other live apps
    "pricelist.skype.com"
    "s.gateway.messenger.live.com"
    "ui.skype.com"
)
Write-Output "" | Out-File -Encoding ASCII -Append $hosts_file
foreach ($domain in $domains) {
    if (-Not (Select-String -Path $hosts_file -Pattern $domain)) {
        Write-Output "0.0.0.0 $domain" | Out-File -Encoding ASCII -Append $hosts_file
    }
}

Write-Output "Adding telemetry ips to firewall"
$ips = @(
    "134.170.30.202"
    "137.116.81.24"
    "157.56.106.189"
    "184.86.53.99"
    "2.22.61.43"
    "2.22.61.66"
    "204.79.197.200"
    "23.218.212.69"
    "65.39.117.230"
    "65.52.108.33"   # Causes problems with Microsoft Store
    "65.55.108.23"
    "64.4.54.254"
)
Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound `
    -Action Block -RemoteAddress ([string[]]$ips)


$registryEntries = (
    ("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power", "CsEnabled ", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowCortanaButton", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowTaskViewButton", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowCortanaButton", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Hidden", 1),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowSuperHidden", 1)



)


$registryEntries | % { 
    

    #If registry entry exists then modify it
    Write-Host -f Yellow "Modifying Registry Key: $($_[0])\$($_[1])"
    Takeown-Registry($_[0]) -ErrorAction SilentlyContinue
    #Takeown-Registry($_[0])\$($_[1])
    #New-Item -Path "registry::$($_[0])" -Name "$($_[1])" -ErrorAction SilentlyContinue
    New-FolderForced -Path "registry::$($_[0])"
    Set-ItemProperty -Path "registry::$($_[0])" -Name "$($_[1])" -Value "$($_[2])" -Force -ErrorAction SilentlyContinue | Out-Null
    if ($? -eq $false){
        #Get-ItemProperty -Path "$($_[0])" -Name "$($_[1])" -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "registry::$($_[0])" -Name "$($_[1])" -Value "$($_[2])" -Force | Out-Null
        if ($? -eq $false){Write-Host -f red "ERROR: Unable to modify: $($_[0])\$($_[1])"}
        
        }

    
 }

 # Disable Privacy Settings Experience #
# Also disables all settings in Privacy Experience #

reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d "1" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "1" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /v "Enabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f


# Set Windows to Dark Mode #

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f

# Prevents SYSPREP from freezing at "Getting Ready" on first boot                          #
# NOTE, DMWAPPUSHSERVICE is a Keyboard and Ink telemetry service, and potential keylogger. #
# It is recommended to disable this service in new builds, but SYSPREP will freeze/fail    #
# if the service is not running. If SYSPREP will be used, add a FirstBootCommand to your   #
# build to disable the service.                                                            #

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /t REG_DWORD /d "1"
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "2"

# This script removes all Start Menu Tiles from the .default user #

Set-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -Value '<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <LayoutOptions StartTileGroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:StartLayout GroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  </DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        <taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:UWA AppUserModelID="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        </taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      </defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '</LayoutModificationTemplate>'

$START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

$layoutFile="C:\Windows\StartMenuLayout.xml"


Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"


Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Output "Removing scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Waiting for explorer to complete loading"
Start-Sleep 10

Write-Output "Removing additional OneDrive leftovers"
foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
    Takeown-Folder $item.FullName
    Remove-Item -Recurse -Force $item.FullName
}




$Bloatware = @(
	"Microsoft.BingNews"
	"Microsoft.GetHelp"
	"Microsoft.Getstarted"
	"Microsoft.Messaging"
	"Microsoft.Microsoft3DViewer"
	"Microsoft.MicrosoftOfficeHub"
	"Microsoft.MicrosoftSolitaireCollection"
	"Microsoft.NetworkSpeedTest"
	"Microsoft.News"
	"Microsoft.Office.Lens"
	"Microsoft.Office.OneNote"
	"Microsoft.Office.Sway"
	"Microsoft.OneConnect"
	"Microsoft.People"
	"Microsoft.Print3D"
	"Microsoft.RemoteDesktop"
	"Microsoft.SkypeApp"
	"Microsoft.StorePurchaseApp"
	"Microsoft.Office.Todo.List"
	"Microsoft.Whiteboard"
	"Microsoft.WindowsAlarms"
	"Microsoft.WindowsCamera"
	"microsoft.windowscommunicationsapps"
	"Microsoft.WindowsFeedbackHub"
	"Microsoft.WindowsMaps"
	"Microsoft.WindowsSoundRecorder"
	"Microsoft.Xbox.TCUI"
	"Microsoft.XboxApp"
	"Microsoft.XboxGameOverlay"
	"Microsoft.XboxIdentityProvider"
	"Microsoft.XboxSpeechToTextOverlay"
	"Microsoft.ZuneMusic"
	"Microsoft.ZuneVideo"
	"*EclipseManager*"
	"*ActiproSoftwareLLC*"
	"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
	"*Duolingo-LearnLanguagesforFree*"
	"*PandoraMediaInc*"
	"*CandyCrush*"
	"*BubbleWitch3Saga*"
	"*Wunderlist*"
	"*Flipboard*"
	"*Twitter*"
	"*Facebook*"
	"*Spotify*"
	"*Minecraft*"
	"*Royal Revolt*"
	"*Sway*"
	"*Speed Test*"
	"*Dolby*"
	"*Microsoft.BingWeather*"
	"*Microsoft.MicrosoftStickyNotes*"
	"*Microsoft.549981C3F5F10*"
	"Microsoft.3DBuilder"
	"Microsoft.Microsoft3DViewer"
	"Microsoft.Appconnector"
	"Microsoft.BingFinance"
	"Microsoft.BingNews"
	"Microsoft.BingSports"
	"Microsoft.BingWeather"
	"Microsoft.WindowsCamera"
	#"Microsoft.FreshPaint"
	"Microsoft.Getstarted"
	"Microsoft.MicrosoftOfficeHub"
	"Microsoft.MicrosoftSolitaireCollection"
	"Microsoft.MicrosoftStickyNotes"
	"Microsoft.Office.OneNote"
	"Microsoft.OneConnect"
	"Microsoft.People"
	"Microsoft.SkypeApp"
	"Microsoft.StorePurchaseApp"
	#"Microsoft.Windows.Photos"
	"Microsoft.WindowsAlarms"
	#"Microsoft.WindowsCalculator"
	"Microsoft.WindowsCamera"
	"Microsoft.Windows.Cortana"
	"Microsoft.WindowsMaps"
	"Microsoft.WindowsPhone"
	"Microsoft.WindowsSoundRecorder"
	#"Microsoft.WindowsStore"
	"Microsoft.XboxApp"
	"Microsoft.XboxGameOverlay"
	"Microsoft.XboxSpeechToTextOverlay"
	"Microsoft.XboxIdentityProvider"
	"Microsoft.XboxGameXCallableUI"
	"Microsoft.ZuneMusic"
	"Microsoft.ZuneVideo"
	"microsoft.windowscommunicationsapps"
	"Microsoft.Wallet"
	"Microsoft.MinecraftUWP"
	"Microsoft.NetworkSpeedTest"
	"Microsoft.PPIProjection"
	"Microsoft.MicrosoftEdge"
	"Microsoft.MicrosoftPowerBIForWindows"
	"AdobeSystemsIncorporated.AdobePhotoshopExpress"
	"Microsoft.CommsPhone"
	"Microsoft.ConnectivityStore"
	"Microsoft.Messaging"
	"Microsoft.Office.Sway"
	"Microsoft.OneConnect"
	"Microsoft.WindowsFeedbackHub"
	"Microsoft.BingFoodAndDrink"
	"Microsoft.BingTravel"
	"Microsoft.BingHealthAndFitness"
	"Microsoft.WindowsReadingList"
	"CortanaListenUIApp"
	"Microsoft.MicrosoftSolitaiteCollection"
	"CortanaListenUIApp_10.0.15063.0_neutral__cw5n1h2txyewy"
	"9E2F88E3.Twitter"
	"PandoraMediaInc.29680B314EFC2"
	"Flipboard.Flipboard"
	"ShazamEntertainmentLtd.Shazam"
	"king.com.CandyCrushSaga"
	"king.com.CandyCrushSodaSaga"
	"king.com.*"
	"ClearChannelRadioDigital.iHeartRadio"
	"4DF9E0F8.Netflix"
	"6Wunderkinder.Wunderlist"
	"Drawboard.DrawboardPDF"
	"2FE3CB00.PicsArt-PhotoStudio"
	"D52A8D61.FarmVille2CountryEscape"
	"TuneIn.TuneInRadio"
	"GAMELOFTSA.Asphalt8Airborne"
	"TheNewYorkTimes.NYTCrossword"
	"DB6EA5DB.CyberLinkMediaSuiteEssentials"
	"Facebook.Facebook"
	"flaregamesGmbH.RoyalRevolt2"
	"Playtika.CaesarsSlotsFreeCasino"
	"46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
	"ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
	"AdobeSystemsIncorporated.AdobePhotoshopExpress_1.3.2.4_x64__ynb6jyjzte8ga"
	"*xboxapp*"
	"ActiproSoftwareLLC.562882FEEB491"
	"Microsoft.Xbox.TCUI"
	"Microsoft.XboxGamingOverlay"
	"Microsoft.XboxGameOverlay"
	"Microsoft.XboxIdentityProvide"
	"Microsoft.XboxSpeechToTextOverlay"
	"Microsoft.WindowsFeedbackHub_1.1907.3152.0_x64__8wekyb3d8bbwe"
	"Microsoft.GetHelp_10.1706.13331.0_x64__8wekyb3d8bbwe"
	"Microsoft.ZuneMusic_10.19071.19011.0_x64__8wekyb3d8bbwe"
	"microsoft.windowscommunicationsapps_16005.11629.20316.0_x64__8wekyb3d8bbwe"
	"Microsoft.Windows.ContentDeliveryManager_10.0.19041.423_neutral_neutral_cw5n1h2txyewy"
	"Microsoft.MicrosoftEdgeDevToolsClient_1000.19041.423.0_neutral_neutral_8wekyb3d8bbwe"
	"Microsoft.Windows.ParentalControls_1000.19041.423.0_neutral_neutral_cw5n1h2txyewy"
	"Microsoft.Wallet_2.4.18324.0_x64__8wekyb3d8bbwe"
	"Microsoft.People_10.1902.633.0_x64__8wekyb3d8bbwe"
	"Microsoft.Windows.Photos_2019.19071.12548.0_x64__8wekyb3d8bbwe"
	"Microsoft.MicrosoftSolitaireCollection_4.4.8204.0_x64__8wekyb3d8bbwe"
	"Microsoft.MicrosoftStickyNotes_3.6.73.0_x64__8wekyb3d8bbwe"
	"Microsoft.Getstarted_8.2.22942.0_x64__8wekyb3d8bbwe"
	"Microsoft.Microsoft3DViewer_6.1908.2042.0_x64__8wekyb3d8bbwe"
	"Microsoft.MixedReality.Portal_2000.19081.1301.0_x64__8wekyb3d8bbwe"
	"Microsoft.ZuneVideo_10.19071.19011.0_x64__8wekyb3d8bbwe"
	"Microsoft.BingWeather_4.25.20211.0_x64__8wekyb3d8bbwe"
	"Microsoft.Windows.NarratorQuickStart_10.0.19041.423_neutral_neutral_8wekyb3d8bbwe"
	"Microsoft.MicrosoftOfficeHub_18.1903.1152.0_x64__8wekyb3d8bbwe"
	"Microsoft.Office.OneNote_16001.12026.20112.0_x64__8wekyb3d8bbwe"
	"Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c"
	"Microsoft.Windows.SecureAssessmentBrowser_10.0.19041.423_neutral_neutral_cw5n1h2txyewy"
	"Microsoft.WindowsAlarms_10.1906.2182.0_x64__8wekyb3d8bbwe"
	"Windows.CBSPreview_10.0.19041.423_neutral_neutral_cw5n1h2txyewy"
	"Microsoft.WindowsCamera_2018.826.98.0_x64__8wekyb3d8bbwe"
	"Microsoft.Windows.Apprep.ChxApp_1000.19041.423.0_neutral_neutral_cw5n1h2txyewy"
	"Microsoft.BioEnrollment_10.0.19041.423_neutral__cw5n1h2txyewy"
	"Microsoft.WindowsMaps_5.1906.1972.0_x64__8wekyb3d8bbwe"
	"Microsoft.Windows.SecHealthUI_10.0.19041.423_neutral__cw5n1h2txyewy"
	"Microsoft.WindowsSoundRecorder_10.1906.1972.0_x64__8wekyb3d8bbwe"
	"Microsoft.AAD.BrokerPlugin_1000.19041.423.0_neutral_neutral_cw5n1h2txyewy"
	"Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe"
	"Microsoft.XboxGamingOverlay_2.34.28001.0_x64__8wekyb3d8bbwe"
	"Microsoft.XboxGameOverlay_1.46.11001.0_x64__8wekyb3d8bbwe"
	"Microsoft.XboxGameCallableUI_1000.19041.423.0_neutral_neutral_cw5n1h2txyewy"
	"Microsoft.XboxIdentityProvider_12.50.6001.0_x64__8wekyb3d8bbwe"
	"Microsoft.Xbox.TCUI_1.23.28002.0_x64__8wekyb3d8bbwe"
	"Microsoft.Windows.CloudExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy"
	"Microsoft.YourPhone_0.19051.7.0_x64__8wekyb3d8bbwe"
	"Microsoft.Xbox.TCUI_1.24.10001.0_x64__8wekyb3d8bbwe"
	"Microsoft.XboxSpeechToTextOverlay_1.21.13002.0_x64__8wekyb3d8bbwe"
	"Microsoft.XboxGameCallableUI_1000.18362.449.0_neutral_neutral_cw5n1h2txyewy"
	"Microsoft.XboxGameOverlay_1.47.14001.0_x64__8wekyb3d8bbwe"
	"Microsoft.XboxGamingOverlay_3.34.15002.0_x64__8wekyb3d8bbwe"
	"Microsoft.XboxIdentityProvider_12.58.1001.0_x64__8wekyb3d8bbwe"
	"Microsoft.Windows.NarratorQuickStart_10.0.19041.423_neutral_neutral_8wekyb3d8bbwe"
	"Microsoft.549981C3F5F10"
)
foreach ($Bloat in $Bloatware) {
	Get-AppxPackage -allusers -Name $Bloat| Remove-AppxPackage
	Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
	Write-Host "Uninstalling $Bloat"
}

$files = (
	"C:\OneDriveTemp",
	"$env:USERPROFILE\OneDrive",
	"$env:LOCALAPPDATA\Microsoft\OneDrive",
	"$env:PROGRAMDATA\Microsoft OneDrive",
	'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore',
	"$env:SYSTEMDRIVE\OneDriveTemp",
	"$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
)

$files | % {

	if (Test-Path $_){

		Remove-Item $_ -Recurse -Force | Out-Null

	}

}

get-appxpackage *microsoft.windowscommunicationsapps* | remove-appxpackage

$apps = @(
	# default Windows 10 apps
	"Microsoft.3DBuilder"
	"Microsoft.Appconnector"
	"Microsoft.BingFinance"
	"Microsoft.BingNews"
	"Microsoft.BingSports"
	"Microsoft.BingTranslator"
	"Microsoft.BingWeather"
	"Microsoft.FreshPaint"
	"Microsoft.GamingServices"
	"Microsoft.Microsoft3DViewer"
	"Microsoft.MicrosoftOfficeHub"
	"Microsoft.MicrosoftPowerBIForWindows"
	"Microsoft.MicrosoftSolitaireCollection"
	#"Microsoft.MicrosoftStickyNotes"
	"Microsoft.MinecraftUWP"
	"Microsoft.NetworkSpeedTest"
	"Microsoft.Office.OneNote"
	"Microsoft.People"
	"Microsoft.Print3D"
	"Microsoft.SkypeApp"
	"Microsoft.Wallet"
	#"Microsoft.Windows.Photos"
	"Microsoft.WindowsAlarms"
	#"Microsoft.WindowsCalculator"
	"Microsoft.WindowsCamera"
	"microsoft.windowscommunicationsapps"
	"Microsoft.WindowsMaps"
	"Microsoft.WindowsPhone"
	"Microsoft.WindowsSoundRecorder"
	#"Microsoft.WindowsStore"   # can't be re-installed
	"Microsoft.Xbox.TCUI"
	"Microsoft.XboxApp"
	"Microsoft.XboxGameOverlay"
	"Microsoft.XboxGamingOverlay"
	"Microsoft.XboxSpeechToTextOverlay"
	"Microsoft.YourPhone"
	"Microsoft.ZuneMusic"
	"Microsoft.ZuneVideo"

	# Threshold 2 apps
	"Microsoft.CommsPhone"
	"Microsoft.ConnectivityStore"
	"Microsoft.GetHelp"
	"Microsoft.Getstarted"
	"Microsoft.Messaging"
	"Microsoft.Office.Sway"
	"Microsoft.OneConnect"
	"Microsoft.WindowsFeedbackHub"

	# Creators Update apps
	"Microsoft.Microsoft3DViewer"
	#"Microsoft.MSPaint"

	#Redstone apps
	"Microsoft.BingFoodAndDrink"
	"Microsoft.BingHealthAndFitness"
	"Microsoft.BingTravel"
	"Microsoft.WindowsReadingList"

	# Redstone 5 apps
	"Microsoft.MixedReality.Portal"
	"Microsoft.ScreenSketch"
	"Microsoft.XboxGamingOverlay"
	"Microsoft.YourPhone"

	# non-Microsoft
	"2FE3CB00.PicsArt-PhotoStudio"
	"46928bounde.EclipseManager"
	"4DF9E0F8.Netflix"
	"613EBCEA.PolarrPhotoEditorAcademicEdition"
	"6Wunderkinder.Wunderlist"
	"7EE7776C.LinkedInforWindows"
	"89006A2E.AutodeskSketchBook"
	"9E2F88E3.Twitter"
	"A278AB0D.DisneyMagicKingdoms"
	"A278AB0D.MarchofEmpires"
	"ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
	"CAF9E577.Plex"  
	"ClearChannelRadioDigital.iHeartRadio"
	"D52A8D61.FarmVille2CountryEscape"
	"D5EA27B7.Duolingo-LearnLanguagesforFree"
	"DB6EA5DB.CyberLinkMediaSuiteEssentials"
	"DolbyLaboratories.DolbyAccess"
	"Drawboard.DrawboardPDF"
	"Facebook.Facebook"
	"Fitbit.FitbitCoach"
	"Flipboard.Flipboard"
	"GAMELOFTSA.Asphalt8Airborne"
	"KeeperSecurityInc.Keeper"
	"NORDCURRENT.COOKINGFEVER"
	"PandoraMediaInc.29680B314EFC2"
	"Playtika.CaesarsSlotsFreeCasino"
	"ShazamEntertainmentLtd.Shazam"
	"SlingTVLLC.SlingTV"
	"SpotifyAB.SpotifyMusic"
	#"TheNewYorkTimes.NYTCrossword"
	"ThumbmunkeysLtd.PhototasticCollage"
	"TuneIn.TuneInRadio"
	"WinZipComputing.WinZipUniversal"
	"XINGAG.XING"
	"flaregamesGmbH.RoyalRevolt2"
	"king.com.*"
	"king.com.BubbleWitch3Saga"
	"king.com.CandyCrushSaga"
	"king.com.CandyCrushSodaSaga"
	# apps which cannot be removed using Remove-AppxPackage
	#"Microsoft.BioEnrollment"
	#"Microsoft.MicrosoftEdge"
	#"Microsoft.Windows.Cortana"
	#"Microsoft.WindowsFeedback"
	#"Microsoft.XboxGameCallableUI"
	#"Microsoft.XboxIdentityProvider"
	#"Windows.ContactSupport"

	# apps which other apps depend on
	"Microsoft.Advertising.Xaml"
)

foreach ($app in $apps) {

	Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

	Get-AppXProvisionedPackage -Online |
		Where-Object DisplayName -EQ $app |
		Remove-AppxProvisionedPackage -Online
}

# Prevents Apps from re-installing
$cdm = @(
	"ContentDeliveryAllowed"
	"FeatureManagementEnabled"
	"OemPreInstalledAppsEnabled"
	"PreInstalledAppsEnabled"
	"PreInstalledAppsEverEnabled"
	"SilentInstalledAppsEnabled"
	"SubscribedContent-314559Enabled"
	"SubscribedContent-338387Enabled"
	"SubscribedContent-338388Enabled"
	"SubscribedContent-338389Enabled"
	"SubscribedContent-338393Enabled"
	"SubscribedContentEnabled"
	"SystemPaneSuggestionsEnabled"
)

New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($key in $cdm) {
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
}

New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

# Prevents "Suggested Applications" returning
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1


$disableTasks = (

    "Microsoft\Windows\AppID\SmartScreenSpecific",
    "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "Microsoft\Windows\Application Experience\StartupAppTask",
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "Microsoft\Windows\Customer Experience Improvement Program\Uploader",
    "Microsoft\Windows\Shell\FamilySafetyUpload",
    "Microsoft\Office\OfficeTelemetryAgentLogOn",
    "Microsoft\Office\OfficeTelemetryAgentFallBack",
    "Microsoft\Office\Office 15 Subscription Heartbeat",
    "Microsoft\Windows\Autochk\Proxy",
    "Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    #"Microsoft\Windows\DiskFootprint\Diagnostics",
    "Microsoft\Windows\FileHistory\File History (maintenance mode)",
    "Microsoft\Windows\Maintenance\WinSAT",
    "Microsoft\Windows\NetTrace\GatherNetworkInfo",
    "Microsoft\Windows\PI\Sqm-Tasks",
    "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime",
    "Microsoft\Windows\Time Synchronization\SynchronizeTime",
    "Microsoft\Windows\Windows Error Reporting\QueueReporting",
    "Microsoft\Windows\WindowsUpdate\Automatic App Update",
    "Microsoft\Windows\RemovalTools\MRT_HB",
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319",
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64",
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical",
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical",
    #"\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)",
    #"\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)",
    #"\Microsoft\Windows\AppID\EDP Policy Manager",
    #"\Microsoft\Windows\AppID\PolicyConverter",
    "\Microsoft\Windows\AppID\SmartScreenSpecific",
    #"\Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck",
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    #"\Microsoft\Windows\Application Experience\StartupAppTask",
    #"\Microsoft\Windows\ApplicationData\CleanupTemporaryState",
    #"\Microsoft\Windows\ApplicationData\DsSvcCleanup",
    #"\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup",
    "\Microsoft\Windows\Autochk\Proxy",
    #"\Microsoft\Windows\Bluetooth\UninstallDeviceTask",
    #"\Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask",
    #"\Microsoft\Windows\CertificateServicesClient\KeyPreGenTask",
    #"\Microsoft\Windows\CertificateServicesClient\SystemTask",
    #"\Microsoft\Windows\CertificateServicesClient\UserTask",
    #"\Microsoft\Windows\CertificateServicesClient\UserTask-Roam",
    #"\Microsoft\Windows\Chkdsk\ProactiveScan",
    #"\Microsoft\Windows\Clip\License Validation",
    "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    #"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan",
    #"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery",
    #"\Microsoft\Windows\Defrag\ScheduledDefrag",
    #"\Microsoft\Windows\Diagnosis\Scheduled",
    #"\Microsoft\Windows\DiskCleanup\SilentCleanup",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    #"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver",
    #"\Microsoft\Windows\DiskFootprint\Diagnostics",
    "\Microsoft\Windows\Feedback\Siuf\DmClient",
    #"\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync",
    #"\Microsoft\Windows\FileHistory\File History (maintenance mode)",
    #"\Microsoft\Windows\LanguageComponentsInstaller\Installation",
    #"\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation",
    #"\Microsoft\Windows\Location\Notifications",
    #"\Microsoft\Windows\Location\WindowsActionDialog",
    #"\Microsoft\Windows\Maintenance\WinSAT",
    #"\Microsoft\Windows\Maps\MapsToastTask",
    #"\Microsoft\Windows\Maps\MapsUpdateTask",
    #"\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents",
    #"\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic",
    "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser",
    #"\Microsoft\Windows\MUI\LPRemove",
    #"\Microsoft\Windows\Multimedia\SystemSoundsService",
    #"\Microsoft\Windows\NetCfg\BindingWorkItemQueueHandler",
    #"\Microsoft\Windows\NetTrace\GatherNetworkInfo",
    #"\Microsoft\Windows\Offline Files\Background Synchronization",
    #"\Microsoft\Windows\Offline Files\Logon Synchronization",
    #"\Microsoft\Windows\PI\Secure-Boot-Update",
    #"\Microsoft\Windows\PI\Sqm-Tasks",
    #"\Microsoft\Windows\Plug and Play\Device Install Group Policy",
    #"\Microsoft\Windows\Plug and Play\Device Install Reboot Required",
    #"\Microsoft\Windows\Plug and Play\Plug and Play Cleanup",
    #"\Microsoft\Windows\Plug and Play\Sysprep Generalize Drivers",
    #"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
    #"\Microsoft\Windows\Ras\MobilityManager",
    #"\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE",
    #"\Microsoft\Windows\Registry\RegIdleBackup",
    #"\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask",
    #"\Microsoft\Windows\RemovalTools\MRT_HB",
    #"\Microsoft\Windows\Servicing\StartComponentCleanup",
    #"\Microsoft\Windows\SettingSync\NetworkStateChangeTask",
    #"\Microsoft\Windows\Shell\CreateObjectTask",
    #"\Microsoft\Windows\Shell\FamilySafetyMonitor",
    #"\Microsoft\Windows\Shell\FamilySafetyRefresh",
    #"\Microsoft\Windows\Shell\IndexerAutomaticMaintenance",
    #"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask",
    #"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon",
    #"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork",
    #"\Microsoft\Windows\SpacePort\SpaceAgentTask",
    #"\Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate",
    #"\Microsoft\Windows\Sysmain\HybridDriveCacheRebalance",
    #"\Microsoft\Windows\Sysmain\ResPriStaticDbSync",
    #"\Microsoft\Windows\Sysmain\WsSwapAssessmentTask",
    #"\Microsoft\Windows\SystemRestore\SR",
    #"\Microsoft\Windows\Task Manager\Interactive",
    #"\Microsoft\Windows\TextServicesFramework\MsCtfMonitor",
    #"\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime",
    #"\Microsoft\Windows\Time Synchronization\SynchronizeTime",
    #"\Microsoft\Windows\Time Zone\SynchronizeTimeZone",
    #"\Microsoft\Windows\TPM\Tpm-HASCertRetr",
    #"\Microsoft\Windows\TPM\Tpm-Maintenance",
    #"\Microsoft\Windows\UpdateOrchestrator\Maintenance Install",
    #"\Microsoft\Windows\UpdateOrchestrator\Policy Install",
    #"\Microsoft\Windows\UpdateOrchestrator\Reboot",
    #"\Microsoft\Windows\UpdateOrchestrator\Resume On Boot",
    #"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
    #"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display",
    #"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot",
    #"\Microsoft\Windows\UPnP\UPnPHostConfig",
    #"\Microsoft\Windows\User Profile Service\HiveUploadTask",
    #"\Microsoft\Windows\WCM\WiFiTask",
    #"\Microsoft\Windows\WDI\ResolutionHost",
    "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
    "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
    "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
    "\Microsoft\Windows\Windows Defender\Windows Defender Verification",
    "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    #"\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange",
    #"\Microsoft\Windows\Windows Media Sharing\UpdateLibrary",
    #"\Microsoft\Windows\WindowsColorSystem\Calibration Loader",
    #"\Microsoft\Windows\WindowsUpdate\Automatic App Update",
    #"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
    #"\Microsoft\Windows\WindowsUpdate\sih",
    #"\Microsoft\Windows\WindowsUpdate\sihboot",
    #"\Microsoft\Windows\Wininet\CacheTask",
    #"\Microsoft\Windows\WOF\WIM-Hash-Management",
    #"\Microsoft\Windows\WOF\WIM-Hash-Validation",
    #"\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization",
    #"\Microsoft\Windows\Work Folders\Work Folders Maintenance Work",
    #"\Microsoft\Windows\Workplace Join\Automatic-Device-Join",
    #"\Microsoft\Windows\WS\License Validation",
    #"\Microsoft\Windows\WS\WSTask",
    # Scheduled tasks which cannot be disabled,
    #"\Microsoft\Windows\Device Setup\Metadata Refresh",
    #"\Microsoft\Windows\SettingSync\BackgroundUploadTask"

)

#Disable the scheduled tasks listed above
$disableTasks | % {
    Write-Host -f Yellow "Disabling Scheduled Task: $_"
    Disable-ScheduledTask $_ -ErrorAction SilentlyContinue | Out-Null
    if ($? -eq $false){
            Write-Host -f red "ERROR: Unable to disable: $_"
    }
}




$features = @(
    'MediaPlayback',
    'SMB1Protocol',
    'Xps-Foundation-Xps-Viewer',
    'WorkFolders-Client',
    'WCF-Services45',
    'NetFx4-AdvSrvs',
    'Printing-Foundation-Features',
    'Printing-PrintToPDFServices-Features',
    'Printing-XPSServices-Features',
    'MSRDC-Infrastructure',
    'MicrosoftWindowsPowerShellV2Root',
    'Internet-Explorer-Optional-amd64'
)
foreach ($feature in $features) {
    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
}

$services = @(

    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"                                # Diagnostics Tracking Service
    "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
    "lfsvc"                                    # Geolocation Service
    "MapsBroker"                               # Downloaded Maps Manager
    "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
    "RemoteAccess"                             # Routing and Remote Access
    "RemoteRegistry"                           # Remote Registry
    "SharedAccess"                             # Internet Connection Sharing (ICS)
    "TrkWks"                                   # Distributed Link Tracking Client
    "WbioSrvc"                                 # Windows Biometric Service (required for Fingerprint reader / facial detection)
    #"WlanSvc"                                 # WLAN AutoConfig
    "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
    "wscsvc"                                  # Windows Security Center Service
    #"WSearch"                                 # Windows Search
    "XblAuthManager"                           # Xbox Live Auth Manager
    "XblGameSave"                              # Xbox Live Game Save Service
    "XboxNetApiSvc"                            # Xbox Live Networking Service
    "ndu"                                      # Windows Network Data Usage Monitor
    # Services which cannot be disabled
    #"WdNisSvc"

    # See https://virtualfeller.com/2017/04/25/optimize-vdi-windows-10-services-original-anniversary-and-creator-updates/

    # Connected User Experiences and Telemetry
    'DiagTrack',

    # Data Usage service
    'DusmSvc',

    # Peer-to-peer updates
    'DoSvc',

    # AllJoyn Router Service (IoT)
    'AJRouter',

    # SSDP Discovery (UPnP)
    'SSDPSRV',
    'upnphost',

    # http://www.csoonline.com/article/3106076/data-protection/disable-wpad-now-or-have-your-accounts-and-private-data-compromised.html
    'iphlpsvc',
    'WinHttpAutoProxySvc',

    # Black Viper 'Safe for DESKTOP' services.
    # See http://www.blackviper.com/service-configurations/black-vipers-windows-10-service-configurations/
    'tzautoupdate',
    'AppVClient',
    'RemoteRegistry',
    'RemoteAccess',
    'shpamsvc',
    'SCardSvr',
    'UevAgentService',
    'ALG',
    'PeerDistSvc',
    'NfsClnt',
    'dmwappushservice',
    'MapsBroker',
    'lfsvc',
    'HvHost',
    'vmickvpexchange',
    'vmicguestinterface',
    'vmicshutdown',
    'vmicheartbeat',
    'vmicvmsession',
    'vmicrdv',
    'vmictimesync',
    'vmicvss',
    'irmon',
    'SharedAccess',
    'MSiSCSI',
    'SmsRouter',
    'CscService',
    'SEMgrSvc',
    'PhoneSvc',
    'RpcLocator',
    'RetailDemo',
    'SensorDataService',
    'SensrSvc',
    'SensorService',
    'ScDeviceEnum',
    'SCPolicySvc',
    'SNMPTRAP',
    'TabletInputService',
    'WFDSConSvc',
    'FrameServer',
    'wisvc',
    'icssvc',
    'WinRM',
    'WwanSvc',
    'XblAuthManager',
    'XblGameSave',
    'XboxNetApiSvc',
    'diagnosticshub.standardcollector.service',
    'TrkWks',
    'WMPNetworkSvc',
    'dmwappushservice',
    'RemoteRegistry'
)
foreach ($service in $services) {
    Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
}

$stopServices = (
    'DiagTrack',
    'diagnosticshub.standardcollector.service',
    'dmwappushservice',
    'WMPNetworkSvc'
)

$stopServices | % { 
    Write-Host -f Yellow "Stopping service: ${_}"
    Stop-Service $_ -ErrorAction SilentlyContinue | Out-Null
    if ($? -eq $false){
            Write-Host -f red "ERROR: Unable to stop: $_"
    }
}


(New-Object -Com Shell.Application).
    NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').
    Items() |
        % { $_.Verbs() } |
        ? {$_.Name -match 'Un.*pin from Start'} |
        % {$_.DoIt()}

Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask
Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask
Get-ScheduledTask  Consolidator | Disable-ScheduledTask
Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
Get-ScheduledTask  DmClient | Disable-ScheduledTask
Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask

Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Disable automatic download and installation of Windows updates"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3

Write-Output "Disable seeding of updates to other computers via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0

#echo "Disabling automatic driver update"
#sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0

$objSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
$EveryOne = $objSID.Translate( [System.Security.Principal.NTAccount]).Value


Write-Output "Disable 'Updates are available' message"

takeown /F "$env:WinDIR\System32\MusNotification.exe"
icacls "$env:WinDIR\System32\MusNotification.exe" /deny "$($EveryOne):(X)"
takeown /F "$env:WinDIR\System32\MusNotificationUx.exe"
icacls "$env:WinDIR\System32\MusNotificationUx.exe" /deny "$($EveryOne):(X)"

$tasks = @(
    "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
    "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
    "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
    "\Microsoft\Windows\Windows Defender\Windows Defender Verification"
)

foreach ($task in $tasks) {
    $parts = $task.split('\')
    $name = $parts[-1]
    $path = $parts[0..($parts.length-2)] -join '\'

    Write-Output "Trying to disable scheduled task $name"
    Disable-ScheduledTask -TaskName "$name" -TaskPath "$path"
}

Write-Output "Disabling Windows Defender via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableRoutinelyTakingAction" 1
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" 1

Write-Output "Disabling Windows Defender Services"
Takeown-Registry("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend")
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "Start" 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "AutorunsDisabled" 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "Start" 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "AutorunsDisabled" 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "Start" 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "AutorunsDisabled" 3

Write-Output "Removing Windows Defender context menu item"
Set-Item "HKLM:\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" ""

Write-Output "Removing Windows Defender GUI / tray from autorun"
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "WindowsDefender" -ea 0

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

Write-Output "Disable mouse pointer hiding"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" "UserPreferencesMask" ([byte[]](0x9e,
0x1e, 0x06, 0x80, 0x12, 0x00, 0x00, 0x00))

Write-Output "Disable Game DVR and Game Bar"
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowgameDVR" 0

Write-Output "Disable easy access keyboard stuff"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" "Flags" "122"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" "Flags" "58"

Write-Output "Disable Edge desktop shortcut on new profiles"
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name DisableEdgeDesktopShortcutCreation -PropertyType DWORD -Value 1

Write-Output "Restoring old volume slider"
New-FolderForced -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" "EnableMtcUvc" 0

Write-Output "Setting folder view options"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideDrivesWithNoMedia" 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" 0

Write-Output "Disable Aero-Shake Minimize feature"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisallowShaking" 1

Write-Output "Setting default explorer view to This PC"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo" 1

Write-Output "Removing user folders under This PC"
# Remove Music from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"  -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ErrorAction SilentlyContinue
# Remove Pictures from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ErrorAction SilentlyContinue
# Remove Videos from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ErrorAction SilentlyContinue
# Remove 3D Objects from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -ErrorAction SilentlyContinue

#echo "Disabling tile push notification"
#New-FolderForced -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
#sp "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoTileApplicationNotification" 1
Start-Process "Explorer.exe" -Wait
