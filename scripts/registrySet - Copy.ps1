if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

Import-Module -DisableNameChecking $PSScriptRoot\take-own.psm1
Import-Module -DisableNameChecking $PSScriptRoot\New-FolderForced.psm1
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

$registryEntries = (
    
    #Disable Cortana
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana", 1),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search","CortanaEnabled", 0),

    #Bing Start Menu Search
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 0),

    #Prevent Windows From Downloading Broken Drivers From Windows Update
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata", "PreventDeviceMetadataFromNetwork", 1),

    # Telemetry Diagnostic and usage data
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
    ("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience\Program-Telemetry", "Enabled", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat", "DisableUAR", 1),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT", "DontOfferThroughWUAU", 1),
    ("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener", "Start", 0),
    ("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger", "Start", 0),

    # Cortana Telemetry
    ("HKEY_LOCAL_MACHINE\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0", "f!dss-winrt-telemetry.js", 0),
    ("HKEY_LOCAL_MACHINE\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0", "f!proactive-telemetry.js", 0),
    ("HKEY_LOCAL_MACHINE\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0", "f!proactive-telemetry-event_8ac43a41e5030538", 0),
    ("HKEY_LOCAL_MACHINE\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0", "f!proactive-telemetry-inter_58073761d33f144b", 0),
  

     # Disable Customer Experience Improvement Telemetry (CEIP/SQM - Software Quality Management)
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows", "CEIPEnable", 0),

    # Disable Application Impact Telemetry (AIT)
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat", "AITEnable", 0),

    #Get fun facts, tips, tricks, and more on your lock screen (ADs) / Windows Spotlight
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "RotatingLockScreenEnabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "RotatingLockScreenOverlayEnabled", 0),
    
    # Get tips, tricks, and suggestions as you use Windows (ADs) / Can cause high disc usage via a process System and compressed memory
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SoftLandingEnabled", 0), 

    # Shows occasional suggestions in Start menu (ADs)
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled",0),

    # Disable AD customization: Settings -> Privacy -> General -> Let apps use my advertising ID...
    ("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy", 1),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", 'Enabled', 0),

    # SmartScreen Filter for Store Apps: Disable
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost", 'EnableWebContentEvaluation', 0),

    # Let websites provide locally...
    ("HKEY_CURRENT_USER\Control Panel\International\User Profile", 'HttpAcceptLanguageOptOut', 1),

    # WiFi Sense: HotSpot Sharing: Disable
    ("HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting", 'value', 0),

    # WiFi Sense: Shared HotSpot Auto-Connect: Disable
    ("HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots", 'value', 0),

    # Change Windows Updates to "Notify to schedule restart"
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings", 'UxOption', 1),

    #Disable P2P Update downlods outside of local network
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config", 'DODownloadMode', 0),

    # Hide the search box from taskbar. You can still search by pressing the Win key and start typing what you're looking for ***
    # 0 = hide completely, 1 = show only icon, 2 = show long search box
    #("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search", "SearchboxTaskbarMode", 0),

    # *** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_TrackDocs", 0),

    # *** Set Windows Explorer to start on This PC instead of Quick Access ***
    # 1 = This PC, 2 = Quick access
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "LaunchTo", 1),

    # Keys related to onedrive uninstall
    ("HKEY_LOCAL_MACHINE:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder", "Attributes", 0),
    ("HKEY_LOCAL_MACHINE:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder", "Attributes", 0),
    
    #Microsoft Malicious Software Removal Tool
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT", 'DontOfferThroughWUAU', 1),
    #Desktop Compression
    ("HKEY_CURRENT_USER\Control Panel\Desktop", "JPEGImportQuality", 100),

    #Remove Activate Windows Watermark
    ("HKEY_CURRENT_USER\Control Panel\Desktop", "PaintDesktopVersion", 00000000),

    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search", "SearchboxTaskbarMode", 00000000),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowCortanaButton", 00000000),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowTaskViewButton", 00000000),
    ("HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys", "Flags", "506"),
    ("HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard, Response", "Flags", "122"),
    ("HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys", "Flags", "58"),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "FeatureManagementEnabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "OemPreInstalledAppsEnabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "PreInstalledAppsEnabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SilentInstalledAppsEnabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "ContentDeliveryAllowed", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "PreInstalledAppsEverEnabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContentEnabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338388Enabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338389Enabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-314559Enabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338387Enabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338393Enabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore", "AutoDownload", 2),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", 1),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows, Search", "AllowCortana", 0),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows, Search", "DisableWebSearch", 1),
    ("HKEY_CURRENT_USER\Software\Microsoft\Siuf\Rules", "PeriodInNanoSeconds", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", 1),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "ContentDeliveryAllowed", 0),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "OemPreInstalledAppsEnabled", 0),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "PreInstalledAppsEnabled", 0),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "PreInstalledAppsEverEnabled", 0),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SilentInstalledAppsEnabled", 0),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled", 0),
    ("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Holographic", "FirstRunSucceeded", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting", "Value", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots", "Value", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config", "AutoConnectAllowedOEM", 0),
    ("HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications", "NoTileApplicationNotification", 1),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 0),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}", "SensorPermissionState", 0),
    ("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration", "Status", 0),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People", "-Name, PeopleBand", 0),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings", "AcceptedPrivacyPolicy", 0),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 1),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", 1),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore", "HarvestContacts", 0),
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent', 'DisableWindowsConsumerFeatures', 1),
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent', 'DisableSoftLanding', 1),
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableFirstLogonAnimation', 0),

    # Set some commonly changed settings for the current user. The interesting one here is "NoTileApplicationNotification" which disables a bunch of start menu tiles.
    ('HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications', 'NoTileApplicationNotification', 1),
    ('HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState', 'FullPath', 1),
    ('HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced', 'HideFileExt', 0),
    ('HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced', 'Hidden', 1),
    ('HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced', 'ShowSyncProviderNotifications', 0),

    # Disable Cortana, and disable any kind of web search or location settings.
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search', 'AllowCortana', 0),
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search', 'AllowSearchToUseLocation', 0),
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search', 'DisableWebSearch', 1),
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search', 'ConnectedSearchUseWeb', 0),


    # Disable data collection and telemetry settings.
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer', 'SmartScreenEnabled', 'Off'),
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection', 'AllowTelemetry', 0),
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection', 'AllowTelemetry', 0),

    # Disable Windows Defender submission of samples and reporting.
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet', 'SpynetReporting', 0),
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet', 'SubmitSamplesConsent', '2'),

    # Ensure updates are downloaded from Microsoft instead of other computers on the internet.
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization', 'DODownloadMode', 0),
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization', 'SystemSettingsDownloadMode', 0),
    ('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config', 'DODownloadMode', 0),

    ("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB", 04000000),
    ("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 00000000),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 00000000),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main", "AllowPrelaunch", 00000000),
    ("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader", "AllowTabPreloading", 00000000)


)

# Modify Registry Entries using the List above
# 0 = Registry Path, 1 = Registry Key Name, 2 = Key Value
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

