if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

Import-Module -DisableNameChecking $PSScriptRoot\take-own.psm1
Import-Module -DisableNameChecking $PSScriptRoot\New-FolderForced.psm1
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

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

Start-Process "Explorer.exe" -Wait
Start-Sleep -Seconds 6
Restart-Computer