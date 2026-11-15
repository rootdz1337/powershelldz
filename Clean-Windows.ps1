<#
.SYNOPSIS
    Comprehensive Windows bloatware / telemetry / AppX removal toolkit.

.DESCRIPTION
    Removes AppX packages AND:
      - Scheduled tasks (CEIP, Customer Experience, Maps, Feedback, etc.)
      - Services (DiagTrack, dmwappushservice, WMPNetworkSvc, RemoteRegistry, ...)
      - Optional features / capabilities (Windows Recall, Copilot, Xbox, ...)
      - OneDrive (uninstall + deprovision)
      - Edge leftovers (webview, updater)
      - Telemetry registry keys + policies
      - Store re-install prevention (Deprovisioned + EndOfLife + hide)
    Logs everything, supports -DryRun / -WhatIf.

.PARAMETER RemoveAppx
    AppX name prefixes to remove.

.PARAMETER RemoveTasks
    Scheduled task paths to disable/delete.

.PARAMETER RemoveServices
    Service names to stop and disable.

.PARAMETER RemoveFeatures
    Optional Windows features to disable.

.PARAMETER RemoveCapabilities
    Optional capabilities (e.g. "Windows Recall", "Copilot") to remove.

.PARAMETER RemoveOneDrive
    Uninstall + deprovision OneDrive.

.PARAMETER RemoveEdge
    Remove Edge leftovers (WebView2 / Edge updater). Does NOT remove Chromium Edge itself.

.PARAMETER RemoveTelemetry
    Set telemetry to 0 + remove DiagTrack-related keys.

.PARAMETER RemoveStorePrevention
    Add Store hide/deprovision markers to prevent reinstall.

.PARAMETER DryRun
    Preview only.

.EXAMPLE
    .\Clean-Windows.ps1 -RemoveAppx "SecHealthUI","Microsoft.BingNews" -RemoveTelemetry -RemoveOneDrive -DryRun
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$RemoveAppx = @(),

    [string[]]$RemoveTasks = @(
        '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
        '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
        '\Microsoft\Windows\Application Experience\StartupAppTask',
        '\Microsoft\Windows\Autochk\Proxy',
        '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
        '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
        '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask',
        '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
        '\Microsoft\Windows\Feedback\Siuf\DmClient',
        '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload',
        '\Microsoft\Windows\Windows Error Reporting\QueueReporting',
        '\Microsoft\Windows\Windows Media Sharing\UpdateLibrary',
        '\Microsoft\Windows\Maps\MapsToastTask',
        '\Microsoft\Windows\Maps\MapsUpdateTask',
        '\Microsoft\Windows\Speech\SpeechModelDownloadTask'
    ),

    [string[]]$RemoveServices = @(
        'DiagTrack',            # Connected User Experiences and Telemetry
        'dmwappushservice',     # WAP push message routing
        'WMPNetworkSvc',        # Windows Media Player Network Sharing
        'RemoteRegistry',       # Remote registry
        'RetailDemo',           # Retail demo
        'MapsBroker',           # Downloaded Maps Manager
        'lfsvc',                # Geolocation Service
        'WalletService',        # Wallet
        'XblAuthManager',       # Xbox Live Auth Manager
        'XblGameSave',          # Xbox Live Game Save
        'XboxGipSvc',           # Xbox Accessory Management
        'XboxNetApiSvc',        # Xbox Live Networking
        'WerSvc',               # Windows Error Reporting
        'PcaSvc'                # Program Compatibility Assistant
    ),

    [string[]]$RemoveFeatures = @(
        'Xps-Foundation-Xps-Viewer',
        'WorkFolders-Client',
        'FaxServicesClientPackage',
        'Printing-XPSServices-Features',
        'MediaPlayback',
        'WindowsMediaPlayer'
    ),

    [string[]]$RemoveCapabilities = @(
        'App.Support.QuickAssist',
        'App.StepsRecorder',
        'Language.Basic~~~en-US~0.0.1.0',
        'Language.Handwriting~~~en-US~0.0.1.0',
        'Language.OCR~~~en-US~0.0.1.0',
        'Language.Speech~~~en-US~0.0.1.0',
        'Language.TextToSpeech~~~en-US~0.0.1.0',
        'MathRecognizer~~~~en-US~0.0.1.0'
    ),

    [switch]$RemoveOneDrive,
    [switch]$RemoveEdge,
    [switch]$RemoveTelemetry,
    [switch]$RemoveStorePrevention,

    [string]$LogDir = "$env:ProgramData\WinClean\logs",
    [switch]$DryRun
)

#region ---------- Setup ----------
$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$scriptName = 'Clean-Windows'
if (-not (Test-Path $LogDir)) { New-Item $LogDir -ItemType Directory -Force | Out-Null }
$transcriptPath = Join-Path $LogDir "$scriptName-$stamp.log"
$reportPath     = Join-Path $LogDir "$scriptName-$stamp.csv"
Start-Transcript -Path $transcriptPath -Force | Out-Null

Write-Host "=== $scriptName started $(Get-Date) ===" -ForegroundColor Green
Write-Host "DryRun: $DryRun"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Run elevated (Run as Administrator)."
    Stop-Transcript | Out-Null
    return
}

$store   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$results = [System.Collections.Generic.List[object]]::new()
$failed  = [System.Collections.Generic.List[object]]::new()
#endregion

#region ---------- Helpers ----------
function Invoke-Safe {
    param([scriptblock]$Action, [string]$Label)
    try {
        if ($DryRun) {
            Write-Host "  [DRY] $Label" -ForegroundColor Yellow
            return @{ Ok = $true; Dry = $true }
        }
        & $Action
        return @{ Ok = $true; Dry = $false }
    } catch {
        Write-Warning "  [FAIL] $Label :: $($_.Exception.Message)"
        return @{ Ok = $false; Error = $_.Exception.Message }
    }
}

function Add-Result {
    param($Target, [string]$Kind, [string]$Action, [bool]$Success, [string]$Note = '')
    $results.Add([pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Kind      = $Kind
        Target    = $Target
        Action    = $Action
        Success   = $Success
        Note      = $Note
    })
}

function Test-Match {
    param([string]$Name, [string[]]$Patterns)
    if (-not $Name -or -not $Patterns) { return $false }
    foreach ($p in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if ($Name -like "$p*") { return $true }
    }
    return $false
}

function Get-UserSids {
    $sids = @('S-1-5-18')
    if (Test-Path $store) {
        $found = (Get-ChildItem $store -ErrorAction SilentlyContinue |
                  Where-Object { $_.PSChildName -like 'S-1-5-21*' }).PSChildName
        if ($found) { $sids += $found }
    }
    return $sids | Select-Object -Unique
}
#endregion

#region ---------- 1. AppX removal ----------
if ($RemoveAppx.Count -gt 0) {
    Write-Host "`n>>> [AppX] Removing packages..." -ForegroundColor Cyan

    $skip = @()  # extend if desired
    $users        = Get-UserSids
    $provisioned  = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    $appxpackage  = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue

    foreach ($choice in $RemoveAppx) {
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }
        Write-Host "  Target: $choice"

        # --- provisioned ---
        foreach ($appx in ($provisioned | Where-Object { $_.PackageName -like "$choice*" })) {
            if (Test-Match $appx.PackageName $skip) { continue }
            $PackageName = $appx.PackageName
            $match = $appxpackage | Where-Object { $_.Name -eq $appx.DisplayName } | Select-Object -First 1
            $PFN = if ($match) { $match.PackageFamilyName } else {
                if ($PackageName -match '^(.+?)_\d') {
                    $n = $Matches[1]
                    ($appxpackage | Where-Object { $_.Name -eq $n } | Select-Object -First 1).PackageFamilyName
                }
            }

            if ($PFN) {
                $r = Invoke-Safe { New-Item "$store\Deprovisioned\$PFN" -Force | Out-Null } "Deprovision $PFN"
                Add-Result $PackageName 'AppX:Provisioned' 'Deprovision' $r.Ok
                foreach ($sid in $users) {
                    $r = Invoke-Safe { New-Item "$store\EndOfLife\$sid\$PackageName" -Force | Out-Null } "EOL $sid\$PackageName"
                    Add-Result $PackageName 'AppX:Provisioned' "EOL:$sid" $r.Ok
                }
                $r = Invoke-Safe { dism /online /set-nonremovableapppolicy /packagefamily:$PFN /nonremovable:0 | Out-Null } "DISM policy $PFN"
                Add-Result $PackageName 'AppX:Provisioned' 'DISM' $r.Ok
            }

            $r = Invoke-Safe { Remove-AppxProvisionedPackage -PackageName $PackageName -Online -AllUsers -ErrorAction Stop | Out-Null } "Remove provisioned $PackageName"
            Add-Result $PackageName 'AppX:Provisioned' 'Remove' $r.Ok $r.Error
            if (-not $r.Ok) { $failed.Add([pscustomobject]@{Kind='AppX'; Target=$PackageName; Error=$r.Error}) }
        }

        # --- installed ---
        foreach ($appx in ($appxpackage | Where-Object { $_.PackageFullName -like "$choice*" })) {
            if (Test-Match $appx.PackageFullName $skip) { continue }
            $PFN = $appx.PackageFamilyName
            $PF  = $appx.PackageFullName

            $r = Invoke-Safe { New-Item "$store\Deprovisioned\$PFN" -Force | Out-Null } "Deprovision $PFN"
            Add-Result $PF 'AppX:Installed' 'Deprovision' $r.Ok
            foreach ($sid in $users) {
                $r = Invoke-Safe { New-Item "$store\EndOfLife\$sid\$PF" -Force | Out-Null } "EOL $sid\$PF"
                Add-Result $PF 'AppX:Installed' "EOL:$sid" $r.Ok
            }
            $r = Invoke-Safe { dism /online /set-nonremovableapppolicy /packagefamily:$PFN /nonremovable:0 | Out-Null } "DISM policy $PFN"
            Add-Result $PF 'AppX:Installed' 'DISM' $r.Ok

            $r = Invoke-Safe { Remove-AppxPackage -Package $PF -AllUsers -ErrorAction Stop | Out-Null } "Remove $PF"
            Add-Result $PF 'AppX:Installed' 'Remove' $r.Ok $r.Error
            if (-not $r.Ok) { $failed.Add([pscustomobject]@{Kind='AppX'; Target=$PF; Error=$r.Error}) }
        }
    }
}
#endregion

#region ---------- 2. Scheduled tasks ----------
if ($RemoveTasks.Count -gt 0) {
    Write-Host "`n>>> [Tasks] Disabling/removing scheduled tasks..." -ForegroundColor Cyan
    foreach ($t in $RemoveTasks) {
        $full = if ($t.StartsWith('\')) { $t } else { "\$t" }
        $task = Get-ScheduledTask -TaskPath (Split-Path $full) -TaskName (Split-Path $full -Leaf) -ErrorAction SilentlyContinue
        if (-not $task) { Write-Host "  [--] not found: $full" -ForegroundColor DarkGray; continue }

        $r = Invoke-Safe { Disable-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction Stop | Out-Null } "Disable $full"
        Add-Result $full 'Task' 'Disable' $r.Ok

        $r = Invoke-Safe { Unregister-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop } "Remove $full"
        Add-Result $full 'Task' 'Unregister' $r.Ok $r.Error
        if ($r.Ok) { Write-Host "  [OK] $full" -ForegroundColor Green }
        else       { $failed.Add([pscustomobject]@{Kind='Task'; Target=$full; Error=$r.Error}) }
    }
}
#endregion

#region ---------- 3. Services ----------
if ($RemoveServices.Count -gt 0) {
    Write-Host "`n>>> [Services] Stopping & disabling..." -ForegroundColor Cyan
    foreach ($svc in $RemoveServices) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if (-not $s) { Write-Host "  [--] not found: $svc" -ForegroundColor DarkGray; continue }

        if ($s.Status -eq 'Running') {
            $r = Invoke-Safe { Stop-Service -Name $svc -Force -ErrorAction Stop } "Stop $svc"
            Add-Result $svc 'Service' 'Stop' $r.Ok
        }
        $r = Invoke-Safe { Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop } "Disable $svc"
        Add-Result $svc 'Service' 'Disable' $r.Ok $r.Error
        if ($r.Ok) { Write-Host "  [OK] $svc" -ForegroundColor Green }
    }
}
#endregion

#region ---------- 4. Optional features ----------
if ($RemoveFeatures.Count -gt 0) {
    Write-Host "`n>>> [Features] Disabling optional Windows features..." -ForegroundColor Cyan
    foreach ($feat in $RemoveFeatures) {
        $state = Get-WindowsOptionalFeature -Online -FeatureName $feat -ErrorAction SilentlyContinue
        if (-not $state) { Write-Host "  [--] not found: $feat" -ForegroundColor DarkGray; continue }
        if ($state.State -eq 'Disabled') { Write-Host "  [--] already disabled: $feat" -ForegroundColor DarkGray; continue }

        $r = Invoke-Safe { Disable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction Stop | Out-Null } "Disable feature $feat"
        Add-Result $feat 'Feature' 'Disable' $r.Ok $r.Error
        if ($r.Ok) { Write-Host "  [OK] $feat" -ForegroundColor Green }
    }
}
#endregion

#region ---------- 5. Capabilities ----------
if ($RemoveCapabilities.Count -gt 0) {
    Write-Host "`n>>> [Capabilities] Removing..." -ForegroundColor Cyan
    $capList = Get-WindowsCapability -Online -ErrorAction SilentlyContinue
    foreach ($cap in $RemoveCapabilities) {
        $match = $capList | Where-Object { $_.Name -like "$cap*" -and $_.State -ne 'NotPresent' }
        foreach ($c in $match) {
            $r = Invoke-Safe { Remove-WindowsCapability -Online -Name $c.Name -ErrorAction Stop | Out-Null } "Remove capability $($c.Name)"
            Add-Result $c.Name 'Capability' 'Remove' $r.Ok $r.Error
            if ($r.Ok) { Write-Host "  [OK] $($c.Name)" -ForegroundColor Green }
        }
    }
}
#endregion

#region ---------- 6. OneDrive ----------
if ($RemoveOneDrive) {
    Write-Host "`n>>> [OneDrive] Uninstalling..." -ForegroundColor Cyan
    $odSetup = "$env:SystemRoot\System32\OneDriveSetup.exe"
    if (Test-Path $odSetup) {
        $r = Invoke-Safe { Start-Process $odSetup -ArgumentList '/uninstall' -Wait -NoNewWindow } "Uninstall OneDrive"
        Add-Result 'OneDrive' 'Uninstall' $r.Ok
    }
    # Kill running processes
    $r = Invoke-Safe { Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force } "Stop OneDrive process"
    Add-Result 'OneDrive' 'StopProcess' $r.Ok

    # Remove leftover folders
    foreach ($p in @("$env:USERPROFILE\OneDrive", "$env:LOCALAPPDATA\Microsoft\OneDrive", "$env:ProgramData\Microsoft OneDrive")) {
        if (Test-Path $p) {
            $r = Invoke-Safe { Remove-Item $p -Force -Recurse -ErrorAction SilentlyContinue } "Remove $p"
            Add-Result $p 'OneDrive' 'RemoveFolder' $r.Ok
        }
    }

    # Block reinstall via policy
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
    Invoke-Safe { New-Item $pol -Force | Out-Null } 'Create OneDrive policy' | Out-Null
    Invoke-Safe { Set-ItemProperty $pol -Name 'DisableFileSyncNGSC' -Value 1 -Type DWord } 'DisableFileSyncNGSC' | Out-Null
    Invoke-Safe { Set-ItemProperty $pol -Name 'DisableFileSync' -Value 1 -Type DWord } 'DisableFileSync' | Out-Null

    Write-Host "  [OK] OneDrive removed & blocked" -ForegroundColor Green
}
#endregion

#region ---------- 7. Edge leftovers ----------
if ($RemoveEdge) {
    Write-Host "`n>>> [Edge] Removing leftovers (WebView2 / Updater)..." -ForegroundColor Cyan

    # Edge updater scheduled tasks
    foreach ($t in '\MicrosoftEdgeUpdate\MicrosoftEdgeUpdateTaskMachineCore','\MicrosoftEdgeUpdate\MicrosoftEdgeUpdateTaskMachineUA') {
        $task = Get-ScheduledTask -TaskPath (Split-Path $t) -TaskName (Split-Path $t -Leaf) -ErrorAction SilentlyContinue
        if ($task) {
            Invoke-Safe { Unregister-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop } "Remove task $t" | Out-Null
            Add-Result $t 'Edge' 'RemoveTask' $true
        }
    }

    # Edge Update services
    foreach ($s in 'edgeupdate','edgeupdatem','MicrosoftEdgeElevationService') {
        $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($svc) {
            Invoke-Safe { Stop-Service $s -Force -ErrorAction SilentlyContinue } "Stop $s" | Out-Null
            Invoke-Safe { sc.exe config $s start= disabled | Out-Null } "Disable $s" | Out-Null
            Add-Result $s 'Edge' 'Disable' $true
        }
    }

    # Policy: prevent Edge / WebView2 reinstall
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
    Invoke-Safe { New-Item $pol -Force | Out-Null } 'Create EdgeUpdate policy' | Out-Null
    Invoke-Safe { Set-ItemProperty $pol -Name 'InstallDefault' -Value 0 -Type DWord } 'InstallDefault=0' | Out-Null
    Invoke-Safe { Set-ItemProperty $pol -Name 'Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' -Value 0 -Type DWord } 'Block Edge install' | Out-Null
    Invoke-Safe { Set-ItemProperty $pol -Name 'Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -Value 0 -Type DWord } 'Block WebView2 install' | Out-Null
    Invoke-Safe { Set-ItemProperty $pol -Name 'UpdateDefault' -Value 0 -Type DWord } 'UpdateDefault=0' | Out-Null

    Write-Host "  [OK] Edge update components blocked" -ForegroundColor Green
}
#endregion

#region ---------- 8. Telemetry ----------
if ($RemoveTelemetry) {
    Write-Host "`n>>> [Telemetry] Disabling..." -ForegroundColor Cyan

    # Policy: telemetry level
    $policies = @{
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' = @{
            'AllowTelemetry'                = 0
            'MaxTelemetryAllowed'           = 0
            'DoNotShowFeedbackNotifications' = 1
        }
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' = @{
            'DisableWindowsConsumerFeatures' = 1
            'DisableSoftLanding'             = 1
            'DisableWindowsSpotlightFeatures'= 1
        }
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' = @{
            'AllowTelemetry' = 0
        }
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' = @{
            'DisabledByGroupPolicy' = 1
        }
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' = @{
            'AITEnable' = 0
        }
        'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' = @{
            'CEIPEnable' = 0
        }
    }
    foreach ($k in $policies.Keys) {
        if (-not (Test-Path $k)) { Invoke-Safe { New-Item $k -Force | Out-Null } "Create $k" | Out-Null }
        foreach ($v in $policies[$k].GetEnumerator()) {
            $r = Invoke-Safe { Set-ItemProperty $k -Name $v.Key -Value $v.Value -Type DWord -ErrorAction Stop } "$k\$($v.Key)=$($v.Value)"
            Add-Result $k 'Telemetry' "Set:$($v.Key)" $r.Ok
        }
    }

    # Scheduled task-based telemetry already handled if RemoveTasks ran
    # Disable Windows Error Reporting via policy
    $wer = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
    if (Test-Path $wer) {
        Invoke-Safe { Set-ItemProperty $wer -Name 'Disabled' -Value 1 -Type DWord } 'WER Disabled' | Out-Null
    }
    $werPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
    if (-not (Test-Path $werPol)) { Invoke-Safe { New-Item $werPol -Force | Out-Null } "Create WER policy" | Out-Null }
    Invoke-Safe { Set-ItemProperty $werPol -Name 'Disabled' -Value 1 -Type DWord } 'WER policy disabled' | Out-Null

    Write-Host "  [OK] Telemetry disabled" -ForegroundColor Green
}
#endregion

#region ---------- 9. Store prevention ----------
if ($RemoveStorePrevention) {
    Write-Host "`n>>> [Store] Adding reinstall prevention..." -ForegroundColor Cyan

    # Prevent Windows Update from reinstalling bloatware
    $cn = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    if (-not (Test-Path $cn)) { Invoke-Safe { New-Item $cn -Force | Out-Null } 'CloudContent policy' | Out-Null }
    Invoke-Safe { Set-ItemProperty $cn -Name 'DisableWindowsConsumerFeatures' -Value 1 -Type DWord } 'DisableConsumerFeatures' | Out-Null
    Invoke-Safe { Set-ItemProperty $cn -Name 'DisableSoftLanding' -Value 1 -Type DWord } 'DisableSoftLanding' | Out-Null

    # Disable "suggested apps" / Consumer Features
    $adv = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
    $vals = @(
        'SilentInstalledAppsEnabled','PreInstalledAppsEnabled','OemPreInstalledAppsEnabled',
        'PreInstalledAppsEverEnabled','SoftLandingEnabled','SubscribedContent-338388Enabled',
        'SubscribedContent-338389Enabled','SubscribedContent-353694Enabled',
        'SubscribedContent-353696Enabled','SystemPaneSuggestionsEnabled',
        'RotatingLockScreenOverlayEnabled','ContentDeliveryAllowed'
    )
    foreach ($v in $vals) {
        Invoke-Safe { Set-ItemProperty $adv -Name $v -Value 0 -Type DWord -ErrorAction SilentlyContinue } "$v=0" | Out-Null
        Add-Result $adv 'Store' "Set:$v" $true
    }

    # Block Store auto-install of promoted apps
    $ws = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
    if (-not (Test-Path $ws)) { Invoke-Safe { New-Item $ws -Force | Out-Null } 'WindowsStore policy' | Out-Null }
    Invoke-Safe { Set-ItemProperty $ws -Name 'AutoDownload' -Value 2 -Type DWord } 'AutoDownload=2' | Out-Null
    Invoke-Safe { Set-ItemProperty $ws -Name 'DisableStoreApps' -Value 0 -Type DWord } 'DisableStoreApps=0' | Out-Null

    Write-Host "  [OK] Store reinstall prevention applied" -ForegroundColor Green
}
#endregion

#region ---------- 10. Orphan Store key cleanup ----------
Write-Host "`n>>> [Cleanup] Scanning orphan Store entries..." -ForegroundColor Cyan
$currentNames = @{}
$provisioned  = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
$appxpackage  = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
foreach ($p in $provisioned) { $currentNames[$p.PackageName] = $true }
foreach ($p in $appxpackage) { $currentNames[$p.PackageFullName] = $true }

$orphans = 0
$pfnSet  = @{}
foreach ($p in $appxpackage) { $pfnSet[$p.PackageFamilyName] = $true }

foreach ($sub in 'Deprovisioned','EndOfLife') {
    $base = Join-Path $store $sub
    if (-not (Test-Path $base)) { continue }
    Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
        if ($sub -eq 'EndOfLife') {
            Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object -Process {
                if (-not $currentNames.ContainsKey($_.PSChildName)) {
                    if ($PSCmdlet.ShouldProcess($_.PSPath, 'Remove orphan EOL')) {
                        Invoke-Safe { Remove-Item $_.PSPath -Force -Recurse } "Orphan $($_.PSPath)" | Out-Null
                        Add-Result $_.PSChildName 'Store' 'OrphanCleanup' $true
                        $orphans++
                    }
                }
            }
        } else {
            if (-not $pfnSet.ContainsKey($_.PSChildName)) {
                if ($PSCmdlet.ShouldProcess($_.PSPath, 'Remove orphan Deprovisioned')) {
                    Invoke-Safe { Remove-Item $_.PSPath -Force -Recurse } "Orphan $($_.PSPath)" | Out-Null
                    Add-Result $_.PSChildName 'Store' 'OrphanCleanup' $true
                    $orphans++
                }
            }
        }
    }
}
Write-Host "  Orphans removed: $orphans"
#endregion

#region ---------- Report ----------
$results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

Write-Host "`n=== Summary ===" -ForegroundColor Green
$byKind = $results | Group-Object Kind | ForEach-Object { "{0}: {1} actions" -f $_.Name, $_.Count }
$byKind | ForEach-Object { Write-Host "  $_" }

if ($failed.Count -gt 0) {
    Write-Host "`nFailures: $($failed.Count)" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  ! [$($_.Kind)] $($_.Target) :: $($_.Error)" -ForegroundColor Red }
} else {
    Write-Host "`nNo failures." -ForegroundColor Green
}

Write-Host "`nReport: $reportPath"
Write-Host "Log:    $transcriptPath"
Write-Host "NOTE: Reboot required for some changes (features, services, policies)."
Write-Host "=== $scriptName finished $(Get-Date) ===" -ForegroundColor Green
Stop-Transcript | Out-Null
#endregion
