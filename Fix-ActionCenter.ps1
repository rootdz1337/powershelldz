<#
.SYNOPSIS
    Fix-ActionCenter.ps1 — repairs Action Center / notification button after AppX removal.

.DESCRIPTION
    Repairs notification / Action Center / taskbar button failures typically caused by
    aggressive debloat. Re-registers shell AppX packages, restores services, resets the
    notification database, and restarts Explorer.

.PARAMETER ForceReset
    Also deletes the Windows notification DB (destroys notification history).

.PARAMETER ReinstallShell
    Re-registers ALL inbox shell AppX packages (slower, but most thorough).

.EXAMPLE
    .\Fix-ActionCenter.ps1
    .\Fix-ActionCenter.ps1 -ForceReset
    .\Fix-ActionCenter.ps1 -ReinstallShell -ForceReset
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$ForceReset,
    [switch]$ReinstallShell
)

$ErrorActionPreference = 'Continue'
$log = "$env:ProgramData\FixActionCenter-$(Get-Date -f yyyyMMdd_HHmmss).log"
Start-Transcript -Path $log -Force | Out-Null

Write-Host "=== Fix-ActionCenter started $(Get-Date) ===" -ForegroundColor Green

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run elevated."
    Stop-Transcript | Out-Null
    return
}

#region ---------- 1. Restore required services ----------
Write-Host "`n[1/7] Restoring required services..." -ForegroundColor Cyan

$requiredServices = @{
    'WpnService'          = 'Automatic'   # Windows Push Notifications System Service
    'WpnUserService'      = 'Automatic'   # per-user WNS host
    'SystemEventsBroker'  = 'Automatic'   # system event broker (WinRT notifications)
    'BrokerInfrastructure'= 'Automatic'   # background tasks (notifications depend on it)
    'DcomLaunch'          = 'Automatic'
    'RpcSs'               = 'Automatic'
    'Schedule'            = 'Automatic'   # Task Scheduler
    'StateRepository'     = 'Automatic'   # app state DB (notifications)
    'UserManager'         = 'Automatic'
    'ShellHWDetection'    = 'Automatic'
}

foreach ($svc in $requiredServices.GetEnumerator()) {
    $s = Get-Service -Name $svc.Key -ErrorAction SilentlyContinue
    if (-not $s) { Write-Host "  [--] $($svc.Key) not installed" -ForegroundColor DarkGray; continue }
    try {
        Set-Service -Name $svc.Key -StartupType $svc.Value -ErrorAction Stop
        if ($s.Status -ne 'Running') { Start-Service -Name $svc.Key -ErrorAction Stop }
        Write-Host "  [OK] $($svc.Key) = $($svc.Value)" -ForegroundColor Green
    } catch {
        Write-Warning "  [FAIL] $($svc.Key): $($_.Exception.Message)"
    }
}
#endregion

#region ---------- 2. Restore registry keys ----------
Write-Host "`n[2/7] Restoring notification registry keys..." -ForegroundColor Cyan

# Make sure the notification platform isn't disabled by policy
$notifPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
if (-not (Test-Path $notifPolicy)) { New-Item $notifPolicy -Force | Out-Null }
Remove-ItemProperty $notifPolicy -Name 'DisableNotificationCenter' -ErrorAction SilentlyContinue
Remove-ItemProperty $notifPolicy -Name 'NoToastApplicationNotification' -ErrorAction SilentlyContinue

$pushPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
if (-not (Test-Path $pushPolicy)) { New-Item $pushPolicy -Force | Out-Null }
Remove-ItemProperty $pushPolicy -Name 'NoToastApplicationNotification' -ErrorAction SilentlyContinue
Remove-ItemProperty $pushPolicy -Name 'NoCloudApplicationNotification' -ErrorAction SilentlyContinue

# Enable Action Center explicitly (per-user)
$acPolicy = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
if (-not (Test-Path $acPolicy)) { New-Item $acPolicy -Force | Out-Null }
Remove-ItemProperty $acPolicy -Name 'DisableNotificationCenter' -ErrorAction SilentlyContinue

# Restore notification setting for current user
$nset = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications'
if (-not (Test-Path $nset)) { New-Item $nset -Force | Out-Null }
Set-ItemProperty $nset -Name 'ToastEnabled' -Value 1 -Type DWord -Force
Set-ItemProperty $nset -Name 'LockScreenToastEnabled' -Value 1 -Type DWord -Force

# Restore Action Center setting
$acKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'
if (-not (Test-Path $acKey)) { New-Item $acKey -Force | Out-Null }
Set-ItemProperty $acKey -Name 'NOC_GLOBAL_SETTING_TOASTS_ENABLED' -Value 1 -Type DWord -Force
Set-ItemProperty $acKey -Name 'NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK' -Value 1 -Type DWord -Force

Write-Host "  [OK] Registry keys restored" -ForegroundColor Green
#endregion

#region ---------- 3. Re-register critical AppX packages ----------
Write-Host "`n[3/7] Re-registering shell AppX packages..." -ForegroundColor Cyan

# Critical packages for notification/action center
$criticalAppX = @(
    'Microsoft.Windows.ShellExperienceHost',
    'Microsoft.Windows.Cortana',              # notification UI (even if Cortana off, needed)
    'Microsoft.Windows.ContentDeliveryManager',
    'Microsoft.WindowsStore',
    'Microsoft.WindowsTerminal',              # safe to re-register even if not present
    'Microsoft.AAD.BrokerPlugin',
    'Microsoft.AccountsControl',
    'Microsoft.LockApp',
    'Microsoft.Windows.SecureAssessmentBrowser',
    'Microsoft.Windows.CloudExperienceHost',
    'Microsoft.Windows.XGpuEjectDialog',
    'Microsoft.CredDialogHost',
    'Microsoft.Windows.Search',
    'Microsoft.Windows.StartMenuExperienceHost',
    'Microsoft.Windows.SecHealthUI'           # <-- the one we removed
)

function Re-register-AppX {
    param([string]$NamePattern)
    $pkg = Get-AppxPackage -AllUsers -Name "$NamePattern" -ErrorAction SilentlyContinue
    if (-not $pkg) { Write-Host "  [--] $NamePattern not installed" -ForegroundColor DarkGray; return }
    foreach ($p in $pkg) {
        $manifest = Join-Path $p.InstallLocation 'AppxManifest.xml'
        if (-not (Test-Path $manifest)) {
            Write-Warning "  [FAIL] manifest missing for $($p.PackageFullName)"
            continue
        }
        try {
            Add-AppxPackage -DisableDevelopmentMode -Register $manifest -ErrorAction Stop
            Write-Host "  [OK] $($p.PackageFullName)" -ForegroundColor Green
        } catch {
            Write-Warning "  [FAIL] $($p.PackageFullName): $($_.Exception.Message)"
        }
    }
}

foreach ($a in $criticalAppX) { Re-register-AppX $a }

# If nothing was re-registered, restore SecHealthUI from provisioned store
$secHealth = Get-AppxPackage -AllUsers -Name 'Microsoft.Windows.SecHealthUI' -ErrorAction SilentlyContinue
if (-not $secHealth) {
    Write-Host "  [i] SecHealthUI missing — attempting reinstall from provisioned store..." -ForegroundColor Yellow
    try {
        $prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.PackageName -like 'Microsoft.Windows.SecHealthUI*' }
        if ($prov) {
            # Remove our EOL marker for SYSTEM so Windows can restore it
            $store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
            $pfn = ($prov | Select-Object -First 1).PackageName -replace '_\d+.*$',''
            Remove-Item "$store\Deprovisioned\$pfn" -Recurse -Force -ErrorAction SilentlyContinue
            Add-AppxPackage -Register "C:\Program Files\WindowsApps\$($prov[0].PackageName)\AppxManifest.xml" -DisableDevelopmentMode -ErrorAction SilentlyContinue
            Write-Host "  [OK] Attempted SecHealthUI restore" -ForegroundColor Green
        }
    } catch { Write-Warning "  [FAIL] SecHealthUI restore: $($_.Exception.Message)" }
}
#endregion

#region ---------- 4. Reset notification database ----------
Write-Host "`n[4/7] Resetting notification database..." -ForegroundColor Cyan

if ($ForceReset) {
    # Kill processes that lock the DB
    foreach ($p in 'ShellExperienceHost','StartMenuExperienceHost','SearchHost','RuntimeBroker','LockApp') {
        Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2

    $dbPaths = @(
        "$env:LOCALAPPDATA\Microsoft\Windows\Notifications\wpndatabase.db",
        "$env:LOCALAPPDATA\Microsoft\Windows\Notifications\wpndatabase.db-shm",
        "$env:LOCALAPPDATA\Microsoft\Windows\Notifications\wpndatabase.db-wal"
    )
    foreach ($d in $dbPaths) {
        if (Test-Path $d) {
            try {
                Remove-Item $d -Force -ErrorAction Stop
                Write-Host "  [OK] Removed $d" -ForegroundColor Green
            } catch {
                Write-Warning "  [FAIL] $d : $($_.Exception.Message)"
            }
        }
    }
} else {
    Write-Host "  [--] Skipped (use -ForceReset to clear)" -ForegroundColor DarkGray
}
#endregion

#region ---------- 5. Reset Action Center taskbar button ----------
Write-Host "`n[5/7] Resetting taskbar notification button..." -ForegroundColor Cyan

# Re-enable "Action Center" tray icon
$trayKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty $trayKey -Name 'EnableAutoTray' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue

# Ensure ShellExperienceHost package is not blocked
$blocked = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned'
if (Test-Path $blocked) {
    Get-ChildItem $blocked -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -match 'ShellExperienceHost|SecHealthUI|Search'
    } | ForEach-Object {
        try {
            Remove-Item $_.PSPath -Recurse -Force -ErrorAction Stop
            Write-Host "  [OK] Cleared deprovisioned marker: $($_.PSChildName)" -ForegroundColor Green
        } catch {
            Write-Warning "  [FAIL] $($_.PSChildName): $($_.Exception.Message)"
        }
    }
}

# Restart Explorer to force button rebuild
Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
Write-Host "  [OK] Explorer restarted" -ForegroundColor Green
#endregion

#region ---------- 6. Rebuild icon cache ----------
Write-Host "`n[6/7] Rebuilding icon cache..." -ForegroundColor Cyan

$iconCache = "$env:LOCALAPPDATA\IconCache.db"
$iconDir   = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
if (Test-Path $iconCache) { Remove-Item $iconCache -Force -ErrorAction SilentlyContinue }
if (Test-Path $iconDir) {
    Get-ChildItem $iconDir -Filter 'iconcache_*.db' -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
ie4uinit.exe -show 2>$null
Write-Host "  [OK] Icon cache cleared" -ForegroundColor Green
#endregion

#region ---------- 7. Force re-register (optional) ----------
if ($ReinstallShell) {
    Write-Host "`n[7/7] Force re-registering ALL inbox AppX..." -ForegroundColor Cyan
    Get-AppxPackage -AllUsers | Where-Object { $_.SignatureKind -eq 'System' } | ForEach-Object {
        $m = Join-Path $_.InstallLocation 'AppxManifest.xml'
        if (Test-Path $m) {
            try {
                Add-AppxPackage -DisableDevelopmentMode -Register $m -ErrorAction Stop
                Write-Host "  [OK] $($_.PackageFullName)" -ForegroundColor Green
            } catch {
                Write-Host "  [--] $($_.PackageFullName) (skipped)" -ForegroundColor DarkGray
            }
        }
    }
} else {
    Write-Host "`n[7/7] Skipped full re-register (use -ReinstallShell)" -ForegroundColor DarkGray
}
#endregion

# ---------- Summary ----------
Write-Host "`n=== Fix complete. Reboot recommended. ===" -ForegroundColor Green
Write-Host "Log: $log"
Write-Host "`nIf Action Center still doesn't work, try:" -ForegroundColor Yellow
Write-Host "  1. sfc /scannow"
Write-Host "  2. DISM /Online /Cleanup-Image /RestoreHealth"
Write-Host "  3. Reinstall SecHealthUI from Microsoft Store:"
Write-Host "     https://apps.microsoft.com/detail/9p6pmwtjbr5w"
Write-Host "  4. Create a new user profile (corrupted user hive)"

Stop-Transcript | Out-Null
