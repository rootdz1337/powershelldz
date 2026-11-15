<#
.SYNOPSIS
    Removes / deprovisions AppX packages with EOL marking across all user SIDs.

.DESCRIPTION
    - Marks packages as Deprovisioned + EndOfLife for SYSTEM and all user SIDs
    - Clears the non-removable app policy via DISM before removal
    - Handles both provisioned (image) and installed (per-user) packages
    - Logs every action to a transcript + CSV report
    - Supports -WhatIf / -DryRun, skip list, and graceful error handling
    - Cleans up orphaned Store entries for packages that no longer exist

.PARAMETER RemoveAppx
    List of package name prefixes to remove (e.g. "SecHealthUI", "Microsoft.BingNews").

.PARAMETER Skip
    List of package name prefixes to skip even if matched by RemoveAppx.

.PARAMETER LogDir
    Directory to write logs/reports. Defaults to "$env:ProgramData\AppxRemoval\logs".

.PARAMETER DryRun
    If set, shows what WOULD be done — no changes made.

.EXAMPLE
    .\Remove-Appx.ps1 -RemoveAppx "SecHealthUI","Microsoft.BingNews" -DryRun

.EXAMPLE
    .\Remove-Appx.ps1 -RemoveAppx "SecHealthUI" -Skip "Microsoft.BingNews" -LogDir C:\Temp\appx
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$RemoveAppx = @("SecHealthUI"),

    [string[]]$Skip = @(),

    [string]$LogDir = "$env:ProgramData\AppxRemoval\logs",

    [switch]$DryRun
)

#region ---------- Setup ----------
$ErrorActionPreference = 'Continue'
$scriptName = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'

if (-not (Test-Path $LogDir)) { New-Item $LogDir -ItemType Directory -Force | Out-Null }
$transcriptPath = Join-Path $LogDir "$scriptName-$stamp.log"
$reportPath     = Join-Path $LogDir "$scriptName-$stamp.csv"

Start-Transcript -Path $transcriptPath -Force | Out-Null
Write-Host "=== $scriptName started $(Get-Date) ===" -ForegroundColor Green
Write-Host "DryRun: $DryRun | Targets: $($RemoveAppx -join ', ') | Skip: $($Skip -join ', ')"

# Elevation check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run elevated (Run as Administrator)."
    Stop-Transcript | Out-Null
    return
}

$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$results = [System.Collections.Generic.List[object]]::new()
$eol = [System.Collections.Generic.List[string]]::new()
$failed = [System.Collections.Generic.List[object]]::new()
#endregion

#region ---------- Helpers ----------
function Test-Match {
    param([string]$Name, [string[]]$Patterns)
    if (-not $Name -or -not $Patterns) { return $false }
    foreach ($p in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if ($Name -like "$p*") { return $true }
    }
    return $false
}

function Invoke-Safe {
    param([scriptblock]$Action, [string]$Label)
    try {
        if ($DryRun) {
            Write-Host "[DRY-RUN] $Label" -ForegroundColor Yellow
            return @{ Ok = $true; Dry = $true }
        }
        & $Action
        return @{ Ok = $true; Dry = $false }
    } catch {
        Write-Warning "[FAIL] $Label :: $($_.Exception.Message)"
        return @{ Ok = $false; Error = $_.Exception.Message }
    }
}

function Add-Result {
    param($Package, [string]$Kind, [string]$Action, [bool]$Success, [string]$Note = '')
    $results.Add([pscustomobject]@{
        Timestamp    = (Get-Date).ToString('s')
        Kind         = $Kind            # Provisioned | Installed
        Package      = $Package
        Action       = $Action          # Deprovision | EOL | DISM | Remove
        Success      = $Success
        Note         = $Note
    })
}
#endregion

#region ---------- Enumerate SIDs / packages ----------
$users = @('S-1-5-18')   # SYSTEM
if (Test-Path $store) {
    $userSids = (Get-ChildItem $store -ErrorAction SilentlyContinue |
                 Where-Object { $_.PSChildName -like 'S-1-5-21*' }).PSChildName
    if ($userSids) { $users += $userSids }
}
$users = $users | Select-Object -Unique
Write-Host "Target SIDs: $($users -join ', ')"

$provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
$appxpackage = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue

Write-Host "Provisioned packages: $($provisioned.Count)"
Write-Host "Installed (all-users) packages: $($appxpackage.Count)"
#endregion

#region ---------- Main loop ----------
foreach ($choice in $RemoveAppx) {
    if ([string]::IsNullOrWhiteSpace($choice)) { continue }
    Write-Host "`n>>> Processing target: $choice" -ForegroundColor Cyan

    # ---------- Provisioned ----------
    $provMatches = $provisioned | Where-Object { $_.PackageName -like "$choice*" }
    foreach ($appx in $provMatches) {
        if (Test-Match $appx.PackageName $Skip) {
            Write-Host "  [SKIP] $($appx.PackageName)" -ForegroundColor DarkYellow
            continue
        }

        $PackageName = $appx.PackageName
        $installedMatch = $appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }
        $PackageFamilyName = if ($installedMatch) { $installedMatch[0].PackageFamilyName } else { $null }

        # Fallback: derive PFN from the provisioned PackageName (Name_Version_Arch__PublisherId)
        if (-not $PackageFamilyName -and $PackageName -match '^(.+?)_\d') {
            $pfnName = $Matches[1]
            $found = $appxpackage | Where-Object { $_.Name -eq $pfnName } | Select-Object -First 1
            if ($found) { $PackageFamilyName = $found.PackageFamilyName }
        }

        if (-not $PackageFamilyName) {
            Write-Warning "  [WARN] Could not resolve PFN for $PackageName — skipping EOL/Deprovision mark"
        } else {
            $r = Invoke-Safe { New-Item "$store\Deprovisioned\$PackageFamilyName" -Force | Out-Null } "Deprovision mark $PackageFamilyName"
            Add-Result $PackageName 'Provisioned' 'Deprovision' $r.Ok
            if ($r.Ok) { Write-Host "  [OK] Deprovisioned\$PackageFamilyName" -ForegroundColor Green }

            foreach ($sid in $users) {
                $r = Invoke-Safe { New-Item "$store\EndOfLife\$sid\$PackageName" -Force | Out-Null } "EOL $sid\$PackageName"
                Add-Result $PackageName 'Provisioned' "EOL:$sid" $r.Ok
            }

            $r = Invoke-Safe { dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 | Out-Null } "DISM policy $PackageFamilyName"
            Add-Result $PackageName 'Provisioned' 'DISM' $r.Ok
        }

        $r = Invoke-Safe { Remove-AppxProvisionedPackage -PackageName $PackageName -Online -AllUsers -ErrorAction Stop | Out-Null } "Remove provisioned $PackageName"
        Add-Result $PackageName 'Provisioned' 'Remove' $r.Ok $r.Error
        if ($r.Ok) {
            Write-Host "  [OK] Removed provisioned $PackageName" -ForegroundColor Green
            $eol.Add($PackageName)
        } else {
            $failed.Add([pscustomobject]@{ Kind='Provisioned'; Package=$PackageName; Error=$r.Error })
        }
    }

    # ---------- Installed ----------
    $instMatches = $appxpackage | Where-Object { $_.PackageFullName -like "$choice*" }
    foreach ($appx in $instMatches) {
        if (Test-Match $appx.PackageFullName $Skip) {
            Write-Host "  [SKIP] $($appx.PackageFullName)" -ForegroundColor DarkYellow
            continue
        }

        $PackageFullName   = $appx.PackageFullName
        $PackageFamilyName = $appx.PackageFamilyName

        $r = Invoke-Safe { New-Item "$store\Deprovisioned\$PackageFamilyName" -Force | Out-Null } "Deprovision mark $PackageFamilyName"
        Add-Result $PackageFullName 'Installed' 'Deprovision' $r.Ok
        if ($r.Ok) { Write-Host "  [OK] Deprovisioned\$PackageFamilyName" -ForegroundColor Green }

        foreach ($sid in $users) {
            $r = Invoke-Safe { New-Item "$store\EndOfLife\$sid\$PackageFullName" -Force | Out-Null } "EOL $sid\$PackageFullName"
            Add-Result $PackageFullName 'Installed' "EOL:$sid" $r.Ok
        }

        $r = Invoke-Safe { dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 | Out-Null } "DISM policy $PackageFamilyName"
        Add-Result $PackageFullName 'Installed' 'DISM' $r.Ok

        $r = Invoke-Safe { Remove-AppxPackage -Package $PackageFullName -AllUsers -ErrorAction Stop | Out-Null } "Remove installed $PackageFullName"
        Add-Result $PackageFullName 'Installed' 'Remove' $r.Ok $r.Error
        if ($r.Ok) {
            Write-Host "  [OK] Removed installed $PackageFullName" -ForegroundColor Green
            $eol.Add($PackageFullName)
        } else {
            $failed.Add([pscustomobject]@{ Kind='Installed'; Package=$PackageFullName; Error=$r.Error })
        }
    }
}
#endregion

#region ---------- Cleanup orphaned Store entries ----------
Write-Host "`n>>> Scanning for orphaned Store entries..." -ForegroundColor Cyan
$currentNames = @{}
$provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
$appxpackage = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
foreach ($p in $provisioned) { $currentNames[$p.PackageName] = $true }
foreach ($p in $appxpackage) { $currentNames[$p.PackageFullName] = $true }

$orphans = 0
foreach ($sub in @('Deprovisioned','EndOfLife')) {
    $base = Join-Path $store $sub
    if (-not (Test-Path $base)) { continue }
    Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
        $keyName = $_.PSChildName
        # EndOfLife has structure SID\PackageName
        if ($sub -eq 'EndOfLife') {
            Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object -Process {
                if (-not $currentNames.ContainsKey($_.PSChildName)) {
                    if ($PSCmdlet.ShouldProcess($_.PSPath, 'Remove orphan EOL key')) {
                        Invoke-Safe { Remove-Item $_.PSPath -Force -Recurse } "Remove orphan $($_.PSPath)" | Out-Null
                        Add-Result $_.PSChildName 'Store' 'OrphanCleanup' $true
                        $orphans++
                    }
                }
            }
        } else {
            # Deprovisioned key name is PFN, not full name — check by PFN prefix
            $pfn = $keyName
            $stillExists = $appxpackage | Where-Object { $_.PackageFamilyName -eq $pfn }
            if (-not $stillExists) {
                if ($PSCmdlet.ShouldProcess($_.PSPath, 'Remove orphan Deprovisioned key')) {
                    Invoke-Safe { Remove-Item $_.PSPath -Force -Recurse } "Remove orphan $($_.PSPath)" | Out-Null
                    Add-Result $pfn 'Store' 'OrphanCleanup' $true
                    $orphans++
                }
            }
        }
    }
}
Write-Host "Orphans cleaned: $orphans"
#endregion

#region ---------- Report ----------
$results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

Write-Host "`n=== Summary ===" -ForegroundColor Green
Write-Host "Processed (EOL marked): $($eol.Count)"
$eol | ForEach-Object { Write-Host "  + $_" -ForegroundColor Green }

if ($failed.Count -gt 0) {
    Write-Host "`nFailures: $($failed.Count)" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  ! [$($_.Kind)] $($_.Package) :: $($_.Error)" -ForegroundColor Red }
} else {
    Write-Host "No failures." -ForegroundColor Green
}

Write-Host "`nReport: $reportPath"
Write-Host "Log:    $transcriptPath"
Write-Host "=== $scriptName finished $(Get-Date) ===" -ForegroundColor Green

Stop-Transcript | Out-Null
#endregion
