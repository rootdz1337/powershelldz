<#
.SYNOPSIS
    Clear-AllLogs.ps1 — clear Windows event logs, temp files, transcripts, app caches.

.DESCRIPTION
    Clears (default) or exports-then-clears event logs, deletes temp/log files,
    wipes PowerShell history/transcripts, clears browser caches (optional), and
    reports what was cleared.

.PARAMETER EventLogs
    'All' (default), 'Application', 'System', 'Security', or comma-separated names.

.PARAMETER IncludeTemp
    Delete %TEMP%, %WINDIR%\Temp, Windows Update cache, prefetch (with caution).

.PARAMETER IncludePSHistory
    Delete ConsoleHost_history.txt + PS transcripts.

.PARAMETER IncludeBrowser
    Clear Chrome/Edge/Firefox caches (profile-level, current user only).

.PARAMETER ExportBeforeClear
    Save .evtx backups to $OutputDir before clearing.

.PARAMETER OutputDir
    Where to export backups + the cleanup report. Default: $env:ProgramData\LogCleanup.

.PARAMETER WhatIf
    Preview only.

.EXAMPLE
    .\Clear-AllLogs.ps1 -EventLogs All -IncludeTemp -IncludePSHistory -ExportBeforeClear
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$EventLogs = 'All',
    [switch]$IncludeTemp,
    [switch]$IncludePSHistory,
    [switch]$IncludeBrowser,
    [switch]$ExportBeforeClear,
    [string]$OutputDir = "$env:ProgramData\LogCleanup"
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not (Test-Path $OutputDir)) { New-Item $OutputDir -ItemType Directory -Force | Out-Null }

$backupDir = Join-Path $OutputDir "evtx-$stamp"
$reportPath = Join-Path $OutputDir "clear-$stamp.csv"

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result { param($Category, $Target, $Status, $Note = '')
    $results.Add([pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Category  = $Category
        Target    = $Target
        Status    = $Status    # Cleared | Exported | Skipped | Failed
        Note      = $Note
    })
}

# must be elevated
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run elevated."
}

#region ---------- 1. Event logs ----------
Write-Host "`n[1/5] Event logs..." -ForegroundColor Cyan
$logs = if ($EventLogs -eq 'All') {
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 }
} else {
    $names = if ($EventLogs -match ',') { $EventLogs -split ',' } else { @($EventLogs) }
    Get-WinEvent -ListLog $names -ErrorAction SilentlyContinue
}

if ($ExportBeforeClear) { New-Item $backupDir -ItemType Directory -Force | Out-Null }

foreach ($log in $logs) {
    $name = $log.LogName
    try {
        if ($ExportBeforeClear -and $log.RecordCount -gt 0) {
            $safe = $name -replace '[\\/:*?"<>|]','_'
            $evtx = Join-Path $backupDir "$safe.evtx"
            if ($PSCmdlet.ShouldProcess($name, "Export to $evtx")) {
                wevtutil epl $name $evtx /ow:true 2>$null
                if (Test-Path $evtx) { Add-Result 'EventLog' $name 'Exported' $evtx }
            }
        }
        if ($PSCmdlet.ShouldProcess($name, 'Clear event log')) {
            wevtutil cl $name 2>$null
            Add-Result 'EventLog' $name 'Cleared' "$($log.RecordCount) records"
            Write-Host "  [OK] $name" -ForegroundColor Green
        }
    } catch {
        Add-Result 'EventLog' $name 'Failed' $_.Exception.Message
        Write-Warning "  [FAIL] $name : $($_.Exception.Message)"
    }
}
#endregion

#region ---------- 2. Temp / cache files ----------
if ($IncludeTemp) {
    Write-Host "`n[2/5] Temp / cache files..." -ForegroundColor Cyan
    $tempPaths = @(
        $env:TEMP,
        "$env:SystemRoot\Temp",
        "$env:SystemRoot\Logs\CBS",
        "$env:SystemRoot\SoftwareDistribution\Download",
        "$env:LOCALAPPDATA\Temp",
        "$env:LOCALAPPDATA\Microsoft\Windows\WebCache",
        "$env:LOCALAPPDATA\CrashDumps"
    )
    foreach ($p in $tempPaths) {
        if (-not (Test-Path $p)) { Add-Result 'Temp' $p 'Skipped' 'missing'; continue }
        try {
            $size = (Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue |
                     Measure-Object Length -Sum).Sum
            if ($PSCmdlet.ShouldProcess($p, 'Delete contents')) {
                Get-ChildItem $p -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Add-Result 'Temp' $p 'Cleared' ("{0:N1} MB" -f ($size/1MB))
                Write-Host ("  [OK] {0} ({1:N1} MB)" -f $p, ($size/1MB)) -ForegroundColor Green
            }
        } catch {
            Add-Result 'Temp' $p 'Failed' $_.Exception.Message
        }
    }
} else {
    Write-Host "`n[2/5] Temp skipped (use -IncludeTemp)" -ForegroundColor DarkGray
}
#endregion

#region ---------- 3. PowerShell history + transcripts ----------
if ($IncludePSHistory) {
    Write-Host "`n[3/5] PowerShell history / transcripts..." -ForegroundColor Cyan
    $psPaths = @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "$env:APPDATA\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt"
    )
    foreach ($f in $psPaths) {
        if (Test-Path $f) {
            try {
                if ($PSCmdlet.ShouldProcess($f, 'Delete PS history')) {
                    $sz = (Get-Item $f).Length
                    Remove-Item $f -Force -ErrorAction Stop
                    Add-Result 'PSHistory' $f 'Cleared' "$sz bytes"
                    Write-Host "  [OK] $f" -ForegroundColor Green
                }
            } catch { Add-Result 'PSHistory' $f 'Failed' $_.Exception.Message }
        }
    }

    # Transcripts (default location + any custom under user docs)
    Get-ChildItem "$env:USERPROFILE\Documents" -Recurse -Include 'PowerShell_transcript*.txt' -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                if ($PSCmdlet.ShouldProcess($_.FullName, 'Delete transcript')) {
                    Remove-Item $_.FullName -Force -ErrorAction Stop
                    Add-Result 'PSTranscript' $_.FullName 'Cleared'
                    Write-Host "  [OK] $($_.FullName)" -ForegroundColor Green
                }
            } catch { Add-Result 'PSTranscript' $_.FullName 'Failed' $_.Exception.Message }
        }

    # Clear the in-memory history too (current session)
    try { Clear-History -ErrorAction SilentlyContinue } catch {}
} else {
    Write-Host "`n[3/5] PS history skipped (use -IncludePSHistory)" -ForegroundColor DarkGray
}
#endregion

#region ---------- 4. Browser caches ----------
if ($IncludeBrowser) {
    Write-Host "`n[4/5] Browser caches..." -ForegroundColor Cyan
    $cacheDirs = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
    )
    foreach ($d in $cacheDirs) {
        if (-not (Test-Path $d)) { continue }
        try {
            $size = (Get-ChildItem $d -Recurse -Force -ErrorAction SilentlyContinue |
                     Measure-Object Length -Sum).Sum
            if ($PSCmdlet.ShouldProcess($d, 'Delete cache')) {
                Get-ChildItem $d -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Add-Result 'Browser' $d 'Cleared' ("{0:N1} MB" -f ($size/1MB))
                Write-Host ("  [OK] {0} ({1:N1} MB)" -f $d, ($size/1MB)) -ForegroundColor Green
            }
        } catch { Add-Result 'Browser' $d 'Failed' $_.Exception.Message }
    }
} else {
    Write-Host "`n[4/5] Browser caches skipped (use -IncludeBrowser)" -ForegroundColor DarkGray
}
#endregion

#region ---------- 5. Report ----------
Write-Host "`n[5/5] Report..." -ForegroundColor Cyan
$results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

$summary = $results | Group-Object Status | ForEach-Object { "  {0,-8}: {1}" -f $_.Name, $_.Count }
Write-Host "`n=== Summary ===" -ForegroundColor Green
$summary | ForEach-Object { Write-Host $_ }
Write-Host "`nReport: $reportPath"
if ($ExportBeforeClear) { Write-Host "Backups: $backupDir" }
#endregion
