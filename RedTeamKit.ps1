<#
.SYNOPSIS
    RedTeamKit.ps1 — local red-team post-exploitation *audit* toolkit (lab use only).

.DESCRIPTION
    Single-file PowerShell project that performs local reconnaissance, credential-hygiene
    audit, privilege analysis, persistence-hunting, and exfil-risk checks — the kind of
    "what would an attacker see on this box?" picture. Meant for authorized red-team
    engagements on systems you own, or blue-team defensive sweeps.

    NO remote exploitation. NO credential theft. NO AV evasion. NO lateral movement.
    Credential checks are *presence only* — it never dumps secrets, only flags that a
    credential artifact exists where it shouldn't.

.PARAMETER Mode
    Full | Quick | Recon | Priv | Persist | Creds | Exfil | Hardening
    Default: Full

.PARAMETER OutputDir
    Where to write JSON + CSV reports. Default: "$env:ProgramData\RedTeamKit\reports"

.PARAMETER Exclude
    Module names to skip.

.EXAMPLE
    .\RedTeamKit.ps1 -Mode Full
    .\RedTeamKit.ps1 -Mode Priv
    .\RedTeamKit.ps1 -Mode Creds -OutputDir C:\audit
#>

[CmdletBinding()]
param(
    [ValidateSet('Full','Quick','Recon','Priv','Persist','Creds','Exfil','Hardening')]
    [string]$Mode = 'Full',

    [string]$OutputDir = "$env:ProgramData\RedTeamKit\reports",

    [string[]]$Exclude = @()
)

#region ---------- Setup ----------
$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not (Test-Path $OutputDir)) { New-Item $OutputDir -ItemType Directory -Force | Out-Null }

$report = [ordered]@{
    Meta     = [ordered]@{
        Hostname    = $env:COMPUTERNAME
        User        = "$env:USERDOMAIN\$env:USERNAME"
        Timestamp   = (Get-Date).ToString('s')
        Mode        = $Mode
        PSVersion   = $PSVersionTable.PSVersion.ToString()
        Elevated    = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                      ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        IsAdmin     = $false
        IsDomain    = $false
    }
    Findings = [System.Collections.Generic.List[object]]::new()
}

# detect admin / domain
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $report.Meta.IsAdmin  = $cs.PartOfDomain -eq $false -and $env:USERNAME -ne 'SYSTEM'
    $report.Meta.IsDomain = $cs.PartOfDomain
    $report.Meta.Domain   = $cs.Domain
} catch {}

function Add-Finding {
    param(
        [string]$Module,
        [string]$Severity,   # Info | Low | Medium | High | Critical
        [string]$Title,
        [string]$Detail,
        [string]$Mitre = ''
    )
    $report.Findings.Add([pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Module    = $Module
        Severity  = $Severity
        Title     = $Title
        Detail    = $Detail
        Mitre     = $Mitre
    })
    $color = switch ($Severity) {
        'Critical' { 'Magenta' }
        'High'     { 'Red' }
        'Medium'   { 'Yellow' }
        'Low'      { 'Cyan' }
        default    { 'Gray' }
    }
    Write-Host ("  [{0,-8}] {1}" -f $Severity, $Title) -ForegroundColor $color
}

$modules = @{
    Recon     = 'Reconnaissance & host surface'
    Priv      = 'Privilege & token analysis'
    Persist   = 'Persistence hunting'
    Creds     = 'Credential-hygiene audit'
    Exfil     = 'Exfil channel detection'
    Hardening = 'Hardening baseline check'
}
#endregion

#region ====================================================================
# MODULE: Recon
# ====================================================================
function Invoke-Recon {
    Write-Host "`n[Recon] Host surface..." -ForegroundColor Cyan

    # OS / build
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        Add-Finding 'Recon' 'Info' "OS" ("{0} build {1}" -f $os.Caption, $os.BuildNumber)
    } catch {}

    # Uptime
    try {
        $up = (Get-Date) - $os.LastBootUpTime
        Add-Finding 'Recon' 'Info' "Uptime" ("{0}d {1}h" -f $up.Days, $up.Hours)
    } catch {}

    # Patch level — last hotfix
    try {
        $hf = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 3
        foreach ($h in $hf) {
            Add-Finding 'Recon' 'Info' "Hotfix $($h.HotFixID)" "$($h.InstalledOn)"
        }
    } catch {}

    # Defender status
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $sev = if (-not $mp.AntivirusEnabled) { 'High' } elseif (-not $mp.RealTimeProtectionEnabled) { 'High' } else { 'Info' }
        Add-Finding 'Recon' $sev "Defender: AV=$($mp.AntivirusEnabled) RTP=$($mp.RealTimeProtectionEnabled) ASig=$($mp.AntivirusSignatureVersion)"
    } catch {
        Add-Finding 'Recon' 'Medium' "Defender not queryable" $_.Exception.Message
    }

    # Firewall profiles
    try {
        $fw = Get-NetFirewallProfile
        foreach ($p in $fw) {
            if (-not $p.Enabled) {
                Add-Finding 'Recon' 'High' "Firewall disabled: $($p.Name)" "Profile $($p.Name) is disabled"
            }
        }
        Add-Finding 'Recon' 'Info' "Firewall profiles queried" "$($fw.Count) profiles"
    } catch {}

    # Listening ports (external)
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                     Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' } |
                     Select-Object LocalAddress, LocalPort, OwningProcess
        foreach ($l in $listeners) {
            $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
            $sev = if ($l.LocalPort -in 445,3389,5985,5986,135,139,21,23) { 'High' } else { 'Low' }
            Add-Finding 'Recon' $sev "Listening $($l.LocalAddress):$($l.LocalPort)" "PID=$($l.OwningProcess) $($proc.ProcessName)"
        }
    } catch {}

    # SMBv1
    try {
        $s1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($s1.State -eq 'Enabled') { Add-Finding 'Recon' 'High' "SMBv1 enabled" "Legacy SMB protocol" 'T1210' }
    } catch {}

    # WDigest cleartext
    try {
        $wd = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
        if ($wd -eq 1) { Add-Finding 'Recon' 'Critical' "WDigest cleartext enabled" "LSASS stores cleartext passwords" 'T1003.001' }
    } catch {}

    # LSA protection / Credential Guard
    try {
        $lsa = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
        if ($lsa -ne 1) { Add-Finding 'Recon' 'Medium' "LSA protection (RunAsPPL) not set" "LSASS is dumpable" 'T1003.001' }
    } catch {}

    # Long-lived sessions / RDP history
    try {
        $rdp = Get-ItemProperty 'HKCU:\Software\Microsoft\Terminal Server Client\Default' -ErrorAction SilentlyContinue
        if ($rdp) {
            $rdp.PSObject.Properties | Where-Object { $_.Name -like 'MRU*' -and $_.Value } | ForEach-Object {
                Add-Finding 'Recon' 'Medium' "RDP history: $($_.Value)" "MRU entry" 'T1078'
            }
        }
    } catch {}

    # Proxy / hosts file
    try {
        $hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
                 Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() }
        if ($hosts) { Add-Finding 'Recon' 'Medium' "hosts file has $($hosts.Count) entries" "Review for redirection" }
    } catch {}
}
#endregion

#region ====================================================================
# MODULE: Priv
# ====================================================================
function Invoke-Priv {
    Write-Host "`n[Priv] Privilege & token analysis..." -ForegroundColor Cyan

    $id = [Security.Principal.WindowsIdentity]::GetCurrent()

    # Group membership
    foreach ($g in $id.Groups) {
        try {
            $name = $g.Translate([Security.Principal.NTAccount]).Value
            if ($name -match 'Administrators|Backup Operators|Remote Desktop Users|Hyper-V Administrators|Network Configuration Operators') {
                Add-Finding 'Priv' 'High' "High-priv group: $name" "Current token includes $name"
            }
        } catch {}
    }

    # Privileges
    $privs = @(
        'SeDebugPrivilege','SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege',
        'SeTcbPrivilege','SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege',
        'SeLoadDriverPrivilege'
    )
    try {
        $whoami = whoami /priv 2>$null
        foreach ($p in $privs) {
            if ($whoami -match [regex]::Escape($p)) {
                $sev = switch ($p) {
                    'SeDebugPrivilege'            { 'High' }
                    'SeImpersonatePrivilege'      { 'High' }
                    'SeAssignPrimaryTokenPrivilege'{ 'High' }
                    'SeTcbPrivilege'              { 'Critical' }
                    'SeBackupPrivilege'           { 'High' }
                    'SeRestorePrivilege'          { 'High' }
                    'SeTakeOwnershipPrivilege'    { 'Medium' }
                    'SeLoadDriverPrivilege'       { 'High' }
                    default                       { 'Low' }
                }
                Add-Finding 'Priv' $sev "Privilege held: $p" "Token has $p" 'T1134'
            }
        }
    } catch {}

    # UAC level
    try {
        $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
        if ($uac.EnableLUA -eq 0) { Add-Finding 'Priv' 'Critical' "UAC disabled" "EnableLUA=0" 'T1548.002' }
        if ($uac.ConsentPromptBehaviorAdmin -eq 0) { Add-Finding 'Priv' 'High' "UAC admin auto-elevate" "ConsentPromptBehaviorAdmin=0" 'T1548.002' }
        if ($uac.FilterAdministratorToken -eq 0) { Add-Finding 'Priv' 'Medium' "Admin approval mode off" "FilterAdministratorToken=0" }
    } catch {}

    # AutoAdminLogon
    try {
        $w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
        if ($w.AutoAdminLogon -eq '1') {
            Add-Finding 'Priv' 'Critical' "AutoAdminLogon enabled" "User=$($w.DefaultUserName) — password may be in registry" 'T1552.002'
        }
    } catch {}

    # AlwaysInstallElevated
    try {
        $hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
        $hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
        if ($hklm -eq 1 -and $hkcu -eq 1) {
            Add-Finding 'Priv' 'Critical' "AlwaysInstallElevated=1" "MSI installs run as SYSTEM" 'T1548.002'
        }
    } catch {}

    # Unquoted service paths
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' }
        foreach ($s in $svcs) {
            Add-Finding 'Priv' 'Medium' "Unquoted service path: $($s.Name)" $s.PathName 'T1574.009'
        }
    } catch {}

    # Modifiable service binaries
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName }
        foreach ($s in $svcs) {
            $exe = ($s.PathName -replace '^"([^"]+)".*','$1') -replace '^([^\s]+\.exe).*','$1'
            if (Test-Path $exe -ErrorAction SilentlyContinue) {
                try {
                    $acl = Get-Acl $exe
                    foreach ($a in $acl.Access) {
                        if ($a.IdentityReference -match 'Everyone|Users|Authenticated Users' -and
                            $a.FileSystemRights -match 'Write|Modify|FullControl') {
                            Add-Finding 'Priv' 'High' "Writable service binary: $($s.Name)" "$exe -> $($a.IdentityReference)" 'T1574.010'
                            break
                        }
                    }
                } catch {}
            }
        }
    } catch {}

    # Scheduled tasks runnable by non-admin
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            $act = $t.Actions | Where-Object { $_.Execute }
            if ($act) {
                foreach ($a in $act) {
                    if ($a.Execute -and (Test-Path $a.Execute -ErrorAction SilentlyContinue)) {
                        try {
                            $acl = Get-Acl $a.Execute
                            foreach ($x in $acl.Access) {
                                if ($x.IdentityReference -match 'Users|Everyone' -and
                                    $x.FileSystemRights -match 'Write|Modify|FullControl') {
                                    Add-Finding 'Priv' 'High' "Writable task binary: $($t.TaskName)" "$($a.Execute)" 'T1053.005'
                                    break
                                }
                            }
                        } catch {}
                    }
                }
            }
        }
    } catch {}
}
#endregion

#region ====================================================================
# MODULE: Persist
# ====================================================================
function Invoke-Persist {
    Write-Host "`n[Persist] Persistence hunting..." -ForegroundColor Cyan

    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($k in $runKeys) {
        if (Test-Path $k) {
            $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                Add-Finding 'Persist' 'Medium' "Run key: $($_.Name)" "$($_.Value) [$k]" 'T1547.001'
            }
        }
    }

    # Winlogon shell / userinit
    try {
        $w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
        if ($w.Shell -and $w.Shell -ne 'explorer.exe') {
            Add-Finding 'Persist' 'Critical' "Winlogon Shell modified" $w.Shell 'T1547.004'
        }
        if ($w.Userinit -and $w.Userinit -notmatch 'userinit\.exe') {
            Add-Finding 'Persist' 'Critical' "Winlogon Userinit modified" $w.Userinit 'T1547.004'
        }
    } catch {}

    # Image File Execution Options — debuggers
    try {
        $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
            $dbg = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if ($dbg) {
                Add-Finding 'Persist' 'High' "IFEO Debugger set: $($_.PSChildName)" $dbg 'T1546.012'
            }
        }
    } catch {}

    # AppInit_DLLs
    try {
        $ai = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        $dll = (Get-ItemProperty $ai -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs
        $load = (Get-ItemProperty $ai -Name LoadAppInit_DLLs -ErrorAction SilentlyContinue).LoadAppInit_DLLs
        if ($dll -or $load -eq 1) {
            Add-Finding 'Persist' 'Critical' "AppInit_DLLs active" "DLL=$dll LoadAppInit_DLLs=$load" 'T1546.010'
        }
    } catch {}

    # Services with suspicious paths
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        foreach ($s in $svcs) {
            if ($s.PathName -match '\\Temp\\|\\AppData\\|\\Users\\Public\\|powershell|cmd\.exe|mshta|rundll32|regsvr32') {
                Add-Finding 'Persist' 'High' "Suspicious service: $($s.Name)" $s.PathName 'T1543.003'
            }
        }
    } catch {}

    # WMI event subscriptions
    try {
        $subs = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        foreach ($s in $subs) {
            Add-Finding 'Persist' 'High' "WMI event filter: $($s.Name)" $s.Query 'T1546.003'
        }
        $cons = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
        foreach ($c in $cons) {
            Add-Finding 'Persist' 'Critical' "WMI consumer: $($c.Name)" $c.CommandLineTemplate 'T1546.003'
        }
    } catch {}

    # Startup folders
    foreach ($f in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                     "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")) {
        if (Test-Path $f) {
            Get-ChildItem $f -ErrorAction SilentlyContinue | ForEach-Object {
                Add-Finding 'Persist' 'Medium' "Startup folder item: $($_.Name)" $_.FullName 'T1547.001'
            }
        }
    }

    # Scheduled tasks w/ suspicious action
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            foreach ($a in $t.Actions) {
                if ($a.Execute -match 'powershell|cmd|mshta|rundll32|regsvr32|wscript|cscript' -and
                    $a.Arguments -match 'http|base64|FromBase64|-enc|DownloadString|IEX') {
                    Add-Finding 'Persist' 'Critical' "Suspicious task: $($t.TaskName)" "$($a.Execute) $($a.Arguments)" 'T1053.005'
                }
            }
        }
    } catch {}
}
#endregion

#region ====================================================================
# MODULE: Creds (PRESENCE ONLY — never dumps values)
# ====================================================================
function Invoke-Creds {
    Write-Host "`n[Creds] Credential-hygiene audit (presence only)..." -ForegroundColor Cyan

    # Credential Manager
    try {
        $cred = cmdkey /list 2>$null
        $targets = $cred | Select-String 'Target:' | ForEach-Object { $_.Line.Trim() }
        foreach ($t in $targets) {
            Add-Finding 'Creds' 'Medium' "Stored credential: $t" "Credential Manager entry present" 'T1555.004'
        }
    } catch {}

    # DPAPI master keys — presence
    try {
        $mk = Get-ChildItem "$env:APPDATA\Microsoft\Protect" -ErrorAction SilentlyContinue -Recurse
        if ($mk) {
            Add-Finding 'Creds' 'Info' "DPAPI master keys present: $($mk.Count)" "Protected by user logon"
        }
    } catch {}

    # Browser password DBs — presence
    $paths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data",
        "$env:APPDATA\Mozilla\Firefox\Profiles"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Add-Finding 'Creds' 'Medium' "Browser credential store: $p" "Login Data present" 'T1555.003'
        }
    }

    # Unattend / sysprep leftovers
    foreach ($u in @("$env:SystemRoot\Panther\Unattend.xml","$env:SystemRoot\Panther\Unattend\Unattend.xml",
                     "$env:SystemRoot\System32\Sysprep\Unattend.xml","$env:SystemDrive\unattend.xml")) {
        if (Test-Path $u) {
            Add-Finding 'Creds' 'Critical' "Unattend file present: $u" "May contain plaintext creds" 'T1552.001'
        }
    }

    # GPP cpassword in SYSVOL — requires domain; check local cache
    try {
        if ($report.Meta.IsDomain) {
            $sysvol = "\\$($report.Meta.Domain)\SYSVOL"
            if (Test-Path $sysvol) {
                $gpp = Get-ChildItem $sysvol -Recurse -Filter Groups.xml -ErrorAction SilentlyContinue -Depth 3
                foreach ($g in $gpp) {
                    $content = Get-Content $g.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content -match 'cpassword=') {
                        Add-Finding 'Creds' 'Critical' "GPP cpassword: $($g.FullName)" "MS14-025 exposed" 'T1552.006'
                    }
                }
            }
        }
    } catch {}

    # SSH keys unencrypted
    try {
        $ssh = Get-ChildItem "$env:USERPROFILE\.ssh" -ErrorAction SilentlyContinue
        foreach ($k in $ssh | Where-Object { $_.Name -match '^id_' -and $_.Name -notmatch '\.pub$' }) {
            $head = Get-Content $k.FullName -TotalCount 2 -ErrorAction SilentlyContinue
            if ($head -match 'ENCRYPTED') {
                Add-Finding 'Creds' 'Low' "Encrypted SSH key: $($k.Name)" "Passphrase set"
            } else {
                Add-Finding 'Creds' 'Medium' "Unencrypted SSH key: $($k.Name)" "No passphrase" 'T1552.004'
            }
        }
    } catch {}

    # PowerShell history
    try {
        $h = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $h) {
            $lines = Get-Content $h -ErrorAction SilentlyContinue
            if ($lines.Count -gt 0) {
                $pwLines = $lines | Select-String -Pattern 'password|passwd|pwd=|ConvertTo-SecureString|net user' -SimpleMatch
                $sev = if ($pwLines) { 'High' } else { 'Low' }
                Add-Finding 'Creds' $sev "PS history: $($lines.Count) lines" "Contains potentially sensitive commands" 'T1552.003'
            }
        }
    } catch {}

    # LAPS / autologon
    try {
        $w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
        if ($w.DefaultPassword) {
            Add-Finding 'Creds' 'Critical' "Winlogon DefaultPassword set" "Plaintext in registry" 'T1552.002'
        }
    } catch {}

    # .env / config files in home
    try {
        $cfg = Get-ChildItem $env:USERPROFILE -Recurse -Depth 3 -Include '.env','config.json','secrets.yml','.aws\credentials' -ErrorAction SilentlyContinue -Force
        foreach ($c in $cfg) {
            Add-Finding 'Creds' 'Medium' "Potential secrets file: $($c.FullName)" "Review contents" 'T1552.001'
        }
    } catch {}
}
#endregion

#region ====================================================================
# MODULE: Exfil
# ====================================================================
function Invoke-Exfil {
    Write-Host "`n[Exfil] Exfil channel & egress detection..." -ForegroundColor Cyan

    # Active outbound connections
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                 Where-Object { $_.RemoteAddress -notin '127.0.0.1','::1' -and $_.RemoteAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80|fc|fd)' }
        foreach ($c in $conns) {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            $sev = if ($proc.ProcessName -match 'powershell|cmd|wscript|cscript|mshta|rundll32') { 'High' } else { 'Low' }
            Add-Finding 'Exfil' $sev "External conn $($c.RemoteAddress):$($c.RemotePort)" "PID=$($c.OwningProcess) $($proc.ProcessName)" 'T1041'
        }
    } catch {}

    # DNS cache — suspicious domains
    try {
        $dns = Get-DnsClientCache -ErrorAction SilentlyContinue
        $bad = $dns | Where-Object { $_.Entry -match '\.(top|xyz|tk|ml|ga|cf|gq)$|pastebin|ngrok|transfer\.sh|discord(app)?\.com|t\.me' }
        foreach ($d in $bad) {
            Add-Finding 'Exfil' 'Medium' "Suspicious DNS: $($d.Entry)" "TTL=$($d.TimeToLive)" 'T1071.004'
        }
    } catch {}

    # Scheduled tasks that touch network
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            foreach ($a in $t.Actions) {
                if ("$($a.Execute) $($a.Arguments)" -match 'http://|https://|ftp://|WebClient|Invoke-WebRequest|Invoke-RestMethod|curl|wget|bitsadmin') {
                    Add-Finding 'Exfil' 'High' "Task performs network op: $($t.TaskName)" "$($a.Execute) $($a.Arguments)" 'T1105'
                }
            }
        }
    } catch {}

    # PowerShell profiles with network calls
    foreach ($p in @($PROFILE.AllUsersAllHosts, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost)) {
        if (Test-Path $p -ErrorAction SilentlyContinue) {
            $c = Get-Content $p -Raw -ErrorAction SilentlyContinue
            if ($c -match 'Invoke-WebRequest|Invoke-RestMethod|DownloadString|IEX|WebClient|bitsadmin') {
                Add-Finding 'Exfil' 'High' "Suspicious profile: $p" "Network call in profile" 'T1546.013'
            }
        }
    }

    # Clipchamp / clipboard exfil helpers
    try {
        $proc = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -match 'clipchamp|rclone|megasync|dropbox|onedrive|googledrive|syncthing'
        }
        foreach ($p in $proc) {
            Add-Finding 'Exfil' 'Low' "Sync client running: $($p.ProcessName)" "PID=$($p.Id)" 'T1567'
        }
    } catch {}

    # SMB shares (data staging)
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' }
        foreach ($s in $shares) {
            Add-Finding 'Exfil' 'Low' "SMB share: $($s.Name)" $s.Path 'T1039'
        }
    } catch {}
}
#endregion

#region ====================================================================
# MODULE: Hardening
# ====================================================================
function Invoke-Hardening {
    Write-Host "`n[Hardening] Baseline check..." -ForegroundColor Cyan

    $checks = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Want = 5; Sev = 'High';   Title = 'LM/NTLM compat level' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'NoLMHash';            Want = 1; Sev = 'High';   Title = 'NoLMHash' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'SMB1'; Want = 0; Sev = 'High'; Title = 'SMB1 service' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous';   Want = 1; Sev = 'Medium'; Title = 'Anonymous enumeration' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; Name = 'fDenyTSConnections'; Want = 1; Sev = 'Medium'; Title = 'RDP disabled' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Want = 1; Sev = 'Critical'; Title = 'UAC' }
    )
    foreach ($c in $checks) {
        try {
            $v = (Get-ItemProperty $c.Path -Name $c.Name -ErrorAction SilentlyContinue).($c.Name)
            if ($null -eq $v) {
                Add-Finding 'Hardening' 'Low' "$($c.Title) not configured" "$($c.Path)\$($c.Name)"
            } elseif ($v -ne $c.Want) {
                Add-Finding 'Hardening' $c.Sev "$($c.Title) = $v" "expected $($c.Want)"
            } else {
                Add-Finding 'Hardening' 'Info' "$($c.Title) OK" "$v"
            }
        } catch {}
    }

    # BitLocker
    try {
        $bl = Get-BitLockerVolume -ErrorAction Stop
        foreach ($v in $bl) {
            if ($v.ProtectionStatus -ne 'On') {
                Add-Finding 'Hardening' 'High' "BitLocker off: $($v.MountPoint)" "Volume not encrypted" 'T1486'
            }
        }
    } catch {}

    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if (-not $sb) { Add-Finding 'Hardening' 'High' "Secure Boot off" "UEFI Secure Boot disabled" 'T1542.003' }
    } catch {}

    # PowerShell logging
    try {
        $pl = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        $v  = (Get-ItemProperty $pl -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        if ($v -ne 1) { Add-Finding 'Hardening' 'Medium' "ScriptBlock logging off" "EnableScriptBlockLogging != 1" 'T1562.002' }
    } catch {}

    # LAPS presence
    try {
        $laps = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -ErrorAction SilentlyContinue
        if (-not $laps) { Add-Finding 'Hardening' 'Low' "LAPS not configured" "Local admin password management absent" 'T1078.003' }
    } catch {}
}
#endregion

#region ---------- Runner ----------
$toRun = switch ($Mode) {
    'Full'      { 'Recon','Priv','Persist','Creds','Exfil','Hardening' }
    'Quick'     { 'Recon','Priv','Persist' }
    'Recon'     { 'Recon' }
    'Priv'      { 'Priv' }
    'Persist'   { 'Persist' }
    'Creds'     { 'Creds' }
    'Exfil'     { 'Exfil' }
    'Hardening' { 'Hardening' }
}

Write-Host "`n=== RedTeamKit | Host: $($report.Meta.Hostname) | Mode: $Mode | Elevated: $($report.Meta.Elevated) ===" -ForegroundColor Magenta

foreach ($m in $toRun) {
    if ($Exclude -contains $m) { Write-Host "  [skip] $m" -ForegroundColor DarkGray; continue }
    & "Invoke-$m"
}

# ---------- Output ----------
$jsonPath = Join-Path $OutputDir "RedTeamKit-$stamp.json"
$csvPath  = Join-Path $OutputDir "RedTeamKit-$stamp.csv"

$report | ConvertTo-Json -Depth 6 | Set-Content $jsonPath -Encoding UTF8
$report.Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# ---------- Summary ----------
$bySev = $report.Findings | Group-Object Severity | Sort-Object @{Expression={
    switch ($_.Name) { 'Critical'{0}; 'High'{1}; 'Medium'{2}; 'Low'{3}; default{4} }
}} | ForEach-Object { "  {0,-8}: {1}" -f $_.Name, $_.Count }

Write-Host "`n=== Findings by severity ===" -ForegroundColor Magenta
$bySev | ForEach-Object { Write-Host $_ }

Write-Host "`nJSON: $jsonPath"
Write-Host "CSV:  $csvPath"
Write-Host "`nDone $(Get-Date)" -ForegroundColor Magenta
#endregion
