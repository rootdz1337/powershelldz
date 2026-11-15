<#
.SYNOPSIS
    Send-PushToast.ps1 — native Windows toast with logo, URL click, buttons.

.PARAMETER Title       Toast title
.PARAMETER Body        Toast body text
.PARAMETER Url         URL opened when toast/button clicked
.PARAMETER Logo        Local path OR URL to PNG logo (48x48 recommended)
.PARAMETER Hero        Local path OR URL to hero image (364x180 recommended)
.PARAMETER AppName     Display name in Settings → Notifications
.PARAMETER AppId       AUMID (must be stable across runs)
.PARAMETER ButtonText  Text of the action button (default "Open")
.PARAMETER Sound       ms-winsoundevent:* (default Reminder)

.EXAMPLE
    .\Send-PushToast.ps1 -Title "Sign in" -Body "Tap to log in." `
        -Url "https://example.com/login" -Logo "C:\temp\logo.png"

.EXAMPLE
    .\Send-PushToast.ps1 -Title "Update ready" -Body "Restart to apply." `
        -Url "https://contoso.com/update" `
        -Logo "https://contoso.com/logo.png" -AppName "Contoso Updater" `
        -AppId "Contoso.Updater" -ButtonText "Restart"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][string]$Body,
    [Parameter(Mandatory)][string]$Url,
    [string]$Logo       = "",
    [string]$Hero       = "",
    [string]$AppName    = "PowerShell",
    [string]$AppId      = "Microsoft.Windows.PowerShell",
    [string]$ButtonText = "Open",
    [string]$Sound      = "ms-winsoundevent:Notification.Reminder",
    [switch]$Persist
)

#region ---------- helpers ----------
function Resolve-ImagePath {
    param([string]$Src)
    if ([string]::IsNullOrWhiteSpace($Src)) { return $null }

    # Already a local file
    if (Test-Path $Src) { return (Resolve-Path $Src).Path }

    # Looks like a URL → download to temp
    if ($Src -match '^https?://') {
        $ext  = [IO.Path]::GetExtension(([Uri]$Src).AbsolutePath)
        if (-not $ext) { $ext = '.png' }
        $dest = Join-Path $env:TEMP ("toast-" + [IO.Path]::GetRandomFileName() + $ext)
        Invoke-WebRequest -Uri $Src -OutFile $dest -UseBasicParsing
        return $dest
    }

    # Bare path that doesn't exist
    return $null
}

function Register-AumidShortcut {
    param([string]$AppId, [string]$AppName, [string]$ExePath)

    $startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
    $lnk       = Join-Path $startMenu "$AppName.lnk"

    # WScript.Shell can create the .lnk; AUMID needs a small step via shell COM
    $wsh = New-Object -ComObject WScript.Shell
    $sc  = $wsh.CreateShortcut($lnk)
    $sc.TargetPath       = $ExePath
    $sc.WorkingDirectory = Split-Path $ExePath -Parent
    $sc.Description      = $AppName
    $sc.Save()

    # Inject System.AppUserModel.ID property via Shell.Application's property system
    # (WScript.Shell can't write properties; use Shell.Application PropertyStore)
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.Namespace($startMenu)
    $item   = $folder.ParseName("$AppName.lnk")
    # Property index for System.AppUserModel.ID varies; use Shell's InvokeVerb-free path:
    # Write it via a tiny inline C# helper (Add-Type) — see Invoke-SetAumid below
    Set-LnkAppUserModelId -LnkPath $lnk -AppId $AppId
}

# Small inline C# (compiled once by Add-Type) — sets AUMID property on a .lnk
if (-not ('LnkAumid' -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class LnkAumid
{
    [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
    private class CShellLink { }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
     Guid("000214F9-0000-0000-C000-000000000046")]
    private interface IShellLinkW
    {
        void GetPath(System.Text.StringBuilder p, int c, IntPtr d, uint f);
        void GetIDList(out IntPtr p);
        void SetIDList(IntPtr p);
        void GetDescription(System.Text.StringBuilder p, int c);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string s);
        void GetWorkingDirectory(System.Text.StringBuilder p, int c);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string s);
        void GetArguments(System.Text.StringBuilder p, int c);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string s);
        void GetHotkey(out short h);
        void SetHotkey(short h);
        void GetShowCmd(out int s);
        void SetShowCmd(int s);
        void GetIconLocation(System.Text.StringBuilder p, int c, out int i);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string p, int i);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string p, uint r);
        void Resolve(IntPtr h, uint f);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string p);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct PKEY { public Guid fmt; public int pid; }

    [StructLayout(LayoutKind.Explicit)]
    private struct PROPVARIANT
    {
        [FieldOffset(0)] public ushort vt;
        [FieldOffset(8)] public IntPtr ptr;
    }

    [ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPropertyStore
    {
        void GetCount(out uint c);
        void GetAt(uint i, out PKEY k);
        void GetValue(ref PKEY k, out PROPVARIANT v);
        void SetValue(ref PKEY k, ref PROPVARIANT v);
        void Commit();
    }

    [ComImport, Guid("0000010b-0000-0000-C000-000000000046"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPersistFile
    {
        void GetClassID(out Guid g);
        void IsDirty();
        void Load([MarshalAs(UnmanagedType.LPWStr)] string f, uint m);
        void Save([MarshalAs(UnmanagedType.LPWStr)] string f, bool r);
        void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string f);
        void GetCurFile([MarshalAs(UnmanagedType.LPWStr)] out string f);
    }

    public static void SetAumid(string lnkPath, string appId)
    {
        var link = (IShellLinkW)new CShellLink();
        ((IPersistFile)link).Load(lnkPath, 2);

        var key = new PKEY {
            fmt = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"),
            pid = 5
        };
        var pv = new PROPVARIANT {
            vt  = 31, // VT_LPWSTR
            ptr = Marshal.StringToCoTaskMemUni(appId)
        };

        var store = (IPropertyStore)link;
        store.SetValue(ref key, ref pv);
        store.Commit();
        ((IPersistFile)link).Save(lnkPath, true);

        Marshal.FreeCoTaskMem(pv.ptr);
    }
}
"@
}

function Set-LnkAppUserModelId {
    param([string]$LnkPath, [string]$AppId)
    [LnkAumid]::SetAumid($LnkPath, $AppId)
}
#endregion

#region ---------- prepare images ----------
$logoLocal = Resolve-ImagePath $Logo
$heroLocal = Resolve-ImagePath $Hero

$logoUri = if ($logoLocal) { ([Uri]$logoLocal).AbsoluteUri } else { "" }
$heroUri = if ($heroLocal) { ([Uri]$heroLocal).AbsoluteUri } else { $logoUri }
#endregion

#region ---------- build XML ----------
$logoImg = if ($logoUri) { "<image placement=`"appLogoOverride`" hint-crop=`"circle`" src=`"$logoUri`"/>" } else { "" }
$heroImg = if ($heroUri) { "<image placement=`"hero`" src=`"$heroUri`"/>" } else { "" }

# Escape XML entities
$Title = [Security.SecurityElement]::Escape($Title)
$Body  = [Security.SecurityElement]::Escape($Body)
$ButtonText = [Security.SecurityElement]::Escape($ButtonText)
$Url   = [Security.SecurityElement]::Escape($Url)

$xml = @"
<toast activationType="protocol" launch="$Url" scenario="reminder">
  <visual>
    <binding template="ToastGeneric">
      <text>$Title</text>
      <text>$Body</text>
      $logoImg
      $heroImg
    </binding>
  </visual>
  <actions>
    <action content="$ButtonText" activationType="protocol" arguments="$Url"/>
    <action content="Dismiss" activationType="system" arguments="dismiss"/>
  </actions>
  <audio src="$Sound"/>
</toast>
"@
#endregion

#region ---------- (optional) register AUMID ----------
if ($Persist -or $AppId -ne 'Microsoft.Windows.PowerShell') {
    $exe = if ($PSVersionTable.PSEdition -eq 'Core') { (Get-Process -Id $PID).Path } else { "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
    Register-AumidShortcut -AppId $AppId -AppName $AppName -ExePath $exe
}
#endregion

#region ---------- show toast ----------
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)

$toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
$toast.Tag   = "login-required"
$toast.Group = "auth"

$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId)
$notifier.Show($toast)

Write-Host "Toast sent via AUMID '$AppId'. Click should open: $Url" -ForegroundColor Green
#endregion
