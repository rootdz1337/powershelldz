<#
.SYNOPSIS
    Show-TransparentProgress.ps1 — borderless transparent progress overlay.

.DESCRIPTION
    Displays a semi-transparent, always-on-top progress bar in the bottom-right of the
    primary screen. Supports a title, status text, percentage, optional logo, and cancel.

    Works in Windows PowerShell 5.1 and PowerShell 7 (WinForms).

.PARAMETER Title
    Big title text (top of overlay).

.PARAMETER Logo
    Local path or URL to a PNG. Shown at 32x32 to the left of the title.

.PARAMETER Opacity
    Background opacity 0.0–1.0. Default 0.55 (55%).

.PARAMETER Position
    BottomRight (default) | BottomLeft | TopRight | TopLeft | Center.

.PARAMETER Cancel
    Show a Cancel button that raises the .Cancelled property.

.EXAMPLE
    $p = Show-TransparentProgress -Title "Installing..." -Logo .\logo.png
    for ($i=0; $i -le 100; $i+=5) {
        $p.SetProgress($i, "Step $i of 100")
        if ($p.Cancelled) { break }
        Start-Sleep -Milliseconds 200
    }
    $p.Close()
#>

function Show-TransparentProgress {
    [CmdletBinding()]
    param(
        [string]$Title    = "Working...",
        [string]$Status   = "Starting...",
        [string]$Logo     = "",
        [double]$Opacity  = 0.55,
        [ValidateSet('BottomRight','BottomLeft','TopRight','TopLeft','Center')]
        [string]$Position = 'BottomRight',
        [switch]$Cancel,
        [System.Drawing.Color]$Accent = [System.Drawing.Color]::FromArgb(0, 120, 215)
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # --- form ---
    $form = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = 'None'
    $form.StartPosition   = 'Manual'
    $form.ShowInTaskbar   = $false
    $form.TopMost         = $true
    $form.Width           = 380
    $form.Height          = if ($Cancel) { 120 } else { 96 }
    $form.BackColor       = [System.Drawing.Color]::Black
    $form.Opacity         = $Opacity
    $form.Padding         = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)

    # round corners (Win11 / Win10 rounded)
    $radius = 12
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc(0, 0, $radius, $radius, 180, 90)
    $path.AddArc($form.Width - $radius, 0, $radius, $radius, 270, 90)
    $path.AddArc($form.Width - $radius, $form.Height - $radius, $radius, $radius, 0, 90)
    $path.AddArc(0, $form.Height - $radius, $radius, $radius, 90, 90)
    $path.CloseAllFigures()
    $form.Region = New-Object System.Drawing.Region($path)

    # position on screen
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $margin = 24
    switch ($Position) {
        'BottomRight' { $form.Left = $screen.Right  - $form.Width  - $margin; $form.Top = $screen.Bottom - $form.Height - $margin }
        'BottomLeft'  { $form.Left = $screen.Left   + $margin;              $form.Top = $screen.Bottom - $form.Height - $margin }
        'TopRight'    { $form.Left = $screen.Right  - $form.Width  - $margin; $form.Top = $screen.Top + $margin }
        'TopLeft'     { $form.Left = $screen.Left   + $margin;              $form.Top = $screen.Top + $margin }
        'Center'      { $form.Left = $screen.Left + ($screen.Width - $form.Width)/2; $form.Top = $screen.Top + ($screen.Height - $form.Height)/2 }
    }

    # --- logo (optional) ---
    $lblLogo = $null
    $logoWidth = 0
    if ($Logo) {
        if ($Logo -match '^https?://') {
            $dest = Join-Path $env:TEMP "toast-logo.png"
            try { if (-not (Test-Path $dest)) { Invoke-WebRequest $Logo -OutFile $dest -UseBasicParsing } ; $Logo = $dest } catch { $Logo = "" }
        }
        if (Test-Path $Logo) {
            $lblLogo = New-Object System.Windows.Forms.PictureBox
            $lblLogo.Image = [System.Drawing.Image]::FromFile((Resolve-Path $Logo).Path)
            $lblLogo.SizeMode = 'Zoom'
            $lblLogo.Width  = 32
            $lblLogo.Height = 32
            $lblLogo.Left   = 12
            $lblLogo.Top    = 10
            $lblLogo.BackColor = [System.Drawing.Color]::Transparent
            $form.Controls.Add($lblLogo)
            $logoWidth = 40
        }
    }

    # --- title ---
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text      = $Title
    $lblTitle.ForeColor = [System.Drawing.Color]::White
    $lblTitle.Font      = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
    $lblTitle.AutoSize  = $false
    $lblTitle.Left      = 12 + $logoWidth
    $lblTitle.Top       = 10
    $lblTitle.Width     = $form.Width - $lblTitle.Left - 20
    $lblTitle.Height    = 22
    $lblTitle.BackColor = [System.Drawing.Color]::Transparent
    $form.Controls.Add($lblTitle)

    # --- status ---
    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Text      = $Status
    $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
    $lblStatus.Font      = New-Object System.Drawing.Font('Segoe UI', 9)
    $lblStatus.Left      = 12 + $logoWidth
    $lblStatus.Top       = 34
    $lblStatus.Width     = $form.Width - $lblStatus.Left - 20
    $lblStatus.Height    = 18
    $lblStatus.BackColor = [System.Drawing.Color]::Transparent
    $form.Controls.Add($lblStatus)

    # --- progress bar (custom, painted) ---
    $progressPanel = New-Object System.Windows.Forms.Panel
    $progressPanel.Left       = 12
    $progressPanel.Top        = 56
    $progressPanel.Width      = $form.Width - 24
    $progressPanel.Height     = 10
    $progressPanel.BackColor  = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $progressPanel.Tag        = 0      # current percent
    $progressPanel.Add_Paint({
        param($s, $e)
        $pct   = [double]$s.Tag
        $rect  = $s.ClientRectangle
        $g     = $e.Graphics
        $g.SmoothingMode = 'AntiAlias'
        $brush = New-Object System.Drawing.SolidBrush($script:Accent)
        $fillW = [int]($rect.Width * ($pct / 100.0))
        if ($fillW -gt 0) {
            $g.FillRectangle($brush, 0, 0, $fillW, $rect.Height)
        }
        $brush.Dispose()
    }.GetNewClosure())
    $form.Controls.Add($progressPanel)

    # --- cancel button (optional) ---
    $btnCancel = $null
    if ($Cancel) {
        $btnCancel = New-Object System.Windows.Forms.Button
        $btnCancel.Text      = "Cancel"
        $btnCancel.Left      = $form.Width - 100
        $btnCancel.Top       = 72
        $btnCancel.Width     = 80
        $btnCancel.Height    = 24
        $btnCancel.FlatStyle = 'Flat'
        $btnCancel.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
        $btnCancel.ForeColor = [System.Drawing.Color]::White
        $btnCancel.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
        $form.Controls.Add($btnCancel)
    }

    # --- show (non-blocking) ---
    $form.Show()

    # --- wrapper object ---
    $state = [pscustomobject]@{
        Cancelled = $false
        Form      = $form
        SetProgress = {
            param($Percent, $StatusText)
            if ($null -ne $Percent) { $progressPanel.Tag = [Math]::Max(0, [Math]::Min(100, [double]$Percent)) }
            if ($StatusText)        { $lblStatus.Text = [string]$StatusText }
            $progressPanel.Invalidate()
            [System.Windows.Forms.Application]::DoEvents()
        }.GetNewClosure()
        SetStatus = {
            param($StatusText)
            $lblStatus.Text = [string]$StatusText
            [System.Windows.Forms.Application]::DoEvents()
        }.GetNewClosure()
        Close = {
            try { $form.Close(); $form.Dispose() } catch {}
        }.GetNewClosure()
    }

    if ($btnCancel) {
        $btnCancel.Add_Click({
            $state.Cancelled = $true
            $lblStatus.Text  = "Cancelling..."
            [System.Windows.Forms.Application]::DoEvents()
        }.GetNewClosure())
    }

    # keep UI pumped while caller works
    # (caller must call $p.SetProgress / $p.SetStatus, which pump DoEvents)
    return $state
}
