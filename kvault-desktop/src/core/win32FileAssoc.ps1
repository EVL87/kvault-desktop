param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [Parameter(Mandatory=$true)][string]$IconFile,
    [string]$AppDir = ""
)

$ErrorActionPreference = 'Stop'

# Registra la extensión .kvlt en HKCU\Software\Classes (sin requerir permisos de Administrador)
$extKey = 'HKCU:\Software\Classes\.kvlt'
$progId = 'KVault.Container'
$progKey = "HKCU:\Software\Classes\$progId"
$iconKey = "$progKey\DefaultIcon"
$cmdKey = "$progKey\shell\open\command"

$openCommand = if ([string]::IsNullOrWhiteSpace($AppDir)) {
    "`"$ExePath`" `"%1`""
} else {
    "`"$ExePath`" `"$AppDir`" `"%1`""
}

$iconValue = "`"$IconFile`",0"

if (-not (Test-Path $extKey)) { New-Item -Path $extKey -Force | Out-Null }
Set-ItemProperty -Path $extKey -Name '(Default)' -Value $progId

if (-not (Test-Path $progKey)) { New-Item -Path $progKey -Force | Out-Null }
Set-ItemProperty -Path $progKey -Name '(Default)' -Value 'Bóveda Cifrada KVault (.kvlt)'

if (-not (Test-Path $iconKey)) { New-Item -Path $iconKey -Force | Out-Null }
Set-ItemProperty -Path $iconKey -Name '(Default)' -Value $iconValue

if (-not (Test-Path $cmdKey)) { New-Item -Path $cmdKey -Force | Out-Null }
Set-ItemProperty -Path $cmdKey -Name '(Default)' -Value $openCommand

# Notificar a Windows Explorer (SHChangeNotify SHCNE_ASSOCCHANGED) para refrescar el icono de los archivos .kvlt inmediatamente
$csharp = @"
using System;
using System.Runtime.InteropServices;
public static class ShellNotify {
    [DllImport("shell32.dll")]
    public static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);
    public static void Refresh() {
        SHChangeNotify(0x08000000, 0x0000, IntPtr.Zero, IntPtr.Zero);
    }
}
"@

Add-Type -TypeDefinition $csharp -Language CSharp
[ShellNotify]::Refresh()
Write-Output "OK|ASSOCIATED|$iconValue|$openCommand"
