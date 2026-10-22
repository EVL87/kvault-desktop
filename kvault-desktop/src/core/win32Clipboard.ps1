param(
    [string]$Action = "wipe"
)

Add-Type -AssemblyName System.Windows.Forms

$csharpSource = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class KVaultWin32Clip
{
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint RegisterClipboardFormat(string lpszFormat);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GlobalUnlock(IntPtr hMem);

    private const uint CF_UNICODETEXT = 13;
    private const uint GMEM_MOVEABLE = 0x0002;
    private const uint GMEM_ZEROINIT = 0x0040;
    private const uint GHND = GMEM_MOVEABLE | GMEM_ZEROINIT;

    private static void SetDwordFormat(string formatName, int dwordValue)
    {
        uint fmtId = RegisterClipboardFormat(formatName);
        if (fmtId == 0) return;
        IntPtr hMem = GlobalAlloc(GHND, (UIntPtr)4);
        if (hMem == IntPtr.Zero) return;
        IntPtr ptr = GlobalLock(hMem);
        if (ptr != IntPtr.Zero)
        {
            Marshal.WriteInt32(ptr, dwordValue);
            GlobalUnlock(hMem);
            SetClipboardData(fmtId, hMem);
        }
    }

    /// <summary>
    /// Copia el secreto en el slot activo marcándolo con CanIncludeInClipboardHistory=0
    /// y ExcludeClipboardContentFromMonitorProcessing=1 para que NO entre al historial Win+V.
    /// </summary>
    public static bool SetSecureText(string secret)
    {
        if (secret == null) secret = string.Empty;
        for (int i = 0; i < 15; i++)
        {
            if (OpenClipboard(IntPtr.Zero))
            {
                try
                {
                    EmptyClipboard();
                    SetDwordFormat("ExcludeClipboardContentFromMonitorProcessing", 1);
                    SetDwordFormat("CanIncludeInClipboardHistory", 0);
                    SetDwordFormat("CanUploadToCloudClipboard", 0);
                    SetDwordFormat("Clipboard Viewer Ignore", 1);

                    byte[] bytes = Encoding.Unicode.GetBytes(secret + "\0");
                    IntPtr hText = GlobalAlloc(GHND, (UIntPtr)bytes.Length);
                    if (hText != IntPtr.Zero)
                    {
                        IntPtr pText = GlobalLock(hText);
                        if (pText != IntPtr.Zero)
                        {
                            Marshal.Copy(bytes, 0, pText, bytes.Length);
                            GlobalUnlock(hText);
                            SetClipboardData(CF_UNICODETEXT, hText);
                        }
                    }
                    Array.Clear(bytes, 0, bytes.Length);
                    return true;
                }
                finally
                {
                    CloseClipboard();
                }
            }
            Thread.Sleep(20);
        }
        return false;
    }

    /// <summary>
    /// Limpia ÚNICAMENTE el slot activo del portapapeles (sin tocar el historial Win+V del usuario)
    /// y solo si el texto activo sigue siendo el secreto copiado por KVault (patrón ClearIfOwner).
    /// </summary>
    public static bool WipeActiveSlotIfOwner(string expectedSecret)
    {
        for (int i = 0; i < 15; i++)
        {
            if (OpenClipboard(IntPtr.Zero))
            {
                try
                {
                    if (!string.IsNullOrEmpty(expectedSecret))
                    {
                        IntPtr hData = GetClipboardData(CF_UNICODETEXT);
                        if (hData == IntPtr.Zero)
                        {
                            return false;
                        }
                        string currentText = string.Empty;
                        IntPtr pData = GlobalLock(hData);
                        if (pData != IntPtr.Zero)
                        {
                            try
                            {
                                currentText = Marshal.PtrToStringUni(pData) ?? string.Empty;
                            }
                            finally
                            {
                                GlobalUnlock(hData);
                            }
                        }
                        // Si el usuario ya copió otra cosa o seleccionó otro ítem de Win+V, no tocar su portapapeles
                        if (!string.Equals(currentText, expectedSecret, StringComparison.Ordinal))
                        {
                            return false;
                        }
                    }

                    // Limpiar únicamente el slot activo sin llamar jamás a ClearHistory() de Win+V
                    EmptyClipboard();
                    return true;
                }
                finally
                {
                    CloseClipboard();
                }
            }
            Thread.Sleep(20);
        }
        return false;
    }
}
"@

Add-Type -TypeDefinition $csharpSource -Language CSharp

if ($Action -eq "set") {
    $secret = [Console]::In.ReadToEnd()
    $ok = [KVaultWin32Clip]::SetSecureText($secret)
    if ($ok) { Write-Output "OK" } else { Write-Output "ERR" }
}
elseif ($Action -eq "wipe") {
    $expected = [Console]::In.ReadToEnd()
    $ok = [KVaultWin32Clip]::WipeActiveSlotIfOwner($expected)
    if ($ok) { Write-Output "WIPED" } else { Write-Output "SKIPPED" }
}
elseif ($Action -eq "autotype") {
    $payloadJson = [Console]::In.ReadToEnd()
    $data = ConvertFrom-Json $payloadJson
    Start-Sleep -Milliseconds 220

    switch ($data.mode) {
        'user_only' {
            if ($data.u.Length -gt 0) { [System.Windows.Forms.SendKeys]::SendWait($data.u) }
            break
        }
        'pass_only' {
            if ($data.p.Length -gt 0) { [System.Windows.Forms.SendKeys]::SendWait($data.p) }
            break
        }
        'tab_space' {
            if ($data.u.Length -gt 0) { [System.Windows.Forms.SendKeys]::SendWait($data.u) }
            Start-Sleep -Milliseconds 45
            [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
            Start-Sleep -Milliseconds 45
            if ($data.p.Length -gt 0) { [System.Windows.Forms.SendKeys]::SendWait($data.p) }
            Start-Sleep -Milliseconds 45
            [System.Windows.Forms.SendKeys]::SendWait("{TAB} ")
            break
        }
        'no_submit' {
            if ($data.u.Length -gt 0) { [System.Windows.Forms.SendKeys]::SendWait($data.u) }
            Start-Sleep -Milliseconds 45
            [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
            Start-Sleep -Milliseconds 45
            if ($data.p.Length -gt 0) { [System.Windows.Forms.SendKeys]::SendWait($data.p) }
            break
        }
        default {
            if ($data.u.Length -gt 0) { [System.Windows.Forms.SendKeys]::SendWait($data.u) }
            Start-Sleep -Milliseconds 45
            [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
            Start-Sleep -Milliseconds 45
            if ($data.p.Length -gt 0) { [System.Windows.Forms.SendKeys]::SendWait($data.p) }
            Start-Sleep -Milliseconds 45
            [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
            break
        }
    }

    Write-Output "OK"
}
