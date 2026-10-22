param(
    [string]$Action = "probe"
)

$csharp = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Win32WebAuthn
{
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("webauthn.dll")]
    public static extern uint WebAuthNGetApiVersionNumber();

    [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr WebAuthNGetErrorName(int hr);

    [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
    public static extern int WebAuthNAuthenticatorMakeCredential(
        IntPtr hWnd,
        ref WEBAUTHN_RP_ENTITY_INFORMATION pRpInformation,
        ref WEBAUTHN_USER_ENTITY_INFORMATION pUserInformation,
        ref WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pPubKeyCredParams,
        ref WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
        ref WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS pWebAuthNMakeCredentialOptions,
        out IntPtr ppWebAuthNCredentialAttestation);

    [DllImport("webauthn.dll")]
    public static extern void WebAuthNFreeCredentialAttestation(IntPtr pWebAuthNCredentialAttestation);

    [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
    public static extern int WebAuthNAuthenticatorGetAssertion(
        IntPtr hWnd,
        [MarshalAs(UnmanagedType.LPWStr)] string pwszRpId,
        ref WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
        ref WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pWebAuthNGetAssertionOptions,
        out IntPtr ppWebAuthNAssertion);

    [DllImport("webauthn.dll")]
    public static extern void WebAuthNFreeAssertion(IntPtr pWebAuthNAssertion);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_RP_ENTITY_INFORMATION
    {
        public uint dwVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszId;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszName;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszIcon;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_USER_ENTITY_INFORMATION
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszName;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszIcon;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszDisplayName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER
    {
        public uint dwVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszCredentialType;
        public int lAlg;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
    {
        public uint cCredentialParameters;
        public IntPtr pCredentialParameters;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CLIENT_DATA
    {
        public uint dwVersion;
        public uint cbClientDataJSON;
        public IntPtr pbClientDataJSON;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszHashAlgId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WEBAUTHN_CREDENTIALS
    {
        public uint cCredentials;
        public IntPtr pCredentials;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WEBAUTHN_EXTENSIONS
    {
        public uint cExtensions;
        public IntPtr pExtensions;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CREDENTIAL
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszCredentialType;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
    {
        public uint dwVersion;
        public uint dwTimeoutMilliseconds;
        public WEBAUTHN_CREDENTIALS CredentialList;
        public WEBAUTHN_EXTENSIONS Extensions;
        public uint dwAuthenticatorAttachment;
        public int bRequireResidentKey;
        public uint dwUserVerificationRequirement;
        public uint dwAttestationConveyancePreference;
        public uint dwFlags;
        public IntPtr pCancellationId;
        public IntPtr pExcludeCredentialList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
    {
        public uint dwVersion;
        public uint dwTimeoutMilliseconds;
        public WEBAUTHN_CREDENTIALS CredentialList;
        public WEBAUTHN_EXTENSIONS Extensions;
        public uint dwAuthenticatorAttachment;
        public uint dwUserVerificationRequirement;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszU2fAppId;
        public IntPtr pbU2fAppId;
        public IntPtr pCancellationId;
        public IntPtr pAllowCredentialList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CREDENTIAL_ATTESTATION
    {
        public uint dwVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszFormatType;
        public uint cbAuthenticatorData;
        public IntPtr pbAuthenticatorData;
        public uint cbAttestation;
        public IntPtr pbAttestation;
        public uint dwAttestationDecodeType;
        public IntPtr pvAttestationDecode;
        public uint cbAttestationObject;
        public IntPtr pbAttestationObject;
        public uint cbCredentialId;
        public IntPtr pbCredentialId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_ASSERTION
    {
        public uint dwVersion;
        public uint cbAuthenticatorData;
        public IntPtr pbAuthenticatorData;
        public uint cbSignature;
        public IntPtr pbSignature;
        public WEBAUTHN_CREDENTIAL Credential;
        public uint cbUserId;
        public IntPtr pbUserId;
    }

    public static string GetErrorString(int hr)
    {
        IntPtr ptr = WebAuthNGetErrorName(hr);
        if (ptr != IntPtr.Zero)
        {
            return Marshal.PtrToStringUni(ptr) ?? ("0x" + hr.ToString("X8"));
        }
        return "0x" + hr.ToString("X8");
    }

    public static string RegisterHardwareKey(string rpId, string userName, string clientDataJson, uint attachmentMode)
    {
        IntPtr hWnd = GetForegroundWindow();

        var rpInfo = new WEBAUTHN_RP_ENTITY_INFORMATION
        {
            dwVersion = 1,
            pwszId = rpId,
            pwszName = "KVault Desktop Safe",
            pwszIcon = null
        };

        byte[] userIdBytes = Encoding.UTF8.GetBytes("kvault-user-" + userName);
        IntPtr pbUserId = Marshal.AllocHGlobal(userIdBytes.Length);
        Marshal.Copy(userIdBytes, 0, pbUserId, userIdBytes.Length);

        var userInfo = new WEBAUTHN_USER_ENTITY_INFORMATION
        {
            dwVersion = 1,
            cbId = (uint)userIdBytes.Length,
            pbId = pbUserId,
            pwszName = userName,
            pwszIcon = null,
            pwszDisplayName = userName
        };

        // Algoritmo -7 = ES256 (ECDSA P-256 con SHA-256), soportado por Flipper Zero U2F y Yubico Security Key C NFC
        var coseParam = new WEBAUTHN_COSE_CREDENTIAL_PARAMETER
        {
            dwVersion = 1,
            pwszCredentialType = "public-key",
            lAlg = -7
        };
        int paramSize = Marshal.SizeOf(typeof(WEBAUTHN_COSE_CREDENTIAL_PARAMETER));
        IntPtr pCoseParam = Marshal.AllocHGlobal(paramSize);
        Marshal.StructureToPtr(coseParam, pCoseParam, false);

        var coseParams = new WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
        {
            cCredentialParameters = 1,
            pCredentialParameters = pCoseParam
        };

        byte[] clientDataBytes = Encoding.UTF8.GetBytes(clientDataJson);
        IntPtr pbClientData = Marshal.AllocHGlobal(clientDataBytes.Length);
        Marshal.Copy(clientDataBytes, 0, pbClientData, clientDataBytes.Length);

        var clientData = new WEBAUTHN_CLIENT_DATA
        {
            dwVersion = 1,
            cbClientDataJSON = (uint)clientDataBytes.Length,
            pbClientDataJSON = pbClientData,
            pwszHashAlgId = "SHA-256"
        };

        // dwAuthenticatorAttachment: 2 = CROSS_PLATFORM (Llave USB/NFC externa: Flipper U2F / Yubico Security Key)
        // dwUserVerificationRequirement: 3 = DISCOURAGED (Permite U2F sin PIN y llaves FIDO con solo toque fisico)
        var options = new WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
        {
            dwVersion = 3,
            dwTimeoutMilliseconds = 60000,
            dwAuthenticatorAttachment = attachmentMode,
            bRequireResidentKey = 0,
            dwUserVerificationRequirement = 3,
            dwAttestationConveyancePreference = 1,
            dwFlags = 0,
            pCancellationId = IntPtr.Zero,
            pExcludeCredentialList = IntPtr.Zero
        };

        IntPtr ppAttestation = IntPtr.Zero;
        try
        {
            int hr = WebAuthNAuthenticatorMakeCredential(
                hWnd,
                ref rpInfo,
                ref userInfo,
                ref coseParams,
                ref clientData,
                ref options,
                out ppAttestation);

            if (hr != 0)
            {
                throw new Exception("WebAuthN MakeCredential fallo (" + GetErrorString(hr) + ")");
            }

            var att = (WEBAUTHN_CREDENTIAL_ATTESTATION)Marshal.PtrToStructure(
                ppAttestation,
                typeof(WEBAUTHN_CREDENTIAL_ATTESTATION));

            byte[] credId = new byte[att.cbCredentialId];
            Marshal.Copy(att.pbCredentialId, credId, 0, (int)att.cbCredentialId);

            byte[] authData = new byte[att.cbAuthenticatorData];
            Marshal.Copy(att.pbAuthenticatorData, authData, 0, (int)att.cbAuthenticatorData);

            return Convert.ToBase64String(credId) + "|" + Convert.ToBase64String(authData);
        }
        finally
        {
            if (ppAttestation != IntPtr.Zero) WebAuthNFreeCredentialAttestation(ppAttestation);
            Marshal.FreeHGlobal(pbUserId);
            Marshal.FreeHGlobal(pCoseParam);
            Marshal.FreeHGlobal(pbClientData);
        }
    }

    public static string AssertHardwareKey(string rpId, string credentialIdB64, string clientDataJson, uint attachmentMode)
    {
        IntPtr hWnd = GetForegroundWindow();

        byte[] credIdBytes = Convert.FromBase64String(credentialIdB64);
        IntPtr pbCredId = Marshal.AllocHGlobal(credIdBytes.Length);
        Marshal.Copy(credIdBytes, 0, pbCredId, credIdBytes.Length);

        var cred = new WEBAUTHN_CREDENTIAL
        {
            dwVersion = 1,
            cbId = (uint)credIdBytes.Length,
            pbId = pbCredId,
            pwszCredentialType = "public-key"
        };

        int credSize = Marshal.SizeOf(typeof(WEBAUTHN_CREDENTIAL));
        IntPtr pCred = Marshal.AllocHGlobal(credSize);
        Marshal.StructureToPtr(cred, pCred, false);

        byte[] clientDataBytes = Encoding.UTF8.GetBytes(clientDataJson);
        IntPtr pbClientData = Marshal.AllocHGlobal(clientDataBytes.Length);
        Marshal.Copy(clientDataBytes, 0, pbClientData, clientDataBytes.Length);

        var clientData = new WEBAUTHN_CLIENT_DATA
        {
            dwVersion = 1,
            cbClientDataJSON = (uint)clientDataBytes.Length,
            pbClientDataJSON = pbClientData,
            pwszHashAlgId = "SHA-256"
        };

        var options = new WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
        {
            dwVersion = 1,
            dwTimeoutMilliseconds = 60000,
            CredentialList = new WEBAUTHN_CREDENTIALS
            {
                cCredentials = 1,
                pCredentials = pCred
            },
            dwAuthenticatorAttachment = attachmentMode,
            dwUserVerificationRequirement = 3,
            dwFlags = 0,
            pwszU2fAppId = null,
            pbU2fAppId = IntPtr.Zero,
            pCancellationId = IntPtr.Zero,
            pAllowCredentialList = IntPtr.Zero
        };

        IntPtr ppAssertion = IntPtr.Zero;
        try
        {
            int hr = WebAuthNAuthenticatorGetAssertion(
                hWnd,
                rpId,
                ref clientData,
                ref options,
                out ppAssertion);

            if (hr != 0)
            {
                throw new Exception("WebAuthN GetAssertion fallo (" + GetErrorString(hr) + ")");
            }

            var assertion = (WEBAUTHN_ASSERTION)Marshal.PtrToStructure(
                ppAssertion,
                typeof(WEBAUTHN_ASSERTION));

            byte[] authData = new byte[assertion.cbAuthenticatorData];
            Marshal.Copy(assertion.pbAuthenticatorData, authData, 0, (int)assertion.cbAuthenticatorData);

            byte[] sig = new byte[assertion.cbSignature];
            Marshal.Copy(assertion.pbSignature, sig, 0, (int)assertion.cbSignature);

            return Convert.ToBase64String(authData) + "|" + Convert.ToBase64String(sig);
        }
        finally
        {
            if (ppAssertion != IntPtr.Zero) WebAuthNFreeAssertion(ppAssertion);
            Marshal.FreeHGlobal(pbCredId);
            Marshal.FreeHGlobal(pCred);
            Marshal.FreeHGlobal(pbClientData);
        }
    }
}
"@

Add-Type -TypeDefinition $csharp -Language CSharp
Add-Type -AssemblyName System.Security

if ($Action -eq "probe") {
    $ver = [Win32WebAuthn]::WebAuthNGetApiVersionNumber()
    Write-Output "OK|$ver"
}
elseif ($Action -eq "register") {
    $raw = [Console]::In.ReadToEnd()
    $cfg = ConvertFrom-Json $raw
    try {
        $res = [Win32WebAuthn]::RegisterHardwareKey(
            [string]$cfg.rpId,
            [string]$cfg.userName,
            [string]$cfg.clientDataJson,
            [uint32]$cfg.attachmentMode
        )
        Write-Output "OK|$res"
    } catch {
        Write-Output ("ERR|" + $_.Exception.Message)
    }
}
elseif ($Action -eq "assert") {
    $raw = [Console]::In.ReadToEnd()
    $cfg = ConvertFrom-Json $raw
    try {
        $res = [Win32WebAuthn]::AssertHardwareKey(
            [string]$cfg.rpId,
            [string]$cfg.credentialIdB64,
            [string]$cfg.clientDataJson,
            [uint32]$cfg.attachmentMode
        )
        Write-Output "OK|$res"
    } catch {
        Write-Output ("ERR|" + $_.Exception.Message)
    }
}
elseif ($Action -eq "dpapi-protect") {
    $rawB64 = [Console]::In.ReadToEnd().Trim()
    $plain = [Convert]::FromBase64String($rawB64)
    $entropy = [Text.Encoding]::UTF8.GetBytes("KVault-FIDO2-Hardware-Slot-v1")
    $enc = [System.Security.Cryptography.ProtectedData]::Protect(
        $plain,
        $entropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    Write-Output ("OK|" + [Convert]::ToBase64String($enc))
}
elseif ($Action -eq "dpapi-unprotect") {
    $rawB64 = [Console]::In.ReadToEnd().Trim()
    $enc = [Convert]::FromBase64String($rawB64)
    $entropy = [Text.Encoding]::UTF8.GetBytes("KVault-FIDO2-Hardware-Slot-v1")
    $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $enc,
        $entropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    Write-Output ("OK|" + [Convert]::ToBase64String($plain))
}
