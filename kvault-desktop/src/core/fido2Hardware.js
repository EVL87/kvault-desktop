'use strict';

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { ProtectedMemory } = require('./protectedMemory');
const { encryptChaCha20Poly1305, decryptChaCha20Poly1305 } = require('./chacha20poly1305');
const { inspectVaultFileSlot } = require('./vaultFormat');

const PS_WEBAUTHN_PATH = path.join(__dirname, 'win32WebAuthn.ps1');
const RP_ID = 'kvault.local';

/**
 * Módulo de Llaves Físicas por Hardware FIDO2 / U2F (CTAP1 / CTAP2)
 * Compatible con:
 * - Yubico Security Key C NFC (FIDO2 / U2F)
 * - Flipper Zero (Modo USB -> U2F)
 * - YubiKey Serie 5 / SoloKeys / Nitrokey / Feitian
 *
 * Modos soportados (100% configurables por el usuario):
 * 1. `password_only`: Solo Contraseña Maestra (por defecto).
 * 2. `hardware_passwordless`: Desbloqueo con 1 toque en la llave física (sin escribir contraseña),
 *    conservando la contraseña maestra como respaldo de emergencia.
 * 3. `hardware_2fa`: Doble factor criptográfico obligatorio (Contraseña Maestra + Toque físico en llave FIDO/U2F).
 */

function runWebAuthnScript(action, stdinText = '') {
  return new Promise((resolve, reject) => {
    const child = execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', PS_WEBAUTHN_PATH, '-Action', action],
      { windowsHide: true, timeout: 65000 },
      (err, stdout, stderr) => {
        const out = String(stdout || '').trim();
        if (out.startsWith('OK|')) {
          return resolve(out.slice(3));
        }
        if (out.startsWith('ERR|')) {
          return reject(new Error(out.slice(4)));
        }
        if (err) {
          return reject(new Error(stderr || err.message));
        }
        resolve(out);
      }
    );

    if (stdinText) {
      const buf = Buffer.from(String(stdinText), 'utf8');
      try {
        child.stdin.write(buf);
        child.stdin.end();
      } finally {
        ProtectedMemory.zeroize(buf);
      }
    } else {
      child.stdin.end();
    }
  });
}

/**
 * Extrae las coordenadas ECDSA P-256 (X, Y) y el AAGUID desde el bloque `authenticatorData`
 * devuelto por `WebAuthNAuthenticatorMakeCredential` y construye una clave pública SPKI DER.
 *
 * Estructura WebAuthn AuthenticatorData (W3C Section 6.1):
 * - [0..31]  32 bytes : rpIdHash
 * - [32]     1 byte   : flags (bit 0 = UP, bit 6 = AT)
 * - [33..36] 4 bytes  : signCount
 * - [37..52] 16 bytes : AAGUID (0000... en U2F/Flipper Zero; GUID del fabricante en FIDO2/Yubico)
 * - [53..54] 2 bytes  : credentialIdLength (UInt16BE)
 * - [55..55+L-1]      : credentialId
 * - [55+L..end]       : COSE_Key CBOR map
 */
function parseCoseP256PublicKeyFromAuthData(authDataBuf) {
  if (!Buffer.isBuffer(authDataBuf) || authDataBuf.length < 55) {
    throw new Error('AuthenticatorData demasiado corto para contener credencial FIDO2/U2F.');
  }

  const flags = authDataBuf[32];
  const hasAttestedCredData = (flags & 0x40) !== 0;
  if (!hasAttestedCredData) {
    throw new Error('La respuesta de la llave física no incluye AttestedCredentialData.');
  }

  const aaguidHex = authDataBuf.subarray(37, 53).toString('hex');
  const credIdLen = authDataBuf.readUInt16BE(53);
  const coseOffset = 55 + credIdLen;

  if (authDataBuf.length <= coseOffset + 64) {
    throw new Error('Bloque COSE_Key truncado en AuthenticatorData.');
  }

  const coseBytes = authDataBuf.subarray(coseOffset);

  // En CBOR COSE_Key para ES256 (P-256):
  // Key -2 (coordenada X, 32 bytes) se codifica como: 0x21 0x58 0x20 <32 bytes X>
  // Key -3 (coordenada Y, 32 bytes) se codifica como: 0x22 0x58 0x20 <32 bytes Y>
  const xMarker = Buffer.from([0x21, 0x58, 0x20]);
  const yMarker = Buffer.from([0x22, 0x58, 0x20]);

  const xIdx = coseBytes.indexOf(xMarker);
  const yIdx = coseBytes.indexOf(yMarker);

  if (xIdx === -1 || yIdx === -1 || xIdx + 35 > coseBytes.length || yIdx + 35 > coseBytes.length) {
    throw new Error('No se encontraron las coordenadas P-256 (X, Y) en la clave COSE de la llave física.');
  }

  const xCoord = coseBytes.subarray(xIdx + 3, xIdx + 35);
  const yCoord = coseBytes.subarray(yIdx + 3, yIdx + 35);

  const pubKeyObj = crypto.createPublicKey({
    format: 'jwk',
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: xCoord.toString('base64url'),
      y: yCoord.toString('base64url'),
    },
  });

  const spkiDer = pubKeyObj.export({ type: 'spki', format: 'der' });

  return {
    aaguidHex,
    protocolHint: aaguidHex === '00000000000000000000000000000000' ? 'FIDO U2F (CTAP1 / Flipper / Security Key)' : `FIDO2 (CTAP2 AAGUID: ${aaguidHex.slice(0, 8)}…)`,
    publicKeySpkiB64: spkiDer.toString('base64'),
  };
}

/**
 * Verifica criptográficamente la firma ECDSA P-256 producida por la llave física
 * (Yubico Security Key C NFC o Flipper Zero U2F) sobre `authenticatorData || SHA256(clientDataJson)`.
 */
function verifyHardwareAssertionSignature({ publicKeySpkiB64, authDataBuf, clientDataJson, signatureBuf }) {
  if (!Buffer.isBuffer(authDataBuf) || authDataBuf.length < 37) {
    throw new Error('AuthenticatorData inválido en respuesta de llave física.');
  }

  // 1. Verificar Hash del RP ID ("kvault.local")
  const expectedRpIdHash = crypto.createHash('sha256').update(RP_ID, 'utf8').digest();
  const actualRpIdHash = authDataBuf.subarray(0, 32);
  if (!crypto.timingSafeEqual(expectedRpIdHash, actualRpIdHash)) {
    throw new Error('El RP ID firmado por la llave física no coincide con KVault.');
  }

  // 2. Verificar bandera de Presencia Física de Usuario (UP = bit 0)
  const flags = authDataBuf[32];
  if ((flags & 0x01) === 0) {
    throw new Error('La llave física no confirmó presencia de usuario (toque físico requerido).');
  }

  // 3. Verificar firma ECDSA P-256 (SHA-256) sobre authData || SHA256(clientDataJSON)
  const clientDataHash = crypto.createHash('sha256').update(clientDataJson, 'utf8').digest();
  const signedPayload = Buffer.concat([authDataBuf, clientDataHash]);

  const pubKey = crypto.createPublicKey({
    key: Buffer.from(publicKeySpkiB64, 'base64'),
    format: 'der',
    type: 'spki',
  });

  const isValid = crypto.verify('sha256', signedPayload, pubKey, signatureBuf);
  if (!isValid) {
    throw new Error('Fallo de verificación criptográfica: la firma ECDSA P-256 de la llave física es inválida.');
  }

  const signCount = authDataBuf.readUInt32BE(33);
  return { verified: true, signCount };
}

/**
 * Envuelve un secreto de bóveda vinculándolo a la llave física registrada + DPAPI del equipo.
 */
async function wrapSecretForHardwareSlot(secretPlainText, credentialIdB64, publicKeySpkiB64) {
  const wrappingKey = crypto
    .createHash('sha256')
    .update(Buffer.from(credentialIdB64, 'base64'))
    .update(Buffer.from(publicKeySpkiB64, 'base64'))
    .update('KVault-Hardware-Slot-Key-v1', 'utf8')
    .digest();

  const nonce = crypto.randomBytes(12);
  const aad = Buffer.from(credentialIdB64, 'base64');
  const plainBuf = Buffer.from(String(secretPlainText), 'utf8');

  try {
    const { ciphertext, authTag } = encryptChaCha20Poly1305(wrappingKey, nonce, plainBuf, aad);
    const envelopeBuf = Buffer.concat([nonce, authTag, ciphertext]);
    const dpapiProtectedB64 = await runWebAuthnScript('dpapi-protect', envelopeBuf.toString('base64'));
    ProtectedMemory.zeroize(envelopeBuf);
    return dpapiProtectedB64;
  } finally {
    ProtectedMemory.zeroize(wrappingKey);
    ProtectedMemory.zeroize(plainBuf);
  }
}

/**
 * Desenvuelve el secreto de bóveda únicamente después de haber verificado con éxito la firma
 * ECDSA P-256 de la llave física.
 */
async function unwrapSecretFromHardwareSlot(wrappedDpapiB64, credentialIdB64, publicKeySpkiB64) {
  const unwrappedB64 = await runWebAuthnScript('dpapi-unprotect', wrappedDpapiB64);
  const envelopeBuf = Buffer.from(unwrappedB64, 'base64');

  if (envelopeBuf.length < 28) {
    throw new Error('Sobre criptográfico de llave física corrupto.');
  }

  const nonce = envelopeBuf.subarray(0, 12);
  const authTag = envelopeBuf.subarray(12, 28);
  const ciphertext = envelopeBuf.subarray(28);
  const aad = Buffer.from(credentialIdB64, 'base64');

  const wrappingKey = crypto
    .createHash('sha256')
    .update(Buffer.from(credentialIdB64, 'base64'))
    .update(Buffer.from(publicKeySpkiB64, 'base64'))
    .update('KVault-Hardware-Slot-Key-v1', 'utf8')
    .digest();

  let plainBuf = null;
  try {
    plainBuf = decryptChaCha20Poly1305(wrappingKey, nonce, ciphertext, authTag, aad);
    return plainBuf.toString('utf8');
  } finally {
    ProtectedMemory.zeroize(wrappingKey);
    ProtectedMemory.zeroize(envelopeBuf);
    ProtectedMemory.zeroize(plainBuf);
  }
}

/**
 * Combina la Contraseña Maestra con el factor secreto de la llave física para el modo Híbrido 2FA (`hardware_2fa`).
 */
function combinePasswordAndHardwareFactor(masterPassword, hardwareFactorHex) {
  return crypto
    .createHmac('sha256', Buffer.from(String(hardwareFactorHex), 'hex'))
    .update(String(masterPassword), 'utf8')
    .digest('hex');
}

/**
 * Registra una llave física (Yubico Security Key C NFC / Flipper Zero U2F) mediante `webauthn.dll`.
 *
 * @param {object} opts
 * @param {string} [opts.vaultName='KVault']
 * @param {string} [opts.deviceLabel='Yubico / Flipper U2F']
 * @param {number} [opts.attachmentMode=2] 2 = Llave Externa USB/NFC (Cross-Platform), 0 = Cualquiera
 */
async function enrollHardwareKey(opts = {}) {
  const challenge = crypto.randomBytes(32).toString('base64url');
  const clientDataJson = JSON.stringify({
    type: 'webauthn.create',
    challenge,
    origin: `https://${RP_ID}`,
    crossOrigin: false,
  });

  const payload = JSON.stringify({
    rpId: RP_ID,
    userName: opts.vaultName || 'KVault_Owner',
    clientDataJson,
    attachmentMode: opts.attachmentMode ?? 2, // 2 = Exige llave externa USB/NFC (Yubico Security Key / Flipper U2F)
  });

  const rawResult = await runWebAuthnScript('register', payload);
  const [credentialIdB64, authDataB64] = rawResult.split('|');
  if (!credentialIdB64 || !authDataB64) {
    throw new Error('No se recibió credencial válida desde la llave física.');
  }

  const authDataBuf = Buffer.from(authDataB64, 'base64');
  const parsedKey = parseCoseP256PublicKeyFromAuthData(authDataBuf);

  return {
    rpId: RP_ID,
    deviceLabel: opts.deviceLabel || 'Llave Física FIDO2 / U2F',
    credentialIdB64,
    publicKeySpkiB64: parsedKey.publicKeySpkiB64,
    aaguidHex: parsedKey.aaguidHex,
    protocolHint: parsedKey.protocolHint,
    enrolledAt: new Date().toISOString(),
  };
}

/**
 * Solicita tocar la llave física registrada (Yubico Security Key C NFC / Flipper Zero U2F)
 * y verifica matemáticamente su firma ECDSA P-256 contra la clave pública del Key Slot.
 */
async function challengeHardwareKey(hwSlot) {
  if (!hwSlot || !hwSlot.credentialIdB64 || !hwSlot.publicKeySpkiB64) {
    throw new Error('Esta bóveda no tiene un Key Slot de llave física configurado.');
  }

  const challenge = crypto.randomBytes(32).toString('base64url');
  const clientDataJson = JSON.stringify({
    type: 'webauthn.get',
    challenge,
    origin: `https://${RP_ID}`,
    crossOrigin: false,
  });

  const payload = JSON.stringify({
    rpId: hwSlot.rpId || RP_ID,
    credentialIdB64: hwSlot.credentialIdB64,
    clientDataJson,
    attachmentMode: 2,
  });

  const rawResult = await runWebAuthnScript('assert', payload);
  const [authDataB64, signatureB64] = rawResult.split('|');
  if (!authDataB64 || !signatureB64) {
    throw new Error('Respuesta incompleta de la llave física.');
  }

  const authDataBuf = Buffer.from(authDataB64, 'base64');
  const signatureBuf = Buffer.from(signatureB64, 'base64');

  const verification = verifyHardwareAssertionSignature({
    publicKeySpkiB64: hwSlot.publicKeySpkiB64,
    authDataBuf,
    clientDataJson,
    signatureBuf,
  });

  // Una vez verificada la firma ECDSA P-256 del hardware, desenvolvemos el secreto del slot
  const slotSecret = await unwrapSecretFromHardwareSlot(
    hwSlot.wrappedSecretB64,
    hwSlot.credentialIdB64,
    hwSlot.publicKeySpkiB64
  );

  return {
    verified: verification.verified,
    signCount: verification.signCount,
    slotSecret,
  };
}

function getHardwareSlotPath(vaultFilePath) {
  if (!vaultFilePath) return null;
  return `${path.resolve(vaultFilePath)}.hwslot.json`;
}

/**
 * Carga el Hardware Key Slot incrustado en binario dentro del propio archivo `.kvlt`.
 * Si encuentra un archivo `.hwslot.json` heredado junto al `.kvlt`, lo lee como respaldo para migración automática.
 */
function loadHardwareSlotForVault(vaultFilePath) {
  if (!vaultFilePath || !fs.existsSync(vaultFilePath)) return null;

  const embeddedSlot = inspectVaultFileSlot(vaultFilePath);
  if (embeddedSlot) {
    return embeddedSlot;
  }

  // Respaldo de migración automática si existe un archivo .hwslot.json previo
  const legacySlotPath = getHardwareSlotPath(vaultFilePath);
  if (legacySlotPath && fs.existsSync(legacySlotPath)) {
    try {
      return JSON.parse(fs.readFileSync(legacySlotPath, 'utf8'));
    } catch {
      return null;
    }
  }
  return null;
}

function removeLegacyHardwareSlotFile(vaultFilePath) {
  const slotPath = getHardwareSlotPath(vaultFilePath);
  if (slotPath && fs.existsSync(slotPath)) {
    try {
      fs.unlinkSync(slotPath);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

module.exports = {
  RP_ID,
  parseCoseP256PublicKeyFromAuthData,
  verifyHardwareAssertionSignature,
  wrapSecretForHardwareSlot,
  unwrapSecretFromHardwareSlot,
  combinePasswordAndHardwareFactor,
  enrollHardwareKey,
  challengeHardwareKey,
  loadHardwareSlotForVault,
  removeLegacyHardwareSlotFile,
};
