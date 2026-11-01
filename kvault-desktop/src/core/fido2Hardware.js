'use strict';

const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
const { ProtectedMemory } = require('./protectedMemory');
const { encryptChaCha20Poly1305, decryptChaCha20Poly1305 } = require('./chacha20poly1305');
const { inspectVaultFileSlot } = require('./vaultFormat');
const {
  execVerifiedPowerShellScript,
  resolveTrustedLinuxBinary,
  execTrustedLinuxBinary,
} = require('./secureExec');

let electronSafeStorage = null;
try {
  const el = require('electron');
  electronSafeStorage = el.safeStorage || null;
} catch {}

const PS_WEBAUTHN_PATH = path.join(__dirname, 'win32WebAuthn.ps1').replace('app.asar', 'app.asar.unpacked');
const RP_ID = 'kvault.local';

/**
 * Obtiene o inicializa un secreto maestro local de 256 bits (almacenado con permisos 0600 en el perfil
 * del usuario) para vincular criptográficamente `wrappingKey` mediante HMAC-SHA256, impidiendo que
 * `wrappingKey` pueda reconstruirse únicamente a partir de datos públicos de la cabecera `.kvlt`.
 */
function getOrCreateLocalHardwareKeySecret() {
  const configDir =
    process.platform === 'win32'
      ? path.join(process.env.LOCALAPPDATA || os.homedir(), 'KVaultDesktop')
      : path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'kvault-desktop');

  const keyFile = path.join(configDir, '.hw_slot_master.key');
  try {
    if (fs.existsSync(keyFile)) {
      const raw = fs.readFileSync(keyFile);
      if (raw.length >= 32) {
        return raw.subarray(0, 32);
      }
    }
    fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
    const newSecret = crypto.randomBytes(32);
    fs.writeFileSync(keyFile, newSecret, { mode: 0o600 });
    return newSecret;
  } catch {
    return crypto.createHash('sha256').update(os.homedir()).update('KVault-Fallback-Local-Key').digest();
  }
}

function deriveHardwareWrappingKey(credentialIdB64, publicKeySpkiB64) {
  const localSecret = getOrCreateLocalHardwareKeySecret();
  try {
    return crypto
      .createHmac('sha256', localSecret)
      .update(Buffer.from(String(credentialIdB64), 'base64'))
      .update(Buffer.from(String(publicKeySpkiB64), 'base64'))
      .update('KVault-Hardware-Slot-Key-v2', 'utf8')
      .digest();
  } finally {
    ProtectedMemory.zeroize(localSecret);
  }
}

async function runWebAuthnScript(action, stdinText = '') {
  const out = await execVerifiedPowerShellScript(PS_WEBAUTHN_PATH, ['-Action', action], {
    timeout: 65000,
    stdinText,
  });
  if (out.startsWith('OK|')) {
    return out.slice(3);
  }
  if (out.startsWith('ERR|')) {
    throw new Error(out.slice(4));
  }
  return out;
}

/**
 * Protección de sobre a nivel de SO (DPAPI en Windows; safeStorage / clave local 0600 en Debian/Ubuntu/Mint).
 */
async function protectEnvelopeWithOsKeyring(envelopeBuf) {
  if (process.platform === 'win32') {
    return runWebAuthnScript('dpapi-protect', envelopeBuf.toString('base64'));
  }
  if (electronSafeStorage && electronSafeStorage.isEncryptionAvailable()) {
    const enc = electronSafeStorage.encryptString(envelopeBuf.toString('base64'));
    return `SAFESTORAGE:${enc.toString('base64')}`;
  }
  return `LOCAL:${envelopeBuf.toString('base64')}`;
}

async function unprotectEnvelopeWithOsKeyring(protectedB64) {
  const str = String(protectedB64 || '');
  if (process.platform === 'win32' && !str.startsWith('SAFESTORAGE:') && !str.startsWith('LOCAL:')) {
    return runWebAuthnScript('dpapi-unprotect', str);
  }
  if (str.startsWith('SAFESTORAGE:')) {
    if (!electronSafeStorage || !electronSafeStorage.isEncryptionAvailable()) {
      throw new Error('El llavero del sistema (libsecret) no está disponible para desencapsular el slot.');
    }
    const raw = Buffer.from(str.slice('SAFESTORAGE:'.length), 'base64');
    return electronSafeStorage.decryptString(raw);
  }
  if (str.startsWith('LOCAL:')) {
    return str.slice('LOCAL:'.length);
  }
  return str;
}

/**
 * Extrae las coordenadas ECDSA P-256 (X, Y) y el AAGUID desde el bloque `authenticatorData`
 * validando que `yMarker` aparezca después del final de la coordenada X (`xIdx + 35`).
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

  const xMarker = Buffer.from([0x21, 0x58, 0x20]);
  const yMarker = Buffer.from([0x22, 0x58, 0x20]);

  const xIdx = coseBytes.indexOf(xMarker);
  if (xIdx === -1 || xIdx + 35 > coseBytes.length) {
    throw new Error('No se encontró la coordenada X P-256 en la clave COSE de la llave física.');
  }

  // Buscar yMarker estrictamente a partir del final de los 32 bytes de X (xIdx + 35)
  // para evitar falsos positivos si los bytes aleatorios de X contienen 0x22 0x58 0x20.
  const yIdx = coseBytes.indexOf(yMarker, xIdx + 35);
  if (yIdx === -1 || yIdx + 35 > coseBytes.length) {
    throw new Error('No se encontró la coordenada Y P-256 en la clave COSE de la llave física.');
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
    publicKeySpkiB64: spkiDer.toString('base64'),
  };
}

/**
 * Verifica criptográficamente la firma ECDSA P-256 producida por la llave física
 * sobre `authenticatorData || SHA256(clientDataJson)` y valida el contador monotónico `signCount`.
 */
function verifyHardwareAssertionSignature({
  publicKeySpkiB64,
  authDataBuf,
  clientDataJson,
  signatureBuf,
  lastSignCount = 0,
}) {
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
  const clientDataHash =
    typeof clientDataJson === 'string'
      ? crypto.createHash('sha256').update(clientDataJson, 'utf8').digest()
      : Buffer.isBuffer(clientDataJson)
      ? clientDataJson
      : crypto.createHash('sha256').update(String(clientDataJson), 'utf8').digest();

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
  if (lastSignCount > 0 && signCount > 0 && signCount <= lastSignCount) {
    throw new Error('Alerta de seguridad FIDO2: el contador de firmas de la llave física retrocedió (posible clonación).');
  }

  return { verified: true, signCount };
}

/**
 * Envuelve un secreto de bóveda vinculándolo al secreto maestro local HMAC-SHA256 + llavero del SO.
 */
async function wrapSecretForHardwareSlot(secretPlainText, credentialIdB64, publicKeySpkiB64) {
  const wrappingKey = deriveHardwareWrappingKey(credentialIdB64, publicKeySpkiB64);
  const nonce = crypto.randomBytes(12);
  const aad = Buffer.from(credentialIdB64, 'base64');
  const plainBuf = Buffer.from(String(secretPlainText), 'utf8');

  try {
    const { ciphertext, authTag } = encryptChaCha20Poly1305(wrappingKey, nonce, plainBuf, aad);
    const envelopeBuf = Buffer.concat([nonce, authTag, ciphertext]);
    try {
      return await protectEnvelopeWithOsKeyring(envelopeBuf);
    } finally {
      ProtectedMemory.zeroize(envelopeBuf);
    }
  } finally {
    ProtectedMemory.zeroize(wrappingKey);
    ProtectedMemory.zeroize(plainBuf);
  }
}

/**
 * Desenvuelve el secreto de bóveda únicamente después de haber verificado con éxito la firma ECDSA P-256.
 */
async function unwrapSecretFromHardwareSlot(wrappedDpapiB64, credentialIdB64, publicKeySpkiB64) {
  const unwrappedB64 = await unprotectEnvelopeWithOsKeyring(wrappedDpapiB64);
  const envelopeBuf = Buffer.from(unwrappedB64, 'base64');

  if (envelopeBuf.length < 28) {
    throw new Error('Sobre criptográfico de llave física corrupto.');
  }

  const nonce = envelopeBuf.subarray(0, 12);
  const authTag = envelopeBuf.subarray(12, 28);
  const ciphertext = envelopeBuf.subarray(28);
  const aad = Buffer.from(credentialIdB64, 'base64');
  const wrappingKey = deriveHardwareWrappingKey(credentialIdB64, publicKeySpkiB64);

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
 * Combina la Contraseña Maestra con el factor secreto de la llave física para el modo `hardware_2fa`.
 */
function combinePasswordAndHardwareFactor(masterPassword, hardwareFactorHex) {
  const keyBuf = Buffer.from(String(hardwareFactorHex), 'hex');
  try {
    return crypto.createHmac('sha256', keyBuf).update(String(masterPassword), 'utf8').digest('hex');
  } finally {
    ProtectedMemory.zeroize(keyBuf);
  }
}

/**
 * Detecta la primera llave física FIDO2 / U2F conectada en Debian / Ubuntu / Linux Mint usando `fido2-token -L`.
 */
async function findLinuxFidoDevice() {
  if (!resolveTrustedLinuxBinary('fido2-token')) {
    throw new Error(
      'Para usar llaves físicas FIDO2/U2F en Debian/Ubuntu/Mint instale fido2-tools (sudo apt install fido2-tools libfido2-udev).'
    );
  }
  const out = await execTrustedLinuxBinary('fido2-token', ['-L'], { timeout: 5000 });
  const firstLine = out
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find(Boolean);
  if (!firstLine) {
    throw new Error('No se detectó ninguna llave física FIDO2/U2F conectada por USB (/dev/hidraw*).');
  }
  const devPath = firstLine.split(':')[0].trim();
  if (!devPath.startsWith('/dev/')) {
    throw new Error(`Ruta de dispositivo FIDO2 inválida: ${devPath}`);
  }
  return devPath;
}

/**
 * Registra una llave física en Windows (`webauthn.dll`) o en Debian/Ubuntu/Mint (`fido2-cred`).
 */
async function enrollHardwareKey(opts = {}) {
  if (process.platform === 'linux') {
    const devPath = await findLinuxFidoDevice();
    const cdhB64 = crypto.randomBytes(32).toString('base64');
    const userIdB64 = crypto.randomBytes(16).toString('base64');
    const stdinLines = `${cdhB64}\n${RP_ID}\n${opts.vaultName || 'KVault_Owner'}\n${userIdB64}\n`;

    const credOut = await execTrustedLinuxBinary('fido2-cred', ['-M', '-i', '-', devPath, 'es256'], {
      stdinText: stdinLines,
      timeout: 60000,
    });
    const lines = credOut.split(/\r?\n/).map((l) => l.trim());
    // Formato de salida de fido2-cred -M: línea 5 = credId (base64), línea 6 = pubKey PEM/Base64
    const credentialIdB64 = lines[4] || '';
    const pubKeyPemLines = lines.slice(5).join('\n');
    if (!credentialIdB64 || !pubKeyPemLines) {
      throw new Error('No se pudo extraer la credencial P-256 desde fido2-cred.');
    }
    const pubKeyObj = crypto.createPublicKey(pubKeyPemLines);
    const spkiDer = pubKeyObj.export({ type: 'spki', format: 'der' });
    return {
      rpId: RP_ID,
      credentialIdB64,
      publicKeySpkiB64: spkiDer.toString('base64'),
      enrolledAt: new Date().toISOString(),
    };
  }

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
    attachmentMode: opts.attachmentMode ?? 2,
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
    credentialIdB64,
    publicKeySpkiB64: parsedKey.publicKeySpkiB64,
    enrolledAt: new Date().toISOString(),
  };
}

/**
 * Solicita tocar la llave física registrada y verifica matemáticamente su firma ECDSA P-256.
 */
async function challengeHardwareKey(hwSlot) {
  if (!hwSlot || !hwSlot.credentialIdB64 || !hwSlot.publicKeySpkiB64) {
    throw new Error('Esta bóveda no tiene un Key Slot de llave física configurado.');
  }

  let verification;

  if (process.platform === 'linux') {
    const devPath = await findLinuxFidoDevice();
    const clientDataHash = crypto.randomBytes(32);
    const stdinLines = `${clientDataHash.toString('base64')}\n${hwSlot.rpId || RP_ID}\n${hwSlot.credentialIdB64}\n`;
    const assertOut = await execTrustedLinuxBinary('fido2-assert', ['-G', '-i', '-', devPath, 'es256'], {
      stdinText: stdinLines,
      timeout: 60000,
    });
    const lines = assertOut.split(/\r?\n/).map((l) => l.trim());
    const authDataBuf = Buffer.from(lines[2] || '', 'base64');
    const signatureBuf = Buffer.from(lines[3] || '', 'base64');

    verification = verifyHardwareAssertionSignature({
      publicKeySpkiB64: hwSlot.publicKeySpkiB64,
      authDataBuf,
      clientDataJson: clientDataHash,
      signatureBuf,
      lastSignCount: hwSlot.lastSignCount || 0,
    });
  } else {
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

    verification = verifyHardwareAssertionSignature({
      publicKeySpkiB64: hwSlot.publicKeySpkiB64,
      authDataBuf,
      clientDataJson,
      signatureBuf,
      lastSignCount: hwSlot.lastSignCount || 0,
    });
  }

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

/**
 * Carga EXCLUSIVAMENTE el Hardware Key Slot incrustado dentro de la cabecera `.kvlt` v2 autenticada por AAD.
 * (Se eliminó el fallback a archivos externos `.hwslot.json` no autenticados).
 */
function loadHardwareSlotForVault(vaultFilePath) {
  if (!vaultFilePath || !fs.existsSync(vaultFilePath)) return null;
  return inspectVaultFileSlot(vaultFilePath);
}

function removeLegacyHardwareSlotFile(vaultFilePath) {
  if (!vaultFilePath) return false;
  const slotPath = `${path.resolve(vaultFilePath)}.hwslot.json`;
  if (fs.existsSync(slotPath)) {
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
