'use strict';

const crypto = require('node:crypto');
const zlib = require('node:zlib');
const fs = require('node:fs');
const path = require('node:path');
const { ProtectedMemory } = require('./protectedMemory');
const { encryptChaCha20Poly1305, decryptChaCha20Poly1305 } = require('./chacha20poly1305');

/**
 * Especificación del Formato Binario Unificado `.kvlt` (KVault Container Format v1 / v2)
 *
 * Características de diseño:
 * 1. Contenedor único en disco (`.kvlt`): incluye tanto el árbol de credenciales cifrado como
 *    el Key Slot opcional de Llave Física FIDO2 / U2F incrustado en binario dentro de la cabecera,
 *    sin generar archivos `.json` secundarios.
 * 2. Cabecera binaria + Hardware Key Slot autenticados mediante AEAD Additional Authenticated Data (AAD).
 *    Si se altera 1 solo bit de la cabecera o del Key Slot FIDO2/U2F, la verificación de etiqueta AEAD
 *    rechaza el contenedor inmediatamente antes de descomprimir el payload.
 * 3. Cifrado AEAD seleccionable:
 *    - `chacha20-poly1305` (ID = 0x01, RFC 8439)
 *    - `aes-256-gcm`       (ID = 0x02, NIST SP 800-38D)
 * 4. Derivación de clave resistente a GPU/ASIC mediante Scrypt de alta memoria
 *    (N=16384, r=8, p=1) combinando Contraseña Maestra + KeyFile opcional,
 *    con limpieza determinista `zeroize` de los buffers de clave derivados.
 * 5. Guardado transaccional atómico (`.tmp` + `fsync` + `rename`) para prevenir
 *    corrupción ante cortes de energía o cierres inesperados.
 *
 * Estructura binaria del archivo `.kvlt` (v2 unificado):
 * - [0..3]       4 bytes : Magic ASCII "KVLT" (0x4B 0x56 0x4C 0x54)
 * - [4]          1 byte  : Versión del formato (0x02; rétrocompatible en lectura con 0x01)
 * - [5]          1 byte  : ID del Cipher AEAD (0x01 = ChaCha20-Poly1305, 0x02 = AES-256-GCM)
 * - [6..9]       4 bytes : Parámetro KDF N (UInt32LE, ej. 16384)
 * - [10..11]     2 bytes : Parámetro KDF r (UInt16LE, ej. 8)
 * - [12..13]     2 bytes : Parámetro KDF p (UInt16LE, ej. 1)
 * - [14..45]     32 bytes: Salt criptográfico aleatorio (256 bits)
 * - [46..57]     12 bytes: Nonce / IV único de 96 bits para AEAD
 * - [58..61]     4 bytes : Longitud H del Key Slot binario FIDO2/U2F (UInt32LE; 0 si es Solo Contraseña)
 * - [62..62+H-1] H bytes : Bloque binario comprimido del Key Slot FIDO2/U2F
 * - [62+H..77+H] 16 bytes: Auth Tag AEAD (Poly1305 / GCM Tag de 128 bits)
 * - [78+H..N]    Variable: Payload comprimido con GZip y cifrado con AEAD
 *
 * Todos los bytes [0 .. 62+H-1] se autentican como AAD dentro del cifrado AEAD.
 */

const MAGIC = Buffer.from('KVLT', 'ascii');
const FORMAT_VERSION_V1 = 0x01;
const FORMAT_VERSION_V2 = 0x02;

const CIPHERS = {
  'chacha20-poly1305': { id: 0x01, name: 'ChaCha20-Poly1305 (RFC 8439)' },
  'aes-256-gcm': { id: 0x02, name: 'AES-256-GCM (NIST SP 800-38D)' },
};

const CIPHER_BY_ID = {
  0x01: 'chacha20-poly1305',
  0x02: 'aes-256-gcm',
};

const DEFAULT_KDF_PARAMS = {
  N: 16384,
  r: 8,
  p: 1,
};

/**
 * Codifica un objeto Hardware Key Slot a un bloque binario comprimido con DeflateRaw.
 */
function encodeHardwareSlotBinary(hwSlot) {
  if (!hwSlot || typeof hwSlot !== 'object' || !hwSlot.credentialIdB64) {
    return Buffer.alloc(0);
  }
  const rawJson = Buffer.from(JSON.stringify(hwSlot), 'utf8');
  try {
    return zlib.deflateRawSync(rawJson, { level: 9 });
  } finally {
    ProtectedMemory.zeroize(rawJson);
  }
}

/**
 * Decodifica un bloque binario de Hardware Key Slot desde la cabecera `.kvlt`.
 */
function decodeHardwareSlotBinary(slotBuf) {
  if (!Buffer.isBuffer(slotBuf) || slotBuf.length === 0) {
    return null;
  }
  const inflated = zlib.inflateRawSync(slotBuf);
  try {
    return JSON.parse(inflated.toString('utf8'));
  } finally {
    ProtectedMemory.zeroize(inflated);
  }
}

/**
 * Inspecciona únicamente la cabecera pública y el Key Slot FIDO2/U2F incrustado en un archivo `.kvlt`
 * sin necesidad de descifrar el payload aún.
 */
function inspectVaultFileSlot(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return null;
  const buf = fs.readFileSync(filePath);
  if (buf.length < 74 || !buf.subarray(0, 4).equals(MAGIC)) return null;

  const version = buf.readUInt8(4);
  if (version === FORMAT_VERSION_V1) {
    return null;
  }
  if (version === FORMAT_VERSION_V2 && buf.length >= 78) {
    const hwSlotLen = buf.readUInt32LE(58);
    if (hwSlotLen > 0 && buf.length >= 62 + hwSlotLen + 16) {
      const slotSlice = buf.subarray(62, 62 + hwSlotLen);
      return decodeHardwareSlotBinary(slotSlice);
    }
  }
  return null;
}

/**
 * Combina contraseña maestra y archivo de llave opcional en una semilla compuesta de 512 bits.
 * @param {string} masterPassword
 * @param {string|null} keyFilePath
 * @returns {Buffer} Semilla compuesta de 64 bytes (se limpia con zeroize tras usarse)
 */
function buildCompositeKeyMaterial(masterPassword, keyFilePath = null) {
  const pwdBuf = Buffer.from(String(masterPassword ?? ''), 'utf8');
  const pwdHash = crypto.createHash('sha256').update(pwdBuf).digest();
  ProtectedMemory.zeroize(pwdBuf);

  let keyFileHash = Buffer.alloc(32, 0);
  if (keyFilePath && fs.existsSync(keyFilePath)) {
    const fileBytes = fs.readFileSync(keyFilePath);
    keyFileHash = crypto.createHash('sha256').update(fileBytes).digest();
    ProtectedMemory.zeroize(fileBytes);
  }

  try {
    return crypto.createHash('sha512').update(pwdHash).update(keyFileHash).digest();
  } finally {
    ProtectedMemory.zeroize(pwdHash);
    ProtectedMemory.zeroize(keyFileHash);
  }
}

/**
 * Deriva la clave de 256 bits (32 bytes) a partir del CompositeKey y el Salt de 32 bytes.
 */
function deriveVaultKey(masterPassword, keyFilePath, salt, kdfParams = DEFAULT_KDF_PARAMS) {
  const compositeMaterial = buildCompositeKeyMaterial(masterPassword, keyFilePath);
  try {
    const maxmem = Math.max(64 * 1024 * 1024, 128 * kdfParams.N * kdfParams.r * 2);
    return crypto.scryptSync(compositeMaterial, salt, 32, {
      N: kdfParams.N,
      r: kdfParams.r,
      p: kdfParams.p,
      maxmem,
    });
  } finally {
    ProtectedMemory.zeroize(compositeMaterial);
  }
}

/**
 * Serializa y cifra una bóveda en el formato binario unificado `.kvlt` v2.
 * @param {object} vaultObject Objeto de bóveda con grupos, entradas y metadatos
 * @param {string} masterPassword
 * @param {object} options
 * @returns {Buffer}
 */
function serializeVaultToBuffer(vaultObject, masterPassword, options = {}) {
  const cipherName = CIPHERS[options.cipher] ? options.cipher : 'chacha20-poly1305';
  const cipherId = CIPHERS[cipherName].id;
  const kdfParams = options.kdfParams || DEFAULT_KDF_PARAMS;
  const keyFilePath = options.keyFilePath || null;
  const hwSlotBuf = encodeHardwareSlotBinary(options.hardwareSlot || null);

  const salt = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const derivedKey = deriveVaultKey(masterPassword, keyFilePath, salt, kdfParams);

  // Construir cabecera AAD unificada (62 bytes fijos + H bytes del Key Slot binario)
  const aadHeader = Buffer.alloc(62 + hwSlotBuf.length);
  MAGIC.copy(aadHeader, 0); // [0..3] "KVLT"
  aadHeader.writeUInt8(FORMAT_VERSION_V2, 4); // [4] Version = 2
  aadHeader.writeUInt8(cipherId, 5); // [5] Cipher ID
  aadHeader.writeUInt32LE(kdfParams.N, 6); // [6..9] N
  aadHeader.writeUInt16LE(kdfParams.r, 10); // [10..11] r
  aadHeader.writeUInt16LE(kdfParams.p, 12); // [12..13] p
  salt.copy(aadHeader, 14); // [14..45] 32-byte salt
  nonce.copy(aadHeader, 46); // [46..57] 12-byte nonce
  aadHeader.writeUInt32LE(hwSlotBuf.length, 58); // [58..61] Longitud H del Key Slot binario
  if (hwSlotBuf.length > 0) {
    hwSlotBuf.copy(aadHeader, 62); // [62..62+H-1] Key Slot binario protegido por AAD
  }

  let jsonBytes = null;
  let compressedPayload = null;
  try {
    jsonBytes = Buffer.from(JSON.stringify(vaultObject), 'utf8');
    compressedPayload = zlib.gzipSync(jsonBytes, { level: 9 });

    let ciphertext;
    let authTag;
    if (cipherName === 'chacha20-poly1305') {
      const res = encryptChaCha20Poly1305(derivedKey, nonce, compressedPayload, aadHeader);
      ciphertext = res.ciphertext;
      authTag = res.authTag;
    } else {
      const cipher = crypto.createCipheriv(cipherName, derivedKey, nonce);
      cipher.setAAD(aadHeader, { plaintextLength: compressedPayload.length });
      ciphertext = Buffer.concat([cipher.update(compressedPayload), cipher.final()]);
      authTag = cipher.getAuthTag(); // 16 bytes
    }

    return Buffer.concat([aadHeader, authTag, ciphertext]);
  } finally {
    ProtectedMemory.zeroize(derivedKey);
    ProtectedMemory.zeroize(jsonBytes);
    ProtectedMemory.zeroize(compressedPayload);
  }
}

/**
 * Lee, verifica autenticidad AEAD (incluyendo el Key Slot binario en AAD), descifra y descomprime un buffer `.kvlt`.
 * Soporta tanto archivos v1 como v2 unificados.
 * @param {Buffer} fileBuffer
 * @param {string} masterPassword
 * @param {string|null} keyFilePath
 * @returns {{ vault: object, headerInfo: object, hardwareSlot: object|null }}
 */
function deserializeVaultFromBuffer(fileBuffer, masterPassword, keyFilePath = null) {
  if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length < 74) {
    throw new Error('Archivo inválido o truncado: tamaño menor a la cabecera mínima.');
  }

  const magic = fileBuffer.subarray(0, 4);
  if (!magic.equals(MAGIC)) {
    throw new Error('Firma mágica inválida: el archivo no es una bóveda .kvlt válida.');
  }

  const version = fileBuffer.readUInt8(4);
  if (version !== FORMAT_VERSION_V1 && version !== FORMAT_VERSION_V2) {
    throw new Error(`Versión de formato .kvlt no soportada: v${version}.`);
  }

  const cipherId = fileBuffer.readUInt8(5);
  const cipherName = CIPHER_BY_ID[cipherId];
  if (!cipherName) {
    throw new Error(`Identificador de cifrado desconocido en cabecera: 0x${cipherId.toString(16)}.`);
  }

  const N = fileBuffer.readUInt32LE(6);
  const r = fileBuffer.readUInt16LE(10);
  const p = fileBuffer.readUInt16LE(12);
  if (N < 1024 || N > 1048576 || r < 1 || r > 32 || p < 1 || p > 16) {
    throw new Error('Parámetros KDF en cabecera fuera de los límites de seguridad permitidos.');
  }

  const salt = fileBuffer.subarray(14, 46);
  const nonce = fileBuffer.subarray(46, 58);

  let aadEndOffset = 58;
  let hwSlotLen = 0;

  if (version === FORMAT_VERSION_V2) {
    if (fileBuffer.length < 78) {
      throw new Error('Cabecera .kvlt v2 truncada.');
    }
    hwSlotLen = fileBuffer.readUInt32LE(58);
    if (hwSlotLen > 65536 || fileBuffer.length < 62 + hwSlotLen + 16) {
      throw new Error('Longitud de Key Slot en cabecera .kvlt corrupta o manipulada.');
    }
    aadEndOffset = 62 + hwSlotLen;
  }

  const aadHeader = fileBuffer.subarray(0, aadEndOffset);
  const authTag = fileBuffer.subarray(aadEndOffset, aadEndOffset + 16);
  const ciphertext = fileBuffer.subarray(aadEndOffset + 16);

  const derivedKey = deriveVaultKey(masterPassword, keyFilePath, salt, { N, r, p });
  let compressedPayload = null;
  let jsonBytes = null;

  try {
    if (cipherName === 'chacha20-poly1305') {
      compressedPayload = decryptChaCha20Poly1305(derivedKey, nonce, ciphertext, authTag, aadHeader);
    } else {
      const decipher = crypto.createDecipheriv(cipherName, derivedKey, nonce);
      decipher.setAAD(aadHeader, { plaintextLength: ciphertext.length });
      decipher.setAuthTag(authTag);
      compressedPayload = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }

    // Solo descomprimir el Key Slot y el payload DESPUÉS de haber verificado criptográficamente el AuthTag AEAD
    const hardwareSlot =
      hwSlotLen > 0 ? decodeHardwareSlotBinary(fileBuffer.subarray(62, aadEndOffset)) : null;

    jsonBytes = zlib.gunzipSync(compressedPayload);
    const vault = JSON.parse(jsonBytes.toString('utf8'));

    return {
      vault,
      hardwareSlot,
      headerInfo: {
        magic: 'KVLT',
        version,
        cipher: cipherName,
        cipherLabel: CIPHERS[cipherName].name,
        kdf: `Scrypt (N=${N}, r=${r}, p=${p})`,
        saltHex: salt.toString('hex').slice(0, 16) + '…',
        nonceHex: nonce.toString('hex'),
        authTagHex: authTag.toString('hex'),
        fileBytes: fileBuffer.length,
      },
    };
  } catch (err) {
    if (err && /Unsupported state or unable to authenticate data/i.test(err.message)) {
      throw new Error(
        'Contraseña maestra incorrecta, archivo de llave inválido o bóveda alterada (Fallo de verificación AEAD).'
      );
    }
    throw err;
  } finally {
    ProtectedMemory.zeroize(derivedKey);
    ProtectedMemory.zeroize(compressedPayload);
    ProtectedMemory.zeroize(jsonBytes);
  }
}

/**
 * Guardado transaccional atómico en disco:
 * Escribe en un archivo temporal `.tmp`, fuerza volcado físico (`fsyncSync`) y renombra atómicamente.
 */
function saveVaultFileAtomic(filePath, vaultObject, masterPassword, options = {}) {
  const resolvedPath = path.resolve(filePath);
  const tmpPath = `${resolvedPath}.tmp.${process.pid}`;
  const encryptedBuffer = serializeVaultToBuffer(vaultObject, masterPassword, options);

  const fd = fs.openSync(tmpPath, 'w', 0o600);
  try {
    fs.writeFileSync(fd, encryptedBuffer);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  fs.renameSync(tmpPath, resolvedPath);

  // Limpiar cualquier archivo .hwslot.json antiguo si existiera de versiones previas
  const legacySidecar = `${resolvedPath}.hwslot.json`;
  if (fs.existsSync(legacySidecar)) {
    try {
      fs.unlinkSync(legacySidecar);
    } catch {
      // Ignorar si ya fue eliminado
    }
  }

  return {
    path: resolvedPath,
    bytesWritten: encryptedBuffer.length,
    sha256: crypto.createHash('sha256').update(encryptedBuffer).digest('hex'),
  };
}

/**
 * Carga una bóveda `.kvlt` desde disco.
 */
function loadVaultFile(filePath, masterPassword, keyFilePath = null) {
  const resolvedPath = path.resolve(filePath);
  const fileBuffer = fs.readFileSync(resolvedPath);
  const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');
  const result = deserializeVaultFromBuffer(fileBuffer, masterPassword, keyFilePath);
  result.headerInfo.sha256 = sha256;
  result.headerInfo.path = resolvedPath;
  return result;
}

module.exports = {
  CIPHERS,
  DEFAULT_KDF_PARAMS,
  inspectVaultFileSlot,
  serializeVaultToBuffer,
  deserializeVaultFromBuffer,
  saveVaultFileAtomic,
  loadVaultFile,
};
