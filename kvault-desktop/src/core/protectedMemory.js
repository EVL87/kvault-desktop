'use strict';

const crypto = require('node:crypto');
const { encryptChaCha20Poly1305, decryptChaCha20Poly1305 } = require('./chacha20poly1305');

/**
 * ProtectedMemory — Motor de aislamiento criptográfico de secretos en RAM.
 *
 * En lugar de mantener contraseñas y semillas 2FA en texto plano como strings inmutables
 * en el Heap de V8, cifra cada secreto en memoria utilizando ChaCha20-Poly1305 AEAD con una
 * clave efímera de proceso de 256 bits (`_processKey`) y sobrescribe determinísticamente
 * con ceros (`0x00`) todos los buffers temporales inmediatamente después de su uso.
 */
class ProtectedMemory {
  constructor() {
    // Clave efímera aleatoria de 32 bytes que vive únicamente durante la sesión activa del proceso
    this._processKey = crypto.randomBytes(32);
  }

  /**
   * Sobrescribe un Buffer con ceros de forma determinista (Zeroize pattern).
   * @param {Buffer} buf
   */
  static zeroize(buf) {
    if (Buffer.isBuffer(buf)) {
      buf.fill(0);
    }
  }

  /**
   * Protege un string sensible convirtiéndolo en un sobre cifrado en memoria (ChaCha20-Poly1305).
   * @param {string} plainText
   * @returns {{ iv: string, tag: string, data: string, byteLength: number }}
   */
  protectString(plainText) {
    const str = String(plainText ?? '');
    const rawBuf = Buffer.from(str, 'utf8');
    try {
      const iv = crypto.randomBytes(12);
      const { ciphertext, authTag } = encryptChaCha20Poly1305(this._processKey, iv, rawBuf);
      return {
        iv: iv.toString('base64'),
        tag: authTag.toString('base64'),
        data: ciphertext.toString('base64'),
        byteLength: rawBuf.length
      };
    } finally {
      ProtectedMemory.zeroize(rawBuf);
    }
  }

  /**
   * Desprotege temporalmente un sobre en memoria para lectura puntual (ej. copiar al portapapeles).
   * @param {{ iv: string, tag: string, data: string }} envelope
   * @returns {string}
   */
  unprotectToString(envelope) {
    if (!envelope || typeof envelope !== 'object' || !envelope.data) {
      return '';
    }
    const iv = Buffer.from(envelope.iv, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    const encrypted = Buffer.from(envelope.data, 'base64');
    let decryptedBuf = null;
    try {
      decryptedBuf = decryptChaCha20Poly1305(this._processKey, iv, encrypted, tag);
      return decryptedBuf.toString('utf8');
    } finally {
      ProtectedMemory.zeroize(decryptedBuf);
      ProtectedMemory.zeroize(iv);
      ProtectedMemory.zeroize(tag);
      ProtectedMemory.zeroize(encrypted);
    }
  }

  /**
   * Rota la clave efímera o destruye la sesión al bloquear la bóveda (Lock Vault).
   */
  wipeSessionKey() {
    ProtectedMemory.zeroize(this._processKey);
    this._processKey = crypto.randomBytes(32);
  }
}

module.exports = { ProtectedMemory };
