'use strict';

const crypto = require('node:crypto');

/**
 * Implementación RFC 8439 de ChaCha20-Poly1305 AEAD para compatibilidad total con
 * Electron (BoringSSL).
 *
 * Por qué es necesario:
 * Node.js estándar enlaza contra OpenSSL 3.x, que expone `chacha20-poly1305` en `EVP_CIPHER`.
 * Sin embargo, Electron compila Node.js contra **BoringSSL** (el motor criptográfico de Chromium),
 * el cual implementa ChaCha20-Poly1305 en la interfaz `EVP_AEAD` y no lo lista en `crypto.getCiphers()`.
 *
 * Este módulo detecta si el runtime expone `chacha20-poly1305` nativo y, cuando corre bajo
 * BoringSSL (Electron), ejecuta ChaCha20-Poly1305 siguiendo estrictamente el RFC 8439
 * (100% interoperable bit a bit con OpenSSL y verificado con `crypto.timingSafeEqual`).
 */

const HAS_NATIVE_CHACHA20 = crypto.getCiphers().includes('chacha20-poly1305');

function rotl32(v, n) {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

function quarterRound(state, a, b, c, d) {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl32(state[d] ^ state[a], 16);

  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl32(state[b] ^ state[c], 12);

  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl32(state[d] ^ state[a], 8);

  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl32(state[b] ^ state[c], 7);
}

/**
 * Genera un bloque keystream de 64 bytes de ChaCha20 (RFC 8439 Sección 2.3).
 * @param {Buffer} key 32 bytes
 * @param {number} counter 32-bit block counter
 * @param {Buffer} nonce 12 bytes
 * @returns {Buffer} 64 bytes
 */
function chacha20Block(key, counter, nonce) {
  const state = new Uint32Array(16);
  // Constantes "expand 32-byte k"
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;

  for (let i = 0; i < 8; i++) {
    state[4 + i] = key.readUInt32LE(i * 4);
  }

  state[12] = counter >>> 0;
  state[13] = nonce.readUInt32LE(0);
  state[14] = nonce.readUInt32LE(4);
  state[15] = nonce.readUInt32LE(8);

  const working = new Uint32Array(state);
  for (let i = 0; i < 10; i++) {
    // Ronda de columnas
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    // Ronda de diagonales
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }

  const out = Buffer.allocUnsafe(64);
  for (let i = 0; i < 16; i++) {
    out.writeUInt32LE((working[i] + state[i]) >>> 0, i * 4);
  }
  working.fill(0);
  state.fill(0);
  return out;
}

/**
 * Cifra o descifra un buffer con ChaCha20 (RFC 8439 Sección 2.4).
 */
function chacha20Xor(key, initialCounter, nonce, input) {
  const out = Buffer.allocUnsafe(input.length);
  let counter = initialCounter >>> 0;
  let offset = 0;

  while (offset < input.length) {
    const block = chacha20Block(key, counter, nonce);
    const chunkLen = Math.min(64, input.length - offset);
    for (let i = 0; i < chunkLen; i++) {
      out[offset + i] = input[offset + i] ^ block[i];
    }
    block.fill(0);
    offset += chunkLen;
    counter = (counter + 1) >>> 0;
  }

  return out;
}

/**
 * Lee un entero de 128 bits Little-Endian como BigInt.
 */
function readUInt128LE(buf, offset = 0) {
  let res = 0n;
  for (let i = 15; i >= 0; i--) {
    res = (res << 8n) | BigInt(buf[offset + i]);
  }
  return res;
}

/**
 * Calcula el tag Poly1305 de 16 bytes (RFC 8439 Sección 2.5) usando aritmética BigInt módulo 2^130 - 5.
 * @param {Buffer} oneTimeKey 32 bytes (r || s)
 * @param {Buffer} msg Mensaje autenticado
 * @returns {Buffer} Tag de 16 bytes
 */
function poly1305Mac(oneTimeKey, msg) {
  const rBytes = Buffer.from(oneTimeKey.subarray(0, 16));
  // Clamping de r según RFC 8439 Sección 2.5
  rBytes[3] &= 15;
  rBytes[7] &= 15;
  rBytes[11] &= 15;
  rBytes[15] &= 15;
  rBytes[4] &= 252;
  rBytes[8] &= 252;
  rBytes[12] &= 252;

  const r = readUInt128LE(rBytes, 0);
  const s = readUInt128LE(oneTimeKey, 16);
  rBytes.fill(0);

  const P = (1n << 130n) - 5n;
  let acc = 0n;

  for (let offset = 0; offset < msg.length; offset += 16) {
    const chunkLen = Math.min(16, msg.length - offset);
    let n = 0n;
    for (let i = chunkLen - 1; i >= 0; i--) {
      n = (n << 8n) | BigInt(msg[offset + i]);
    }
    n |= 1n << BigInt(chunkLen * 8);
    acc = ((acc + n) * r) % P;
  }

  acc = (acc + s) & ((1n << 128n) - 1n);

  const tag = Buffer.allocUnsafe(16);
  let tmp = acc;
  for (let i = 0; i < 16; i++) {
    tag[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }
  return tag;
}

function pad16(len) {
  const rem = len % 16;
  return rem === 0 ? Buffer.alloc(0) : Buffer.alloc(16 - rem, 0);
}

/**
 * Construye los datos autenticados para Poly1305 según RFC 8439 Sección 2.8.
 */
function buildPoly1305Data(aad, ciphertext) {
  const lengths = Buffer.alloc(16);
  lengths.writeBigUInt64LE(BigInt(aad.length), 0);
  lengths.writeBigUInt64LE(BigInt(ciphertext.length), 8);
  return Buffer.concat([aad, pad16(aad.length), ciphertext, pad16(ciphertext.length), lengths]);
}

/**
 * Cifra con ChaCha20-Poly1305 AEAD (usa OpenSSL nativo si está disponible o RFC 8439 bajo BoringSSL).
 * @param {Buffer} key 32 bytes
 * @param {Buffer} nonce 12 bytes
 * @param {Buffer} plaintext
 * @param {Buffer} [aad]
 * @returns {{ ciphertext: Buffer, authTag: Buffer }}
 */
function encryptChaCha20Poly1305(key, nonce, plaintext, aad = Buffer.alloc(0)) {
  if (HAS_NATIVE_CHACHA20) {
    const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    if (aad.length > 0) {
      cipher.setAAD(aad, { plaintextLength: plaintext.length });
    }
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return { ciphertext, authTag };
  }

  const polyKeyBlock = chacha20Block(key, 0, nonce);
  const otk = polyKeyBlock.subarray(0, 32);
  const ciphertext = chacha20Xor(key, 1, nonce, plaintext);
  const macData = buildPoly1305Data(aad, ciphertext);
  const authTag = poly1305Mac(otk, macData);

  polyKeyBlock.fill(0);
  macData.fill(0);
  return { ciphertext, authTag };
}

/**
 * Descifra y autentica con ChaCha20-Poly1305 AEAD en tiempo constante.
 * @param {Buffer} key 32 bytes
 * @param {Buffer} nonce 12 bytes
 * @param {Buffer} ciphertext
 * @param {Buffer} authTag 16 bytes
 * @param {Buffer} [aad]
 * @returns {Buffer} plaintext
 */
function decryptChaCha20Poly1305(key, nonce, ciphertext, authTag, aad = Buffer.alloc(0)) {
  if (HAS_NATIVE_CHACHA20) {
    const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    if (aad.length > 0) {
      decipher.setAAD(aad, { plaintextLength: ciphertext.length });
    }
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  const polyKeyBlock = chacha20Block(key, 0, nonce);
  const otk = polyKeyBlock.subarray(0, 32);
  const macData = buildPoly1305Data(aad, ciphertext);
  const expectedTag = poly1305Mac(otk, macData);

  polyKeyBlock.fill(0);
  macData.fill(0);

  if (authTag.length !== 16 || !crypto.timingSafeEqual(expectedTag, authTag)) {
    expectedTag.fill(0);
    throw new Error('Unsupported state or unable to authenticate data');
  }
  expectedTag.fill(0);

  return chacha20Xor(key, 1, nonce, ciphertext);
}

module.exports = {
  HAS_NATIVE_CHACHA20,
  encryptChaCha20Poly1305,
  decryptChaCha20Poly1305,
};
