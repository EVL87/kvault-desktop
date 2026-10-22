'use strict';

const crypto = require('node:crypto');

/**
 * Motor Nativo RFC 6238 TOTP (Time-Based One-Time Password) + Analizador de Entropía.
 *
 * Soporta semillas Base32 directas (RFC 4648) y URIs estándar `otpauth://totp/...`.
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Decodifica una cadena Base32 (RFC 4648) o extrae el parámetro `secret=` de una URI `otpauth://`.
 * @param {string} input
 * @returns {Buffer|null}
 */
function decodeBase32Secret(input) {
  if (!input || typeof input !== 'string') return null;
  let raw = input.trim();

  if (raw.toLowerCase().startsWith('otpauth://')) {
    try {
      const url = new URL(raw);
      raw = url.searchParams.get('secret') || '';
    } catch {
      return null;
    }
  }

  const cleaned = raw.toUpperCase().replace(/[\s\-=]+/g, '');
  if (!cleaned) return null;

  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return bytes.length > 0 ? Buffer.from(bytes) : null;
}

/**
 * Genera el código TOTP actual de 6 dígitos y los segundos restantes del ciclo de 30s.
 * @param {string} secretOrUri
 * @param {number} nowMs
 * @returns {{ valid: boolean, code: string, remainingSeconds: number, period: number }}
 */
function generateTotp(secretOrUri, nowMs = Date.now()) {
  const keyBuf = decodeBase32Secret(secretOrUri);
  if (!keyBuf) {
    return { valid: false, code: '------', remainingSeconds: 0, period: 30 };
  }

  try {
    const period = 30;
    const epochSeconds = Math.floor(nowMs / 1000);
    const counter = Math.floor(epochSeconds / period);
    const remainingSeconds = period - (epochSeconds % period);

    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter), 0);

    const hmac = crypto.createHmac('sha1', keyBuf).update(counterBuf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binaryCode =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    const otp = (binaryCode % 1000000).toString().padStart(6, '0');
    return {
      valid: true,
      code: `${otp.slice(0, 3)} ${otp.slice(3)}`,
      rawCode: otp,
      remainingSeconds,
      period
    };
  } finally {
    keyBuf.fill(0);
  }
}

/**
 * Calcula los bits de entropía estimados de una contraseña (basado en el pool de caracteres y longitud real).
 * @param {string} password
 * @returns {{ bits: number, level: 'critical'|'weak'|'good'|'strong', label: string }}
 */
function calculatePasswordEntropy(password) {
  const pwd = String(password ?? '');
  if (!pwd.length) {
    return { bits: 0, level: 'critical', label: 'Vacía (0 bits)' };
  }

  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;

  const uniqueChars = new Set(pwd).size;
  const effectiveLength = pwd.length * (0.5 + 0.5 * (uniqueChars / pwd.length));
  const bits = Math.round(effectiveLength * Math.log2(Math.max(pool, 2)));

  if (bits < 45) return { bits, level: 'critical', label: `Crítica (${bits} bits)` };
  if (bits < 65) return { bits, level: 'weak', label: `Débil (${bits} bits)` };
  if (bits < 90) return { bits, level: 'good', label: `Buena (${bits} bits)` };
  return { bits, level: 'strong', label: `Fuerte (${bits} bits)` };
}

/**
 * Generador criptográfico de contraseñas sin sesgo de módulo (Rejection Sampling).
 */
function generateSecurePassword(options = {}) {
  const length = Math.min(Math.max(Number(options.length) || 20, 8), 128);
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const digits = '23456789';
  const symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?';

  let alphabet = lower + upper + digits;
  if (options.symbols !== false) alphabet += symbols;

  const chars = [];
  const maxValidByte = 256 - (256 % alphabet.length);
  while (chars.length < length) {
    const rand = crypto.randomBytes(length * 2);
    for (let i = 0; i < rand.length && chars.length < length; i++) {
      if (rand[i] < maxValidByte) {
        chars.push(alphabet[rand[i] % alphabet.length]);
      }
    }
  }
  return chars.join('');
}

module.exports = {
  decodeBase32Secret,
  generateTotp,
  calculatePasswordEntropy,
  generateSecurePassword
};
