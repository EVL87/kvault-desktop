'use strict';

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { ProtectedMemory } = require('./protectedMemory');

/**
 * Hashes SHA-256 canónicos (LF normalizado) de los scripts PowerShell desempaquetados (`app.asar.unpacked`).
 * Impide que un atacante local modifique los archivos `.ps1` en disco para interceptar secretos enviados por `stdin`.
 */
const EXPECTED_PS1_HASHES = Object.freeze({
  'win32Clipboard.ps1': '86374d55a6af82a0aabb017027da273c880a02c6cb4ded62f846db40ef0c2bc8',
  'win32WebAuthn.ps1': 'f9a29493f45ad63159ebe323f072899509b6af63766ccde42c1fb2f13260b784',
  'win32FileAssoc.ps1': 'fccc26a378d6527b4b7f6a2642ff94c1c384b8b8a1a9f95216602355b7e21378',
});

/**
 * Resuelve la ruta absoluta de `powershell.exe` dentro de `System32` para impedir ataques de
 * `PATH` / `CWD` Hijacking (CWE-426 / CWE-427) cuando el usuario abre archivos `.kvlt` desde carpetas no confiables.
 */
function getWindowsPowerShellExecutable() {
  const sysRoot = process.env.SystemRoot || 'C:\\Windows';
  const candidate = path.join(sysRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  return candidate;
}

/**
 * Verifica criptográficamente la integridad SHA-256 de un script `.ps1` antes de invocarlo.
 */
function verifyPowerShellScriptIntegrity(scriptPath) {
  const scriptName = path.basename(scriptPath);
  const expectedHash = EXPECTED_PS1_HASHES[scriptName];
  if (!expectedHash) {
    throw new Error(`Script PowerShell no autorizado: ${scriptName}`);
  }
  if (!fs.existsSync(scriptPath)) {
    throw new Error(`No se encontró el script requerido: ${scriptPath}`);
  }
  const normalized = fs.readFileSync(scriptPath, 'utf8').replace(/\r\n/g, '\n');
  const actualHash = crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
  const expectedBuf = Buffer.from(expectedHash, 'hex');
  const actualBuf = Buffer.from(actualHash, 'hex');
  if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
    throw new Error(`Fallo de integridad SHA-256 en ${scriptName}: el script auxiliar fue modificado.`);
  }
  return true;
}

/**
 * Ejecuta un script `.ps1` verificado usando ruta absoluta a `System32\...\powershell.exe` y `cwd` seguro.
 */
function execVerifiedPowerShellScript(scriptPath, scriptArgs = [], options = {}) {
  verifyPowerShellScriptIntegrity(scriptPath);
  const psExe = getWindowsPowerShellExecutable();
  const sysRoot = process.env.SystemRoot || 'C:\\Windows';
  const timeout = options.timeout ?? 8000;
  const stdinText = options.stdinText ?? '';

  return new Promise((resolve, reject) => {
    const child = execFile(
      psExe,
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, ...scriptArgs],
      {
        windowsHide: true,
        timeout,
        cwd: sysRoot,
      },
      (err, stdout, stderr) => {
        if (err) {
          return reject(new Error(String(stderr || stdout || err.message).trim()));
        }
        resolve(String(stdout || '').trim());
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
 * Resuelve en sistemas Debian / Ubuntu / Linux Mint un binario exclusivamente desde rutas del sistema (`/usr/bin`, `/bin`).
 */
function resolveTrustedLinuxBinary(binaryName) {
  if (!/^[a-zA-Z0-9._-]+$/.test(binaryName)) return null;
  const trustedDirs = ['/usr/bin', '/bin'];
  for (const dir of trustedDirs) {
    const fullPath = path.join(dir, binaryName);
    try {
      const st = fs.statSync(fullPath);
      if (st.isFile()) return fullPath;
    } catch {}
  }
  return null;
}

/**
 * Ejecuta un binario de sistema confiable en Linux (`/usr/bin/...`) con `cwd: '/'` y soporte de `stdin` zeroizado.
 */
function execTrustedLinuxBinary(binaryName, args = [], options = {}) {
  const binPath = resolveTrustedLinuxBinary(binaryName);
  if (!binPath) {
    return Promise.reject(new Error(`Utilidad del sistema no instalada en /usr/bin: ${binaryName}`));
  }
  const timeout = options.timeout ?? 8000;
  const stdinBuf =
    options.stdinBuffer != null
      ? Buffer.from(options.stdinBuffer)
      : options.stdinText != null
      ? Buffer.from(String(options.stdinText), 'utf8')
      : null;

  return new Promise((resolve, reject) => {
    const child = execFile(
      binPath,
      args,
      {
        timeout,
        cwd: '/',
        maxBuffer: 1024 * 1024,
      },
      (err, stdout, stderr) => {
        if (err) {
          return reject(new Error(String(stderr || stdout || err.message).trim()));
        }
        resolve(String(stdout || '').trim());
      }
    );

    if (stdinBuf) {
      try {
        child.stdin.write(stdinBuf);
        child.stdin.end();
      } finally {
        ProtectedMemory.zeroize(stdinBuf);
      }
    } else {
      child.stdin.end();
    }
  });
}

/**
 * Valida y sanitiza estrictamente una URL antes de enviarla a `shell.openExternal`:
 * - Bloquea bytes NUL (`\0` / CVE-2026-105482) y caracteres de control.
 * - Permite exclusivamente esquemas `https:` y `http:` con hostname no vacío,
 *   bloqueando `file://`, `smb://`, `ms-msdt:`, `search-ms:`, `javascript:`, etc.
 */
function validateAndSanitizeExternalUrl(rawUrlInput) {
  const raw = String(rawUrlInput ?? '').trim();
  if (!raw) {
    throw new Error('Esta entrada no tiene una URL configurada.');
  }
  if (/[\x00-\x1f\x7f]/.test(raw)) {
    throw new Error('URL bloqueada por seguridad: contiene caracteres de control o bytes NUL (\\0).');
  }

  let candidate = raw;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error('El formato de la URL es inválido.');
  }

  const ALLOWED_PROTOCOLS = new Set(['https:', 'http:']);
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol) || !parsed.hostname || parsed.hostname.includes('\0')) {
    throw new Error(`Protocolo de URL bloqueado por seguridad (${parsed.protocol}). Solo se permite https:// o http://.`);
  }

  return parsed.toString();
}

module.exports = {
  EXPECTED_PS1_HASHES,
  getWindowsPowerShellExecutable,
  verifyPowerShellScriptIntegrity,
  execVerifiedPowerShellScript,
  resolveTrustedLinuxBinary,
  execTrustedLinuxBinary,
  validateAndSanitizeExternalUrl,
};
