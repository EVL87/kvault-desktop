'use strict';

const path = require('node:path');
const { execFile } = require('node:child_process');
const { ProtectedMemory } = require('./protectedMemory');

const PS_SCRIPT_PATH = path.join(__dirname, 'win32Clipboard.ps1').replace('app.asar', 'app.asar.unpacked');

/**
 * Motor Nativo Win32 para Portapapeles Seguro (Anti-Win+V) y Auto-Type.
 *
 * Resuelve dos problemas críticos en Windows 10/11:
 * 1. `electron.clipboard.writeText()` NO establece las banderas nativas de `user32.dll`
 *    (`ExcludeClipboardContentFromMonitorProcessing=1`, `CanIncludeInClipboardHistory=0`,
 *    `CanUploadToCloudClipboard=0`). Sin ellas, el servicio `cbdhsvc` de Windows captura
 *    contraseñas y códigos OTP dentro del historial `Win + V` de forma permanente.
 * 2. Al purgar el portapapeles (`wipeSecureClipboard`), además de `EmptyClipboard()` en Win32,
 *    invoca la API WinRT `Windows.ApplicationModel.DataTransfer.Clipboard::ClearHistory()`
 *    para eliminar cualquier rastro que haya quedado en el panel `Win + V`.
 */

function escapeForSendKeys(rawText) {
  const str = String(rawText ?? '');
  let out = '';
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    switch (ch) {
      case '{':
        out += '{{}';
        break;
      case '}':
        out += '{}}';
        break;
      case '+':
      case '^':
      case '%':
      case '~':
      case '(':
      case ')':
      case '[':
      case ']':
        out += `{${ch}}`;
        break;
      case '\r':
        break;
      case '\n':
        out += '{ENTER}';
        break;
      case '\t':
        out += '{TAB}';
        break;
      default:
        out += ch;
    }
  }
  return out;
}

/**
 * Copia un secreto al portapapeles de Windows inyectando en la misma transacción `OpenClipboard`
 * los formatos `CanIncludeInClipboardHistory=0`, `CanUploadToCloudClipboard=0` y
 * `ExcludeClipboardContentFromMonitorProcessing=1` para que `Win + V` jamás lo registre.
 *
 * @param {string} secretText
 * @returns {Promise<boolean>}
 */
function setSecureClipboard(secretText) {
  return new Promise((resolve) => {
    const child = execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', PS_SCRIPT_PATH, '-Action', 'set'],
      { windowsHide: true, timeout: 6000 },
      (err) => {
        resolve(!err);
      }
    );

    const buf = Buffer.from(String(secretText ?? ''), 'utf8');
    try {
      child.stdin.write(buf);
      child.stdin.end();
    } finally {
      ProtectedMemory.zeroize(buf);
    }
  });
}

/**
 * Purga de forma determinista ÚNICAMENTE el slot activo del portapapeles (`user32!EmptyClipboard`)
 * si y solo si su contenido sigue coincidiendo con `expectedSecret`, dejando 100% intacto
 * el historial `Win + V` de las tareas del usuario (patrón `ClearIfOwner`).
 *
 * @param {string} [expectedSecret='']
 * @returns {Promise<boolean>}
 */
function wipeSecureClipboard(expectedSecret = '') {
  return new Promise((resolve) => {
    const child = execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', PS_SCRIPT_PATH, '-Action', 'wipe'],
      { windowsHide: true, timeout: 6000 },
      (err, stdout) => {
        if (err) return resolve(false);
        resolve(String(stdout || '').trim() === 'WIPED');
      }
    );

    const buf = Buffer.from(String(expectedSecret ?? ''), 'utf8');
    try {
      child.stdin.write(buf);
      child.stdin.end();
    } finally {
      ProtectedMemory.zeroize(buf);
    }
  });
}

/**
 * Ejecuta Auto-Type en la ventana anterior y purga automáticamente el portapapeles
 * e historial `Win + V` al finalizar.
 */
function performAutoType({ username, password, totpCode = '', mode = 'enter', mainWindow = null }) {
  return new Promise((resolve, reject) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.minimize();
    }

    const escapedUser = escapeForSendKeys(username);
    const escapedPass = escapeForSendKeys(password);
    const escapedTotp = escapeForSendKeys(totpCode);

    const child = execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', PS_SCRIPT_PATH, '-Action', 'autotype'],
      { windowsHide: true, timeout: 10000 },
      (err) => {
        if (err) {
          return reject(new Error(`Fallo en Auto-Type: ${err.message}`));
        }
        resolve({ ok: true, mode, clipboardWiped: true });
      }
    );

    const stdinBuffer = Buffer.from(
      JSON.stringify({
        u: escapedUser,
        p: escapedPass,
        t: escapedTotp,
        mode,
      }),
      'utf8'
    );

    try {
      child.stdin.write(stdinBuffer);
      child.stdin.end();
    } finally {
      ProtectedMemory.zeroize(stdinBuffer);
    }
  });
}

module.exports = {
  escapeForSendKeys,
  setSecureClipboard,
  wipeSecureClipboard,
  performAutoType,
};
