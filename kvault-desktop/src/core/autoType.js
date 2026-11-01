'use strict';

const path = require('node:path');
const crypto = require('node:crypto');
const { ProtectedMemory } = require('./protectedMemory');
const {
  execVerifiedPowerShellScript,
  resolveTrustedLinuxBinary,
  execTrustedLinuxBinary,
} = require('./secureExec');

let electronClipboard = null;
try {
  const el = require('electron');
  electronClipboard = el.clipboard || null;
} catch {}

const PS_SCRIPT_PATH = path.join(__dirname, 'win32Clipboard.ps1').replace('app.asar', 'app.asar.unpacked');
const VALID_AUTOTYPE_MODES = new Set(['enter', 'tab-space', 'no-submit']);

/**
 * Motor Multiplataforma (Windows 10/11 + Debian / Ubuntu / Linux Mint) para
 * Portapapeles Seguro (Exclusión de Historial + ClearIfOwner) y Auto-Type Nativo.
 *
 * - En Windows: Invoca `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` con verificación
 *   de integridad SHA-256 sobre `win32Clipboard.ps1` e inyecta `CanIncludeInClipboardHistory=0`.
 * - En Debian / Ubuntu / Linux Mint:
 *   - En portapapeles: inyecta `x-kde-passwordManagerHint=secret` (soportado por Klipper, GPaste, CopyQ)
 *     y soporta `wl-copy` (Wayland) / `xclip` (X11) enviando el secreto exclusivamente por `stdin`.
 *   - En Auto-Type: soporta `xdotool` (X11 / Linux Mint / XWayland) y `wtype` (Wayland) transmitiendo
 *     los caracteres por `stdin` (`--file -` / `-`) para que las contraseñas jamás aparezcan en `/proc/<pid>/cmdline`.
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

function validateAutoTypeMode(mode) {
  const m = String(mode || 'enter');
  if (!VALID_AUTOTYPE_MODES.has(m)) {
    throw new Error(`Modo de Auto-Type inválido: ${m}`);
  }
  return m;
}

/**
 * Copia un secreto al portapapeles excluyéndolo de historiales (`Win + V` en Windows, `x-kde-passwordManagerHint` en Linux).
 * @param {string} secretText
 * @returns {Promise<boolean>}
 */
async function setSecureClipboard(secretText) {
  const textStr = String(secretText ?? '');

  if (process.platform === 'win32') {
    try {
      await execVerifiedPowerShellScript(PS_SCRIPT_PATH, ['-Action', 'set'], {
        timeout: 6000,
        stdinText: textStr,
      });
      return true;
    } catch {
      return false;
    }
  }

  // Linux (Debian / Ubuntu / Linux Mint)
  try {
    if (electronClipboard) {
      electronClipboard.writeText(textStr);
      // Inyectar hint estándar de gestores de contraseñas en Linux (Klipper / GPaste / CopyQ / GNOME)
      try {
        electronClipboard.writeBuffer('x-kde-passwordManagerHint', Buffer.from('secret', 'utf8'));
      } catch {}
    }

    const isWayland = (process.env.XDG_SESSION_TYPE || '').toLowerCase() === 'wayland';
    if (isWayland && resolveTrustedLinuxBinary('wl-copy')) {
      await execTrustedLinuxBinary('wl-copy', ['--'], { stdinText: textStr, timeout: 4000 }).catch(() => {});
    } else if (resolveTrustedLinuxBinary('xclip')) {
      await execTrustedLinuxBinary('xclip', ['-selection', 'clipboard', '-quiet'], {
        stdinText: textStr,
        timeout: 4000,
      }).catch(() => {});
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Purga de forma determinista ÚNICAMENTE el slot activo del portapapeles si y solo si su contenido
 * sigue coincidiendo con `expectedSecret` (patrón `ClearIfOwner`).
 * @param {string} [expectedSecret='']
 * @returns {Promise<boolean>}
 */
async function wipeSecureClipboard(expectedSecret = '') {
  const expectedStr = String(expectedSecret ?? '');

  if (process.platform === 'win32') {
    try {
      const out = await execVerifiedPowerShellScript(PS_SCRIPT_PATH, ['-Action', 'wipe'], {
        timeout: 6000,
        stdinText: expectedStr,
      });
      return out === 'WIPED';
    } catch {
      return false;
    }
  }

  // Linux (Debian / Ubuntu / Linux Mint): comparación en tiempo constante SHA-256 (ClearIfOwner)
  try {
    let currentText = '';
    if (electronClipboard) {
      currentText = electronClipboard.readText() || '';
    } else if (resolveTrustedLinuxBinary('xclip')) {
      currentText = await execTrustedLinuxBinary('xclip', ['-selection', 'clipboard', '-o'], { timeout: 3000 }).catch(
        () => ''
      );
    }

    if (expectedStr.length > 0 && currentText.length > 0) {
      const hExpected = crypto.createHash('sha256').update(expectedStr, 'utf8').digest();
      const hCurrent = crypto.createHash('sha256').update(currentText, 'utf8').digest();
      if (!crypto.timingSafeEqual(hExpected, hCurrent)) {
        return false; // El usuario copió otro texto; respetamos su copia actual
      }
    }

    if (electronClipboard) {
      electronClipboard.clear();
    }
    const isWayland = (process.env.XDG_SESSION_TYPE || '').toLowerCase() === 'wayland';
    if (isWayland && resolveTrustedLinuxBinary('wl-copy')) {
      await execTrustedLinuxBinary('wl-copy', ['--clear'], { timeout: 3000 }).catch(() => {});
    } else if (resolveTrustedLinuxBinary('xclip')) {
      await execTrustedLinuxBinary('xclip', ['-selection', 'clipboard', '-i', '/dev/null'], { timeout: 3000 }).catch(
        () => {}
      );
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Ejecuta Auto-Type en la ventana activa anterior en Windows o Debian/Ubuntu/Linux Mint.
 */
async function performAutoType({ username, password, totpCode = '', mode = 'enter', mainWindow = null }) {
  const safeMode = validateAutoTypeMode(mode);

  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.minimize();
  }

  if (process.platform === 'win32') {
    const escapedUser = escapeForSendKeys(username);
    const escapedPass = escapeForSendKeys(password);
    const escapedTotp = escapeForSendKeys(totpCode);

    const payloadJson = JSON.stringify({
      u: escapedUser,
      p: escapedPass,
      t: escapedTotp,
      mode: safeMode,
    });

    try {
      await execVerifiedPowerShellScript(PS_SCRIPT_PATH, ['-Action', 'autotype'], {
        timeout: 10000,
        stdinText: payloadJson,
      });
      return { ok: true, mode: safeMode, clipboardWiped: true };
    } catch (err) {
      throw new Error(`Fallo en Auto-Type: ${err.message}`);
    }
  }

  // Linux (Debian / Ubuntu / Linux Mint): esperar 220ms tras minimizar para que el gestor de ventanas
  // (Cinnamon, GNOME/Mutter, XFCE, KDE KWin) devuelva el foco a la ventana anterior.
  await new Promise((r) => setTimeout(r, 220));

  const userStr = String(username ?? '');
  const passStr = String(password ?? '');

  if (resolveTrustedLinuxBinary('xdotool')) {
    if (userStr.length > 0) {
      await execTrustedLinuxBinary('xdotool', ['type', '--clearmodifiers', '--delay', '12', '--file', '-'], {
        stdinText: userStr,
        timeout: 8000,
      });
    }
    await execTrustedLinuxBinary('xdotool', ['key', '--clearmodifiers', 'Tab'], { timeout: 4000 });
    if (passStr.length > 0) {
      await execTrustedLinuxBinary('xdotool', ['type', '--clearmodifiers', '--delay', '12', '--file', '-'], {
        stdinText: passStr,
        timeout: 8000,
      });
    }
    if (safeMode === 'enter') {
      await execTrustedLinuxBinary('xdotool', ['key', '--clearmodifiers', 'Return'], { timeout: 4000 });
    } else if (safeMode === 'tab-space') {
      await execTrustedLinuxBinary('xdotool', ['key', '--clearmodifiers', 'Tab', 'space'], { timeout: 4000 });
    }
    return { ok: true, mode: safeMode, clipboardWiped: true };
  }

  if (resolveTrustedLinuxBinary('wtype')) {
    if (userStr.length > 0) {
      await execTrustedLinuxBinary('wtype', ['-'], { stdinText: userStr, timeout: 8000 });
    }
    await execTrustedLinuxBinary('wtype', ['-k', 'Tab'], { timeout: 4000 });
    if (passStr.length > 0) {
      await execTrustedLinuxBinary('wtype', ['-'], { stdinText: passStr, timeout: 8000 });
    }
    if (safeMode === 'enter') {
      await execTrustedLinuxBinary('wtype', ['-k', 'Return'], { timeout: 4000 });
    } else if (safeMode === 'tab-space') {
      await execTrustedLinuxBinary('wtype', ['-k', 'Tab', '-k', 'space'], { timeout: 4000 });
    }
    return { ok: true, mode: safeMode, clipboardWiped: true };
  }

  throw new Error('Para usar Auto-Type en Debian/Ubuntu/Mint instale xdotool (sudo apt install xdotool) o wtype.');
}

module.exports = {
  VALID_AUTOTYPE_MODES,
  escapeForSendKeys,
  validateAutoTypeMode,
  setSecureClipboard,
  wipeSecureClipboard,
  performAutoType,
};
