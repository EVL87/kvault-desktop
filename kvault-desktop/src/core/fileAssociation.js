'use strict';

const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const {
  execVerifiedPowerShellScript,
  resolveTrustedLinuxBinary,
  execTrustedLinuxBinary,
} = require('./secureExec');

function resolveUnpackedPath(targetPath) {
  return targetPath.replace('app.asar', 'app.asar.unpacked');
}

const PS_ASSOC_PATH = resolveUnpackedPath(path.join(__dirname, 'win32FileAssoc.ps1'));

/**
 * Extrae la ruta de un archivo `.kvlt` pasado por línea de comandos de forma segura:
 * - Ignora `argv[0]` (ejecutable de Electron).
 * - Rechaza cualquier argumento que contenga bytes NUL (`\0`) o comience por `-` (previniendo inyección de flags Chromium/Electron CWE-88),
 *   salvo que aparezca después del delimitador explícito `--`.
 */
function extractKvltPathFromArgs(argv = []) {
  if (!Array.isArray(argv)) return null;
  let afterDoubleDash = false;

  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg || typeof arg !== 'string') continue;
    if (arg.includes('\0')) continue;

    const cleaned = arg.replace(/^"+|"+$/g, '').trim();
    if (cleaned === '--') {
      afterDoubleDash = true;
      continue;
    }

    if (!afterDoubleDash && cleaned.startsWith('-')) {
      continue;
    }

    if (cleaned.toLowerCase().endsWith('.kvlt')) {
      try {
        const resolved = path.resolve(cleaned);
        const st = fs.statSync(resolved);
        if (st.isFile()) {
          return resolved;
        }
      } catch {}
    }
  }
  return null;
}

/**
 * Registra en sistemas basados en Debian (Debian, Ubuntu, Linux Mint) el tipo MIME `application/x-kvault` (`*.kvlt`),
 * el icono unificado y el lanzador `kvault-desktop.desktop` con el separador seguro `-- %f`.
 */
async function registerLinuxXdgFileAssociation(app) {
  try {
    const home = os.homedir();
    const mimePackagesDir = path.join(home, '.local', 'share', 'mime', 'packages');
    const appsDir = path.join(home, '.local', 'share', 'applications');
    const iconsDir = path.join(home, '.local', 'share', 'icons', 'hicolor', '256x256', 'apps');

    fs.mkdirSync(mimePackagesDir, { recursive: true });
    fs.mkdirSync(appsDir, { recursive: true });
    fs.mkdirSync(iconsDir, { recursive: true });

    const appRoot = resolveUnpackedPath(path.resolve(__dirname, '..', '..'));
    const pngSource = path.join(appRoot, 'assets', 'icon.png');
    const iconDest = path.join(iconsDir, 'kvault-desktop.png');
    if (fs.existsSync(pngSource)) {
      fs.copyFileSync(pngSource, iconDest);
      fs.copyFileSync(pngSource, path.join(iconsDir, 'application-x-kvault.png'));
    }

    const mimeXml = `<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-kvault">
    <comment>Bóveda Cifrada KVault (.kvlt)</comment>
    <icon name="kvault-desktop"/>
    <glob pattern="*.kvlt"/>
  </mime-type>
</mime-info>
`;
    fs.writeFileSync(path.join(mimePackagesDir, 'application-x-kvault.xml'), mimeXml, 'utf8');

    const exePath = process.execPath;
    const isPackaged = app ? app.isPackaged : true;
    const execLine = isPackaged
      ? `"${exePath}" -- %f`
      : `"${exePath}" "${path.resolve(__dirname, '..', '..')}" -- %f`;

    const desktopEntry = `[Desktop Entry]
Type=Application
Name=KVault Desktop
Comment=Gestor de Credenciales AEAD (.kvlt)
Exec=${execLine}
Icon=kvault-desktop
Terminal=false
Categories=Utility;Security;
MimeType=application/x-kvault;
StartupWMClass=kvault-desktop
`;
    const desktopPath = path.join(appsDir, 'kvault-desktop.desktop');
    fs.writeFileSync(desktopPath, desktopEntry, { encoding: 'utf8', mode: 0o755 });

    if (resolveTrustedLinuxBinary('update-mime-database')) {
      await execTrustedLinuxBinary('update-mime-database', [path.join(home, '.local', 'share', 'mime')]).catch(
        () => {}
      );
    }
    if (resolveTrustedLinuxBinary('xdg-mime')) {
      await execTrustedLinuxBinary('xdg-mime', ['default', 'kvault-desktop.desktop', 'application/x-kvault']).catch(
        () => {}
      );
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Registra automáticamente la asociación de archivos `.kvlt` con el icono oficial de KVault Desktop
 * tanto en Windows (`HKCU\Software\Classes\.kvlt`) como en Debian / Ubuntu / Linux Mint (`XDG MIME`).
 */
async function registerKvltFileAssociation(app) {
  if (process.platform === 'linux') {
    return registerLinuxXdgFileAssociation(app);
  }
  if (process.platform !== 'win32') return false;

  const isPackaged = app ? app.isPackaged : false;
  const exePath = process.execPath;
  const appRoot = resolveUnpackedPath(path.resolve(__dirname, '..', '..'));
  const icoFile = path.join(appRoot, 'assets', 'icon.ico');
  const iconTarget = fs.existsSync(icoFile) ? icoFile : exePath;

  const scriptArgs = ['-ExePath', exePath, '-IconFile', iconTarget];
  if (!isPackaged) {
    scriptArgs.push('-AppDir', path.resolve(__dirname, '..', '..'));
  }

  try {
    const stdout = await execVerifiedPowerShellScript(PS_ASSOC_PATH, scriptArgs, { timeout: 10000 });
    return stdout.includes('OK|ASSOCIATED');
  } catch {
    return false;
  }
}

module.exports = {
  resolveUnpackedPath,
  extractKvltPathFromArgs,
  registerKvltFileAssociation,
};
