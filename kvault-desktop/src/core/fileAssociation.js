'use strict';

const path = require('node:path');
const fs = require('node:fs');
const { execFile } = require('node:child_process');

function resolveUnpackedPath(targetPath) {
  return targetPath.replace('app.asar', 'app.asar.unpacked');
}

const PS_ASSOC_PATH = resolveUnpackedPath(path.join(__dirname, 'win32FileAssoc.ps1'));

/**
 * Extrae la ruta de un archivo `.kvlt` pasado por línea de comandos (ej. al hacer doble clic en Windows Explorer).
 */
function extractKvltPathFromArgs(argv = []) {
  for (const arg of argv) {
    if (!arg || typeof arg !== 'string') continue;
    const cleaned = arg.replace(/^"+|"+$/g, '').trim();
    if (cleaned.toLowerCase().endsWith('.kvlt') && fs.existsSync(cleaned)) {
      return path.resolve(cleaned);
    }
  }
  return null;
}

/**
 * Registra automáticamente en Windows (`HKCU\Software\Classes\.kvlt`) la asociación de archivos `.kvlt`
 * con el ejecutable de KVault Desktop y asigna el mismo icono de la aplicación (`icon.ico` / `.exe,0`).
 */
function registerKvltFileAssociation(app) {
  if (process.platform !== 'win32') return Promise.resolve(false);

  const isPackaged = app.isPackaged;
  const exePath = process.execPath;
  const appRoot = resolveUnpackedPath(path.resolve(__dirname, '..', '..'));
  const icoFile = path.join(appRoot, 'assets', 'icon.ico');
  const iconTarget = fs.existsSync(icoFile) ? icoFile : exePath;

  const args = [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    PS_ASSOC_PATH,
    '-ExePath',
    exePath,
    '-IconFile',
    iconTarget,
  ];

  if (!isPackaged) {
    args.push('-AppDir', path.resolve(__dirname, '..', '..'));
  }

  return new Promise((resolve) => {
    execFile(
      'powershell.exe',
      args,
      { windowsHide: true, timeout: 10000 },
      (err, stdout) => {
        if (err) return resolve(false);
        resolve(String(stdout || '').includes('OK|ASSOCIATED'));
      }
    );
  });
}

module.exports = {
  resolveUnpackedPath,
  extractKvltPathFromArgs,
  registerKvltFileAssociation,
};
