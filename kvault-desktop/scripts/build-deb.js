'use strict';

/**
 * Empaquetador nativo y reproducible de paquetes Debian (.deb) para KVault Desktop
 * Compatible con Debian 11/12/Trixie, Ubuntu 20.04/22.04/24.04+, Linux Mint 21/22, Pop!_OS y Kali.
 *
 * Construye el archivo `dist/kvault-desktop_<version>_amd64.deb` en formato estándar `ar` Debian 2.0
 * con cabeceras POSIX USTAR (`uid=0`, `gid=0`, permisos `0755`/`0644`/`04755`), perfil AppArmor para
 * Ubuntu 24.04 / Mint 22, asociación MIME `.kvlt` (`application/x-kvault`) e icono de 256x256.
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const { downloadArtifact } = require('@electron/get');
const extractZip = require('extract-zip');

const ROOT_DIR = path.resolve(__dirname, '..');
const DIST_DIR = path.join(ROOT_DIR, 'dist');
const PKG_JSON = JSON.parse(fs.readFileSync(path.join(ROOT_DIR, 'package.json'), 'utf8'));
const ELECTRON_PKG = JSON.parse(
  fs.readFileSync(path.join(ROOT_DIR, 'node_modules', 'electron', 'package.json'), 'utf8')
);

const APP_VERSION = PKG_JSON.version;
const ELECTRON_VERSION = ELECTRON_PKG.version;

/**
 * Crea un bloque de cabecera POSIX USTAR de 512 bytes para un archivo o directorio.
 */
function createTarHeader({ name, mode, size, typeflag, mtime }) {
  const header = Buffer.alloc(512, 0);

  let fileName = name.replace(/\\/g, '/');
  let prefix = '';

  if (Buffer.byteLength(fileName, 'utf8') > 100) {
    const slashIdx = fileName.lastIndexOf('/', fileName.length - 2);
    if (slashIdx !== -1) {
      prefix = fileName.slice(0, slashIdx);
      fileName = fileName.slice(slashIdx + 1);
    }
  }

  header.write(fileName, 0, 100, 'utf8');
  header.write(
    `${(mode & 0o7777).toString(8).padStart(7, '0')}\0`,
    100,
    8,
    'ascii'
  );
  // uid = 0 (root), gid = 0 (root)
  header.write('0000000\0', 108, 8, 'ascii');
  header.write('0000000\0', 116, 8, 'ascii');
  header.write(
    `${size.toString(8).padStart(11, '0')}\0`,
    124,
    12,
    'ascii'
  );
  header.write(
    `${Math.floor(mtime).toString(8).padStart(11, '0')}\0`,
    136,
    12,
    'ascii'
  );
  // Rellenar campo checksum (148..155) con espacios antes de calcular
  header.fill(0x20, 148, 156);
  header.write(typeflag, 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  header.write('root', 265, 32, 'ascii');
  header.write('root', 297, 32, 'ascii');
  if (prefix) {
    header.write(prefix, 345, 155, 'utf8');
  }

  let chksum = 0;
  for (let i = 0; i < 512; i++) {
    chksum += header[i];
  }
  header.write(`${chksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return header;
}

class TarBuilder {
  constructor() {
    this.chunks = [];
    this.addedDirs = new Set();
    this.mtime = Math.floor(Date.now() / 1000);
  }

  addDirectory(dirPath, mode = 0o755) {
    let clean = dirPath.replace(/\\/g, '/');
    if (!clean.startsWith('./')) {
      clean = `./${clean.replace(/^\/+/, '')}`;
    }
    if (!clean.endsWith('/')) {
      clean += '/';
    }
    if (this.addedDirs.has(clean)) return;

    // Asegurar directorios padre
    const parts = clean.slice(0, -1).split('/');
    let accum = '';
    for (let i = 0; i < parts.length; i++) {
      accum += (i === 0 ? '' : '/') + parts[i];
      const dirKey = `${accum}/`;
      if (!this.addedDirs.has(dirKey)) {
        this.addedDirs.add(dirKey);
        this.chunks.push(
          createTarHeader({
            name: dirKey,
            mode: i === parts.length - 1 ? mode : 0o755,
            size: 0,
            typeflag: '5',
            mtime: this.mtime,
          })
        );
      }
    }
  }

  addFile(filePath, contentBuf, mode = 0o644) {
    let clean = filePath.replace(/\\/g, '/');
    if (!clean.startsWith('./')) {
      clean = `./${clean.replace(/^\/+/, '')}`;
    }
    const parentDir = path.posix.dirname(clean);
    if (parentDir && parentDir !== '.') {
      this.addDirectory(parentDir, 0o755);
    } else {
      this.addDirectory('.', 0o755);
    }

    const buf = Buffer.isBuffer(contentBuf) ? contentBuf : Buffer.from(contentBuf, 'utf8');
    this.chunks.push(
      createTarHeader({
        name: clean,
        mode,
        size: buf.length,
        typeflag: '0',
        mtime: this.mtime,
      })
    );
    this.chunks.push(buf);
    const remainder = buf.length % 512;
    if (remainder !== 0) {
      this.chunks.push(Buffer.alloc(512 - remainder, 0));
    }
  }

  toGzipBuffer() {
    const endBlocks = Buffer.alloc(1024, 0);
    const tarBuf = Buffer.concat([...this.chunks, endBlocks]);
    return zlib.gzipSync(tarBuf, { level: 9 });
  }
}

/**
 * Construye un contenedor `ar` estándar de Debian (`!<arch>\n`).
 */
function buildArArchive(members) {
  const magic = Buffer.from('!<arch>\n', 'ascii');
  const mtime = Math.floor(Date.now() / 1000);
  const parts = [magic];

  for (const m of members) {
    const hdr = Buffer.alloc(60, 0x20); // Relleno con espacios ASCII
    hdr.write(m.name.slice(0, 16), 0, 'ascii');
    hdr.write(String(mtime).slice(0, 12), 16, 'ascii');
    hdr.write('0', 28, 'ascii'); // uid = 0
    hdr.write('0', 34, 'ascii'); // gid = 0
    hdr.write('100644', 40, 'ascii');
    hdr.write(String(m.data.length), 48, 'ascii');
    hdr.write('`\n', 58, 'ascii');

    parts.push(hdr);
    parts.push(m.data);
    if (m.data.length % 2 !== 0) {
      parts.push(Buffer.from('\n', 'ascii'));
    }
  }

  return Buffer.concat(parts);
}

function isExecutableLinuxFile(relPath) {
  const base = path.posix.basename(relPath);
  if (
    base === 'kvault-desktop' ||
    base === 'chrome-sandbox' ||
    base === 'chrome_crashpad_handler' ||
    base.endsWith('.so') ||
    /\.so\.\d+/.test(base)
  ) {
    return true;
  }
  return false;
}

async function main() {
  console.log('======================================================================');
  console.log(` CONSTRUYENDO PAQUETE DEBIAN SEGURO: kvault-desktop_${APP_VERSION}_amd64.deb`);
  console.log('======================================================================');

  const asarPath = path.join(DIST_DIR, 'win-unpacked', 'resources', 'app.asar');
  const asarUnpackedDir = path.join(DIST_DIR, 'win-unpacked', 'resources', 'app.asar.unpacked');

  if (!fs.existsSync(asarPath)) {
    throw new Error(
      `No se encontró ${asarPath}. Ejecuta primero 'npm run build:exe' para compilar app.asar.`
    );
  }

  console.log(`[1/4] Descargando/verificando runtime oficial Electron v${ELECTRON_VERSION} (linux-x64)...`);
  const zipPath = await downloadArtifact({
    version: ELECTRON_VERSION,
    artifactName: 'electron',
    platform: 'linux',
    arch: 'x64',
  });

  const tmpStage = fs.mkdtempSync(path.join(os.tmpdir(), 'kvault-deb-stage-'));
  const electronDir = path.join(tmpStage, 'electron-linux');
  fs.mkdirSync(electronDir, { recursive: true });

  try {
    console.log('[2/4] Extrayendo binarios de Linux y empaquetando app.asar...');
    await extractZip(zipPath, { dir: electronDir });

    const oldBin = path.join(electronDir, 'electron');
    const newBin = path.join(electronDir, 'kvault-desktop');
    if (fs.existsSync(oldBin)) {
      fs.renameSync(oldBin, newBin);
    }

    const defaultAppAsar = path.join(electronDir, 'resources', 'default_app.asar');
    if (fs.existsSync(defaultAppAsar)) {
      fs.rmSync(defaultAppAsar, { force: true });
    }

    fs.copyFileSync(asarPath, path.join(electronDir, 'resources', 'app.asar'));
    if (fs.existsSync(asarUnpackedDir)) {
      fs.cpSync(asarUnpackedDir, path.join(electronDir, 'resources', 'app.asar.unpacked'), {
        recursive: true,
      });
    }

    console.log('[3/4] Generando árbol de sistema Debian, reglas MIME .kvlt y perfil AppArmor...');
    const dataTar = new TarBuilder();
    const md5Lines = [];
    let installedBytes = 0;

    function addDataFile(debRelPath, buf, mode) {
      dataTar.addFile(debRelPath, buf, mode);
      installedBytes += buf.length;
      const md5 = crypto.createHash('md5').update(buf).digest('hex');
      md5Lines.push(`${md5}  ${debRelPath.replace(/^\.?\//, '')}`);
    }

    function walkAndAddDir(srcDir, debBaseDir) {
      const entries = fs.readdirSync(srcDir, { withFileTypes: true });
      for (const entry of entries) {
        const fullSrc = path.join(srcDir, entry.name);
        const debRel = path.posix.join(debBaseDir, entry.name);
        if (entry.isDirectory()) {
          dataTar.addDirectory(debRel, 0o755);
          walkAndAddDir(fullSrc, debRel);
        } else if (entry.isFile()) {
          const buf = fs.readFileSync(fullSrc);
          let mode = 0o644;
          if (entry.name === 'chrome-sandbox') {
            mode = 0o4755;
          } else if (isExecutableLinuxFile(debRel)) {
            mode = 0o755;
          }
          addDataFile(debRel, buf, mode);
        }
      }
    }

    walkAndAddDir(electronDir, 'opt/KVault Desktop');

    // Wrapper ejecutable en /usr/bin/kvault-desktop
    const usrBinWrapper = Buffer.from(
      '#!/bin/sh\nexec "/opt/KVault Desktop/kvault-desktop" "$@"\n',
      'utf8'
    );
    addDataFile('usr/bin/kvault-desktop', usrBinWrapper, 0o755);

    // Lanzador Freedesktop en /usr/share/applications/kvault-desktop.desktop
    const desktopEntry = Buffer.from(
      [
        '[Desktop Entry]',
        'Name=KVault Desktop',
        'Comment=Gestor de Credenciales Cifrado (.kvlt AEAD, FIDO2/U2F, TOTP)',
        'Exec="/opt/KVault Desktop/kvault-desktop" -- %f',
        'Terminal=false',
        'Type=Application',
        'Icon=kvault-desktop',
        'StartupWMClass=KVault Desktop',
        'Categories=Utility;Security;',
        'MimeType=application/x-kvault;',
        '',
      ].join('\n'),
      'utf8'
    );
    addDataFile('usr/share/applications/kvault-desktop.desktop', desktopEntry, 0o644);

    // Definición MIME .kvlt en /usr/share/mime/packages/kvault-desktop.xml
    const mimeXml = Buffer.from(
      [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">',
        '  <mime-type type="application/x-kvault">',
        '    <comment>Bóveda Cifrada KVault (.kvlt)</comment>',
        '    <glob pattern="*.kvlt"/>',
        '    <magic priority="80">',
        '      <match type="string" offset="0" value="KVLT"/>',
        '    </magic>',
        '    <icon name="kvault-desktop"/>',
        '  </mime-type>',
        '</mime-info>',
        '',
      ].join('\n'),
      'utf8'
    );
    addDataFile('usr/share/mime/packages/kvault-desktop.xml', mimeXml, 0o644);

    // Icono oficial en /usr/share/icons/hicolor/256x256/apps/kvault-desktop.png
    const iconPngPath = path.join(ROOT_DIR, 'assets', 'icon.png');
    const iconBuf = fs.readFileSync(iconPngPath);
    addDataFile('usr/share/icons/hicolor/256x256/apps/kvault-desktop.png', iconBuf, 0o644);

    const dataTarGz = dataTar.toGzipBuffer();

    // Construir control.tar.gz
    const installedSizeKb = Math.ceil(installedBytes / 1024);
    const controlContent =
      [
        'Package: kvault-desktop',
        `Version: ${APP_VERSION}`,
        'Section: utils',
        'Priority: optional',
        'Architecture: amd64',
        `Installed-Size: ${installedSizeKb}`,
        'Depends: libgtk-3-0 | libgtk-3-0t64, libnotify4, libnss3, libxss1, libxtst6, xdg-utils, libatspi2.0-0 | libatspi2.0-0t64, libuuid1, libsecret-1-0, libasound2 | libasound2t64',
        'Recommends: fido2-tools, libfido2-udev, xdotool, xclip, wl-clipboard',
        'Maintainer: KVault Security <EVL87@users.noreply.github.com>',
        'Homepage: https://github.com/EVL87/kvault-desktop',
        'Description: Gestor de credenciales de escritorio con contenedor .kvlt AEAD y FIDO2/U2F',
        ' KVault Desktop protege credenciales con cifrado ChaCha20-Poly1305 y AES-256-GCM,',
        ' derivacion KDF Scrypt resistente a ASIC/GPU, memoria cifrada ProtectedMemory,',
        ' soporte nativo para llaves fisicas FIDO2/U2F (Yubico Security Key, Flipper Zero),',
        ' generador 2FA TOTP RFC 6238 y Auto-Type seguro.',
        '',
      ].join('\n');

    const postinstContent =
      [
        '#!/bin/sh',
        'set -e',
        '',
        '# 1. Asegurar permisos SUID root para el sandbox de Chromium',
        'if [ -f "/opt/KVault Desktop/chrome-sandbox" ]; then',
        '  chown root:root "/opt/KVault Desktop/chrome-sandbox" || true',
        '  chmod 4755 "/opt/KVault Desktop/chrome-sandbox" || true',
        'fi',
        '',
        '# 2. Configurar perfil AppArmor para Ubuntu 24.04+ / Linux Mint 22+ (userns)',
        'if [ -d "/etc/apparmor.d" ] && command -v apparmor_parser >/dev/null 2>&1; then',
        '  cat << \'EOF\' > /etc/apparmor.d/kvault-desktop || true',
        'abi <abi/4.0>,',
        'include <tunables/global>',
        '',
        'profile kvault-desktop "/opt/KVault Desktop/kvault-desktop" flags=(unconfined) {',
        '  userns,',
        '  include if exists <local/kvault-desktop>',
        '}',
        'EOF',
        '  apparmor_parser -r /etc/apparmor.d/kvault-desktop >/dev/null 2>&1 || true',
        'fi',
        '',
        '# 3. Actualizar bases de datos MIME (.kvlt), escritorio e iconos',
        'if command -v update-mime-database >/dev/null 2>&1; then',
        '  update-mime-database /usr/share/mime >/dev/null 2>&1 || true',
        'fi',
        'if command -v update-desktop-database >/dev/null 2>&1; then',
        '  update-desktop-database /usr/share/applications >/dev/null 2>&1 || true',
        'fi',
        'if command -v gtk-update-icon-cache >/dev/null 2>&1; then',
        '  gtk-update-icon-cache -f -t /usr/share/icons/hicolor >/dev/null 2>&1 || true',
        'fi',
        '',
        'exit 0',
        '',
      ].join('\n');

    const postrmContent =
      [
        '#!/bin/sh',
        'set -e',
        'if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then',
        '  rm -f /etc/apparmor.d/kvault-desktop || true',
        '  if command -v update-mime-database >/dev/null 2>&1; then',
        '    update-mime-database /usr/share/mime >/dev/null 2>&1 || true',
        '  fi',
        '  if command -v update-desktop-database >/dev/null 2>&1; then',
        '    update-desktop-database /usr/share/applications >/dev/null 2>&1 || true',
        '  fi',
        'fi',
        'exit 0',
        '',
      ].join('\n');

    const controlTar = new TarBuilder();
    controlTar.addFile('control', Buffer.from(controlContent, 'utf8'), 0o644);
    controlTar.addFile('postinst', Buffer.from(postinstContent, 'utf8'), 0o755);
    controlTar.addFile('postrm', Buffer.from(postrmContent, 'utf8'), 0o755);
    controlTar.addFile('md5sums', Buffer.from(`${md5Lines.join('\n')}\n`, 'utf8'), 0o644);
    const controlTarGz = controlTar.toGzipBuffer();

    console.log('[4/4] Ensamblando archivo .deb final y calculando hash SHA-256...');
    const debBuf = buildArArchive([
      { name: 'debian-binary', data: Buffer.from('2.0\n', 'ascii') },
      { name: 'control.tar.gz', data: controlTarGz },
      { name: 'data.tar.gz', data: dataTarGz },
    ]);

    const debFileName = `kvault-desktop_${APP_VERSION}_amd64.deb`;
    const debOutPath = path.join(DIST_DIR, debFileName);
    fs.writeFileSync(debOutPath, debBuf);

    const sha256 = crypto.createHash('sha256').update(debBuf).digest('hex');
    const sizeMb = (debBuf.length / (1024 * 1024)).toFixed(2);
    console.log('======================================================================');
    console.log(` [OK] Paquete Debian creado: ${debOutPath}`);
    console.log(`      Tamaño: ${sizeMb} MB | SHA-256: ${sha256}`);
    console.log('======================================================================');
  } finally {
    fs.rmSync(tmpStage, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error('[ERROR build-deb]:', err);
  process.exit(1);
});
