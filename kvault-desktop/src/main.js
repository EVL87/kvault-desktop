'use strict';

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { app, BrowserWindow, ipcMain, dialog, clipboard, Menu, shell } = require('electron');

const { ProtectedMemory } = require('./core/protectedMemory');
const {
  performAutoType,
  setSecureClipboard,
  wipeSecureClipboard,
} = require('./core/autoType');
const {
  wrapSecretForHardwareSlot,
  combinePasswordAndHardwareFactor,
  enrollHardwareKey,
  challengeHardwareKey,
  loadHardwareSlotForVault,
  removeLegacyHardwareSlotFile,
} = require('./core/fido2Hardware');
const {
  serializeVaultToBuffer,
  deserializeVaultFromBuffer,
  saveVaultFileAtomic,
  loadVaultFile,
} = require('./core/vaultFormat');
const {
  generateTotp,
  calculatePasswordEntropy,
  generateSecurePassword,
} = require('./core/totp');
const { importKeePassFile } = require('./importer/keepassImporter');

const memoryGuard = new ProtectedMemory();

/**
 * Estado en vivo dentro del proceso Main (aislado del Renderer).
 * Los secretos (`password`, `totpSecret`) de cada entrada viven exclusivamente
 * como sobres cifrados en RAM (`memoryGuard.protectString(...)` con ChaCha20-Poly1305)
 * y jamás se envían serializados en los listados de la interfaz.
 */
const session = {
  unlocked: false,
  filePath: null,
  cipherId: 1, // 1 = chacha20-poly1305, 2 = aes-256-gcm
  cipherName: 'chacha20-poly1305',
  dirty: false,
  meta: null,
  groups: [],
  entries: new Map(), // id -> { ...publicFields, _pwdEnvelope, _totpEnvelope }
  masterPasswordEnvelope: null,
  keyFilePath: null,
  hardwareSlot: null,
  clipboardTimer: null,
  clipboardCountdownInterval: null,
  lastClipboardEnvelope: null,
};

let mainWindow = null;

/**
 * Limpia de forma determinista toda la sesión en RAM y rota la clave efímera.
 */
function wipeSessionMemory() {
  session.entries.clear();
  session.groups = [];
  session.meta = null;
  session.masterPasswordEnvelope = null;
  session.keyFilePath = null;
  session.hardwareSlot = null;
  session.unlocked = false;
  session.filePath = null;
  session.dirty = false;
  memoryGuard.wipeSessionKey();
}

/**
 * Hidrata entradas crudas dentro de sobres `ProtectedMemory`
 * y calcula la entropía sin conservar el texto plano.
 */
function hydrateEntriesIntoProtectedMemory(rawEntries) {
  session.entries.clear();

  for (const raw of rawEntries) {
    const id = raw.id || crypto.randomUUID();
    const pwdPlain = String(raw.password || '');
    const totpPlain = String(raw.totpSecret || '');
    const entropy = calculatePasswordEntropy(pwdPlain);

    const pwdEnvelope = memoryGuard.protectString(pwdPlain);
    const totpEnvelope = memoryGuard.protectString(totpPlain);

    session.entries.set(id, {
      id,
      groupId: raw.groupId || 'g-root',
      title: String(raw.title || 'Sin título'),
      username: String(raw.username || ''),
      url: String(raw.url || ''),
      notes: String(raw.notes || ''),
      tags: Array.isArray(raw.tags) ? raw.tags : [],
      hasPassword: pwdPlain.length > 0,
      hasTotp: totpPlain.length > 0,
      entropy,
      protectedStats: {
        encryptedBytes: pwdEnvelope.byteLength,
        algorithm: 'chacha20-poly1305-ephemeral',
      },
      createdAt: raw.createdAt || raw.modifiedAt || new Date().toISOString(),
      updatedAt: raw.updatedAt || raw.modifiedAt || new Date().toISOString(),
      _pwdEnvelope: pwdEnvelope,
      _totpEnvelope: totpEnvelope,
    });
  }
}

/**
 * Exporta el árbol en memoria de vuelta a un objeto JSON efímero para cifrar en disco.
 */
function exportVaultPayloadForDisk() {
  const entries = [];
  for (const item of session.entries.values()) {
    const password = memoryGuard.unprotectToString(item._pwdEnvelope);
    const totpSecret = memoryGuard.unprotectToString(item._totpEnvelope);
    entries.push({
      id: item.id,
      groupId: item.groupId,
      title: item.title,
      username: item.username,
      password,
      url: item.url,
      totpSecret,
      notes: item.notes,
      tags: item.tags,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt,
    });
  }
  return {
    meta: {
      ...session.meta,
      updatedAt: new Date().toISOString(),
    },
    groups: session.groups,
    entries,
  };
}

/**
 * Construye el estado público (sin secretos) para enviar al Renderer via IPC.
 */
function getPublicState() {
  if (!session.unlocked) {
    return {
      unlocked: false,
      securityFlags: {
        contentProtection: true,
        contextIsolation: true,
        sandbox: true,
        protectedMemoryEngine: 'ChaCha20-Poly1305 (Ephemeral 256-bit Key)',
      },
    };
  }

  const publicEntries = [];
  let weakCount = 0;
  let totpCount = 0;
  let totalBits = 0;

  for (const item of session.entries.values()) {
    if (item.entropy && item.entropy.bits < 60) weakCount++;
    if (item.hasTotp) totpCount++;
    totalBits += item.entropy ? item.entropy.bits : 0;

    publicEntries.push({
      id: item.id,
      groupId: item.groupId,
      title: item.title,
      username: item.username,
      url: item.url,
      notes: item.notes,
      tags: item.tags,
      hasPassword: item.hasPassword,
      hasTotp: item.hasTotp,
      entropy: item.entropy,
      protectedStats: item.protectedStats,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt,
    });
  }

  const avgEntropy = publicEntries.length > 0 ? Math.round(totalBits / publicEntries.length) : 0;

  return {
    unlocked: true,
    filePath: session.filePath,
    cipherId: session.cipherId,
    cipherName: session.cipherName,
    dirty: session.dirty,
    meta: session.meta,
    groups: session.groups,
    entries: publicEntries,
    hardwareSlot: formatPublicHardwareSlot(session.hardwareSlot),
    audit: {
      totalEntries: publicEntries.length,
      weakCount,
      totpCount,
      avgEntropy,
    },
    securityFlags: {
      contentProtection: true,
      contextIsolation: true,
      sandbox: true,
      protectedMemoryEngine: 'ChaCha20-Poly1305 (Ephemeral 256-bit Key)',
    },
  };
}

function formatPublicHardwareSlot(slot) {
  if (!slot || !slot.credentialIdB64) {
    return { enabled: false, authMode: 'password_only' };
  }
  return {
    enabled: true,
    authMode: slot.authMode,
  };
}

function getPublicHardwareSlotInfo(vaultFilePath) {
  const slot = loadHardwareSlotForVault(vaultFilePath);
  return formatPublicHardwareSlot(slot);
}

/**
 * Limpia ÚNICAMENTE el slot activo del portapapeles (`EmptyClipboard`) si aún contiene
 * el secreto copiado por KVault, dejando 100% intacto el historial `Win + V` del usuario.
 */
async function forceWipeClipboardAndHistory(reasonLabel = 'Secreto purgado del slot activo (Win+V intacto)') {
  if (session.clipboardTimer) {
    clearTimeout(session.clipboardTimer);
    session.clipboardTimer = null;
  }
  if (session.clipboardCountdownInterval) {
    clearInterval(session.clipboardCountdownInterval);
    session.clipboardCountdownInterval = null;
  }

  let expectedSecret = '';
  if (session.lastClipboardEnvelope) {
    try {
      expectedSecret = memoryGuard.unprotectToString(session.lastClipboardEnvelope);
    } catch {
      expectedSecret = '';
    }
    session.lastClipboardEnvelope = null;
  }

  const wiped = await wipeSecureClipboard(expectedSecret);

  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('clipboard:status', {
      active: false,
      label: wiped ? reasonLabel : 'Intacto (El usuario copió otro texto)',
      remainingSeconds: 0,
    });
  }
}

/**
 * Copia un secreto al portapapeles del sistema usando las banderas nativas de exclusión
 * de historial Win+V (`CanIncludeInClipboardHistory=0`, `ExcludeClipboardContentFromMonitorProcessing=1`)
 * y programa la limpieza exclusiva de ese secreto en 12 segundos sin borrar el historial Win+V del usuario.
 */
async function copyWithAutoWipe(secretText, label = 'Secreto') {
  if (session.clipboardTimer) clearTimeout(session.clipboardTimer);
  if (session.clipboardCountdownInterval) clearInterval(session.clipboardCountdownInterval);

  const textStr = String(secretText ?? '');
  session.lastClipboardEnvelope = memoryGuard.protectString(textStr);

  const ok = await setSecureClipboard(textStr);
  if (!ok) {
    clipboard.writeText(textStr);
  }

  const totalSeconds = 12;
  let remaining = totalSeconds;

  const notify = (active, secs) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('clipboard:status', {
        active,
        label,
        remainingSeconds: secs,
      });
    }
  };

  notify(true, remaining);

  session.clipboardCountdownInterval = setInterval(() => {
    remaining -= 1;
    if (remaining > 0) {
      notify(true, remaining);
    }
  }, 1000);

  session.clipboardTimer = setTimeout(async () => {
    await forceWipeClipboardAndHistory('Secreto purgado (Historial Win+V intacto)');
  }, totalSeconds * 1000);
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1340,
    height: 840,
    minWidth: 1024,
    minHeight: 640,
    backgroundColor: '#141619',
    title: 'KVault — Utilitarian AEAD Password Safe (.kvlt)',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
      devTools: true,
    },
  });

  // Activa SetWindowDisplayAffinity en Windows para impedir capturas de pantalla.
  mainWindow.setContentProtection(true);

  Menu.setApplicationMenu(null);
  mainWindow.loadFile(path.join(__dirname, 'ui', 'index.html'));
}

// ============================================================================
// CONTROLADORES IPC
// ============================================================================

ipcMain.handle('vault:get-state', () => getPublicState());

ipcMain.handle('dialog:pick-file', async (_evt, opts = {}) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: opts.title || 'Seleccionar archivo',
    filters: opts.filters || [{ name: 'Todos los archivos', extensions: ['*'] }],
    properties: ['openFile'],
  });
  if (result.canceled || !result.filePaths.length) return null;
  return result.filePaths[0];
});

ipcMain.handle('dialog:pick-save-file', async (_evt, opts = {}) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    title: opts.title || 'Guardar bóveda KVault (.kvlt)',
    defaultPath: opts.defaultPath || 'boveda.kvlt',
    filters: [{ name: 'KVault AEAD Container (.kvlt)', extensions: ['kvlt'] }],
  });
  if (result.canceled || !result.filePath) return null;
  return result.filePath;
});

ipcMain.handle('vault:create', async (_evt, opts) => {
  const {
    name,
    masterPassword,
    cipherId = 1,
    filePath = null,
    keyFilePath = null,
    seedSample = true,
    authMode = 'password_only',
    deviceLabel = 'Yubico Security Key / Flipper U2F',
  } = opts || {};

  if (!masterPassword || masterPassword.length < 4) {
    throw new Error('Ingrese una contraseña maestra (mínimo 4 caracteres; servirá como clave principal o de respaldo).');
  }

  let targetFilePath = filePath || null;
  if (authMode !== 'password_only' && !targetFilePath) {
    const picked = await dialog.showSaveDialog(mainWindow, {
      title: 'Guardar bóveda KVault (.kvlt) para vincular Llave Física FIDO2/U2F',
      defaultPath: `${name || 'boveda_fido'}.kvlt`,
      filters: [{ name: 'KVault AEAD Container (.kvlt)', extensions: ['kvlt'] }],
    });
    if (picked.canceled || !picked.filePath) {
      throw new Error('Para vincular una llave física FIDO2/U2F es necesario elegir dónde guardar el archivo .kvlt.');
    }
    targetFilePath = picked.filePath;
  }

  let effectiveVaultPassword = masterPassword;
  let pendingHwSlot = null;

  if (authMode === 'hardware_passwordless' || authMode === 'hardware_2fa') {
    const enrolled = await enrollHardwareKey({
      vaultName: name || 'KVault',
      deviceLabel,
    });

    if (authMode === 'hardware_passwordless') {
      // En modo Passwordless, la contraseña maestra del archivo se envuelve dentro del Key Slot de la llave física,
      // de modo que el usuario puede abrir la bóveda tocando su llave física O escribiendo su contraseña de respaldo.
      const wrappedSecretB64 = await wrapSecretForHardwareSlot(
        masterPassword,
        enrolled.credentialIdB64,
        enrolled.publicKeySpkiB64
      );
      pendingHwSlot = {
        version: 1,
        authMode: 'hardware_passwordless',
        ...enrolled,
        wrappedSecretB64,
      };
    } else if (authMode === 'hardware_2fa') {
      // En modo Doble Factor (2FA), se genera un factor criptográfico aleatorio de 256 bits que vive en el Key Slot
      // y se combina por HMAC-SHA256 con la contraseña maestra para cifrar el contenedor .kvlt.
      const hwFactorHex = crypto.randomBytes(32).toString('hex');
      effectiveVaultPassword = combinePasswordAndHardwareFactor(masterPassword, hwFactorHex);
      const wrappedSecretB64 = await wrapSecretForHardwareSlot(
        hwFactorHex,
        enrolled.credentialIdB64,
        enrolled.publicKeySpkiB64
      );
      pendingHwSlot = {
        version: 1,
        authMode: 'hardware_2fa',
        ...enrolled,
        wrappedSecretB64,
      };
    }
  }

  wipeSessionMemory();

  session.masterPasswordEnvelope = memoryGuard.protectString(effectiveVaultPassword);
  session.keyFilePath = keyFilePath || null;
  session.hardwareSlot = pendingHwSlot || null;
  session.cipherId = Number(cipherId) === 2 ? 2 : 1;
  session.cipherName = session.cipherId === 2 ? 'aes-256-gcm' : 'chacha20-poly1305';
  session.filePath = targetFilePath;

  const rootGroupId = 'g-root';
  const infraGroupId = 'g-infra';
  const devGroupId = 'g-dev';
  const financeGroupId = 'g-finance';

  session.meta = {
    name: name || 'Corporativo_SecOps',
    format: 'KVLT-v1',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  session.groups = [
    { id: rootGroupId, parentId: null, name: 'Raíz (.kvlt)', icon: 'folder' },
    { id: infraGroupId, parentId: rootGroupId, name: 'Infraestructura & Cloud', icon: 'server' },
    { id: devGroupId, parentId: rootGroupId, name: 'Repositorios & CI/CD', icon: 'terminal' },
    { id: financeGroupId, parentId: rootGroupId, name: 'Criptografía & Llaves', icon: 'key' },
  ];

  const initialEntries = seedSample
    ? [
        {
          id: crypto.randomUUID(),
          groupId: infraGroupId,
          title: 'AWS Production Root Bastion',
          username: 'secops-admin@corp.internal',
          password: generateSecurePassword({ length: 24 }),
          url: 'https://console.aws.amazon.com',
          totpSecret: 'JBSWY3DPEHPK3PXP',
          notes: 'Acceso principal IAM con MFA obligatorio. Rotación trimestral.',
          tags: ['prod', 'aws', 'iam'],
        },
        {
          id: crypto.randomUUID(),
          groupId: devGroupId,
          title: 'GitHub Enterprise Signing Token',
          username: 'release-bot',
          password: generateSecurePassword({ length: 28 }),
          url: 'https://github.com/org/security',
          totpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
          notes: 'Token para firmado de artefactos de compilación en pipeline.',
          tags: ['ci-cd', 'github'],
        },
        {
          id: crypto.randomUUID(),
          groupId: financeGroupId,
          title: 'HSM Offline Backup Passphrase',
          username: 'pkcs11-slot0',
          password: generateSecurePassword({ length: 32 }),
          url: 'pkcs11://hsm-cluster-01.internal',
          totpSecret: '',
          notes: 'Custodia compartida M-of-N. No copiar en máquinas no auditadas.',
          tags: ['hsm', 'critical'],
        },
      ]
    : [];

  hydrateEntriesIntoProtectedMemory(initialEntries);
  session.unlocked = true;
  session.dirty = true;

  if (session.filePath) {
    const payload = exportVaultPayloadForDisk();
    const pwdPlain = memoryGuard.unprotectToString(session.masterPasswordEnvelope);
    saveVaultFileAtomic(session.filePath, payload, pwdPlain, {
      cipher: session.cipherName,
      keyFilePath: session.keyFilePath,
      hardwareSlot: session.hardwareSlot,
    });
    session.dirty = false;
  }

  return getPublicState();
});

ipcMain.handle('hardware:inspect-slot', (_evt, { filePath }) => {
  if (!filePath) return { enabled: false, authMode: 'password_only' };
  return getPublicHardwareSlotInfo(filePath);
});

ipcMain.handle('vault:open', async (_evt, opts) => {
  const { filePath, masterPassword, keyFilePath = null } = opts || {};
  if (!filePath || !fs.existsSync(filePath)) {
    throw new Error('El archivo de bóveda (.kvlt) especificado no existe.');
  }
  if (!masterPassword) {
    throw new Error('Ingrese la contraseña maestra para descifrar la bóveda.');
  }

  const hwSlot = loadHardwareSlotForVault(filePath);
  let effectivePassword = masterPassword;

  if (hwSlot && hwSlot.authMode === 'hardware_2fa') {
    const hwChallenge = await challengeHardwareKey(hwSlot);
    effectivePassword = combinePasswordAndHardwareFactor(masterPassword, hwChallenge.slotSecret);
  }

  const decoded = loadVaultFile(filePath, effectivePassword, keyFilePath);

  wipeSessionMemory();
  session.masterPasswordEnvelope = memoryGuard.protectString(effectivePassword);
  session.keyFilePath = keyFilePath;
  session.filePath = filePath;
  session.hardwareSlot = decoded.hardwareSlot || hwSlot || null;
  session.cipherName = decoded.headerInfo.cipher;
  session.cipherId = session.cipherName === 'aes-256-gcm' ? 2 : 1;
  session.meta = decoded.vault.meta || { name: path.basename(filePath, '.kvlt') };
  session.groups = Array.isArray(decoded.vault.groups) ? decoded.vault.groups : [];
  hydrateEntriesIntoProtectedMemory(decoded.vault.entries || []);
  session.unlocked = true;
  session.dirty = false;

  // Si provenía de un archivo .hwslot.json antiguo separado, consolidarlo dentro del binario .kvlt automáticamente
  if (!decoded.hardwareSlot && hwSlot) {
    const payload = exportVaultPayloadForDisk();
    saveVaultFileAtomic(filePath, payload, effectivePassword, {
      cipher: session.cipherName,
      keyFilePath: session.keyFilePath,
      hardwareSlot: hwSlot,
    });
  }

  return getPublicState();
});

ipcMain.handle('vault:open-hardware', async (_evt, opts) => {
  const { filePath, keyFilePath = null } = opts || {};
  if (!filePath || !fs.existsSync(filePath)) {
    throw new Error('Seleccione primero un archivo de bóveda (.kvlt) válido.');
  }

  const hwSlot = loadHardwareSlotForVault(filePath);
  if (!hwSlot) {
    throw new Error('Esta bóveda no tiene una llave física FIDO2/U2F vinculada.');
  }
  if (hwSlot.authMode === 'hardware_2fa') {
    throw new Error('Esta bóveda está en modo Doble Factor (2FA): ingrese su contraseña maestra y luego toque su llave física.');
  }

  const hwChallenge = await challengeHardwareKey(hwSlot);
  const effectivePassword = hwChallenge.slotSecret;

  const decoded = loadVaultFile(filePath, effectivePassword, keyFilePath);

  wipeSessionMemory();
  session.masterPasswordEnvelope = memoryGuard.protectString(effectivePassword);
  session.keyFilePath = keyFilePath;
  session.filePath = filePath;
  session.hardwareSlot = decoded.hardwareSlot || hwSlot || null;
  session.cipherName = decoded.headerInfo.cipher;
  session.cipherId = session.cipherName === 'aes-256-gcm' ? 2 : 1;
  session.meta = decoded.vault.meta || { name: path.basename(filePath, '.kvlt') };
  session.groups = Array.isArray(decoded.vault.groups) ? decoded.vault.groups : [];
  hydrateEntriesIntoProtectedMemory(decoded.vault.entries || []);
  session.unlocked = true;
  session.dirty = false;

  // Si provenía de un archivo .hwslot.json antiguo separado, consolidarlo dentro del binario .kvlt automáticamente
  if (!decoded.hardwareSlot && hwSlot) {
    const payload = exportVaultPayloadForDisk();
    saveVaultFileAtomic(filePath, payload, effectivePassword, {
      cipher: session.cipherName,
      keyFilePath: session.keyFilePath,
      hardwareSlot: hwSlot,
    });
  }

  return getPublicState();
});

ipcMain.handle('hardware:configure', async (_evt, { authMode, deviceLabel, currentMasterPassword }) => {
  if (!session.unlocked) throw new Error('Desbloquee la bóveda antes de configurar llaves físicas.');

  if (!session.filePath) {
    const picked = await dialog.showSaveDialog(mainWindow, {
      title: 'Guardar bóveda KVault (.kvlt) antes de vincular llave física',
      defaultPath: `${(session.meta && session.meta.name) || 'boveda'}.kvlt`,
      filters: [{ name: 'KVault AEAD Container (.kvlt)', extensions: ['kvlt'] }],
    });
    if (picked.canceled || !picked.filePath) {
      throw new Error('Debe guardar la bóveda en disco para vincular una llave física.');
    }
    session.filePath = picked.filePath;
  }

  if (authMode === 'password_only') {
    if (currentMasterPassword && currentMasterPassword.length >= 4) {
      session.masterPasswordEnvelope = memoryGuard.protectString(currentMasterPassword);
    }
    session.hardwareSlot = null;
    const payload = exportVaultPayloadForDisk();
    const pwdPlain = memoryGuard.unprotectToString(session.masterPasswordEnvelope);
    saveVaultFileAtomic(session.filePath, payload, pwdPlain, {
      cipher: session.cipherName,
      keyFilePath: session.keyFilePath,
      hardwareSlot: null,
    });
    removeLegacyHardwareSlotFile(session.filePath);
    session.dirty = false;
    return getPublicState();
  }

  const enrolled = await enrollHardwareKey({
    vaultName: session.meta?.name || 'KVault',
    deviceLabel: deviceLabel || 'Yubico Security Key / Flipper U2F',
  });

  if (authMode === 'hardware_passwordless') {
    const currentEffectivePwd = memoryGuard.unprotectToString(session.masterPasswordEnvelope);
    const wrappedSecretB64 = await wrapSecretForHardwareSlot(
      currentEffectivePwd,
      enrolled.credentialIdB64,
      enrolled.publicKeySpkiB64
    );
    session.hardwareSlot = {
      version: 1,
      authMode: 'hardware_passwordless',
      ...enrolled,
      wrappedSecretB64,
    };
    const payload = exportVaultPayloadForDisk();
    saveVaultFileAtomic(session.filePath, payload, currentEffectivePwd, {
      cipher: session.cipherName,
      keyFilePath: session.keyFilePath,
      hardwareSlot: session.hardwareSlot,
    });
    session.dirty = false;
  } else if (authMode === 'hardware_2fa') {
    if (!currentMasterPassword || currentMasterPassword.length < 4) {
      throw new Error('Ingrese su contraseña maestra para vincularla en modo Doble Factor (2FA).');
    }
    const hwFactorHex = crypto.randomBytes(32).toString('hex');
    const newEffectivePwd = combinePasswordAndHardwareFactor(currentMasterPassword, hwFactorHex);
    session.masterPasswordEnvelope = memoryGuard.protectString(newEffectivePwd);

    const wrappedSecretB64 = await wrapSecretForHardwareSlot(
      hwFactorHex,
      enrolled.credentialIdB64,
      enrolled.publicKeySpkiB64
    );
    session.hardwareSlot = {
      version: 1,
      authMode: 'hardware_2fa',
      ...enrolled,
      wrappedSecretB64,
    };

    const payload = exportVaultPayloadForDisk();
    saveVaultFileAtomic(session.filePath, payload, newEffectivePwd, {
      cipher: session.cipherName,
      keyFilePath: session.keyFilePath,
      hardwareSlot: session.hardwareSlot,
    });
    session.dirty = false;
  }

  return getPublicState();
});

ipcMain.handle('hardware:remove', () => {
  if (!session.unlocked || !session.filePath) {
    throw new Error('No hay bóveda activa con archivo asociado.');
  }
  const existingSlot = session.hardwareSlot || loadHardwareSlotForVault(session.filePath);
  if (existingSlot && existingSlot.authMode === 'hardware_2fa') {
    throw new Error('Para pasar de Doble Factor (2FA) a Solo Contraseña, use la opción "Solo Contraseña" en el modal de Llave Física e ingrese su contraseña maestra.');
  }
  session.hardwareSlot = null;
  const payload = exportVaultPayloadForDisk();
  const pwdPlain = memoryGuard.unprotectToString(session.masterPasswordEnvelope);
  saveVaultFileAtomic(session.filePath, payload, pwdPlain, {
    cipher: session.cipherName,
    keyFilePath: session.keyFilePath,
    hardwareSlot: null,
  });
  return getPublicState();
});

ipcMain.handle('vault:save', async () => {
  if (!session.unlocked) throw new Error('La bóveda está bloqueada.');

  let targetPath = session.filePath;
  if (!targetPath) {
    const picked = await dialog.showSaveDialog(mainWindow, {
      title: 'Guardar bóveda KVault (.kvlt)',
      defaultPath: `${(session.meta && session.meta.name) || 'boveda'}.kvlt`,
      filters: [{ name: 'KVault AEAD Container (.kvlt)', extensions: ['kvlt'] }],
    });
    if (picked.canceled || !picked.filePath) {
      return { saved: false, state: getPublicState() };
    }
    targetPath = picked.filePath;
    session.filePath = targetPath;
  }

  const payload = exportVaultPayloadForDisk();
  const pwdPlain = memoryGuard.unprotectToString(session.masterPasswordEnvelope);
  saveVaultFileAtomic(targetPath, payload, pwdPlain, {
    cipher: session.cipherName,
    keyFilePath: session.keyFilePath,
    hardwareSlot: session.hardwareSlot,
  });
  session.dirty = false;

  return { saved: true, filePath: targetPath, state: getPublicState() };
});

ipcMain.handle('vault:lock', async () => {
  wipeSessionMemory();
  await forceWipeClipboardAndHistory('Bóveda Bloqueada — Portapapeles y Win+V Purgados');
  return getPublicState();
});

ipcMain.handle('clipboard:wipe-now', async () => {
  await forceWipeClipboardAndHistory('Purgado Manual (Win32 + Historial Win+V)');
  return { wiped: true };
});

ipcMain.handle('entry:upsert', async (_evt, entryInput) => {
  if (!session.unlocked) throw new Error('La bóveda está bloqueada.');

  const isExisting = entryInput.id && session.entries.has(entryInput.id);
  const existing = isExisting ? session.entries.get(entryInput.id) : null;
  const id = isExisting ? entryInput.id : crypto.randomUUID();

  let pwdPlain = '';
  if (typeof entryInput.password === 'string' && entryInput.password !== '__KEEP_EXISTING__') {
    pwdPlain = entryInput.password;
  } else if (existing && existing._pwdEnvelope) {
    pwdPlain = memoryGuard.unprotectToString(existing._pwdEnvelope);
  }

  let totpPlain = '';
  if (typeof entryInput.totpSecret === 'string' && entryInput.totpSecret !== '__KEEP_EXISTING__') {
    totpPlain = entryInput.totpSecret.trim();
  } else if (existing && existing._totpEnvelope) {
    totpPlain = memoryGuard.unprotectToString(existing._totpEnvelope);
  }

  const pwdEnvelope = memoryGuard.protectString(pwdPlain);
  const totpEnvelope = memoryGuard.protectString(totpPlain);
  const entropy = calculatePasswordEntropy(pwdPlain);

  const now = new Date().toISOString();
  session.entries.set(id, {
    id,
    groupId: entryInput.groupId || (existing ? existing.groupId : session.groups[0]?.id || 'g-root'),
    title: String(entryInput.title || 'Sin título').trim(),
    username: String(entryInput.username || '').trim(),
    url: String(entryInput.url || '').trim(),
    notes: String(entryInput.notes || ''),
    tags: Array.isArray(entryInput.tags)
      ? entryInput.tags
      : String(entryInput.tags || '')
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
    hasPassword: pwdPlain.length > 0,
    hasTotp: totpPlain.length > 0,
    entropy,
    protectedStats: {
      encryptedBytes: pwdEnvelope.byteLength,
      algorithm: 'chacha20-poly1305-ephemeral',
    },
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
    _pwdEnvelope: pwdEnvelope,
    _totpEnvelope: totpEnvelope,
  });

  session.dirty = true;
  return { id, state: getPublicState() };
});

ipcMain.handle('entry:delete', (_evt, entryId) => {
  if (!session.unlocked) throw new Error('La bóveda está bloqueada.');
  if (session.entries.has(entryId)) {
    session.entries.delete(entryId);
    session.dirty = true;
  }
  return getPublicState();
});

ipcMain.handle('group:create', (_evt, groupInput) => {
  if (!session.unlocked) throw new Error('La bóveda está bloqueada.');
  const name = String(groupInput?.name || '').trim();
  if (!name) throw new Error('El nombre del grupo no puede estar vacío.');
  const newGroup = {
    id: `g-${crypto.randomUUID().slice(0, 8)}`,
    parentId: groupInput.parentId || session.groups[0]?.id || null,
    name,
    icon: 'folder',
  };
  session.groups.push(newGroup);
  session.dirty = true;
  return { group: newGroup, state: getPublicState() };
});

ipcMain.handle('secret:reveal', (_evt, { entryId, field }) => {
  if (!session.unlocked) throw new Error('Bóveda bloqueada.');
  const item = session.entries.get(entryId);
  if (!item) throw new Error('Entrada no encontrada.');

  if (field === 'totp') {
    return memoryGuard.unprotectToString(item._totpEnvelope);
  }
  return memoryGuard.unprotectToString(item._pwdEnvelope);
});

ipcMain.handle('secret:copy', async (_evt, { entryId, field }) => {
  if (!session.unlocked) throw new Error('Bóveda bloqueada.');
  const item = session.entries.get(entryId);
  if (!item) throw new Error('Entrada no encontrada.');

  if (field === 'username') {
    await copyWithAutoWipe(item.username, `Usuario (${item.title})`);
    return { copied: true, label: 'Usuario' };
  }
  if (field === 'url') {
    await copyWithAutoWipe(item.url, `URL (${item.title})`);
    return { copied: true, label: 'URL' };
  }
  if (field === 'title') {
    await copyWithAutoWipe(item.title, `Título (${item.title})`);
    return { copied: true, label: 'Título' };
  }
  if (field === 'notes') {
    await copyWithAutoWipe(item.notes, `Notas (${item.title})`);
    return { copied: true, label: 'Notas' };
  }
  if (field === 'totp') {
    const secret = memoryGuard.unprotectToString(item._totpEnvelope);
    if (!secret) throw new Error('Esta entrada no tiene semilla TOTP configurada.');
    const totp = generateTotp(secret);
    await copyWithAutoWipe(totp.rawCode || totp.code.replace(/\s+/g, ''), `TOTP 6-Digit (${item.title})`);
    return { copied: true, label: 'TOTP' };
  }

  const secret = memoryGuard.unprotectToString(item._pwdEnvelope);
  await copyWithAutoWipe(secret, `Contraseña (${item.title})`);
  return { copied: true, label: 'Contraseña' };
});

ipcMain.handle('url:open', async (_evt, { entryId }) => {
  if (!session.unlocked) throw new Error('Bóveda bloqueada.');
  const item = session.entries.get(entryId);
  if (!item || !item.url) throw new Error('Esta entrada no tiene una URL configurada.');

  let targetUrl = item.url.trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(targetUrl)) {
    targetUrl = `https://${targetUrl}`;
  }

  await shell.openExternal(targetUrl);
  return { opened: true, url: targetUrl };
});

ipcMain.handle('autotype:run', async (_evt, { entryId, mode = 'enter' }) => {
  if (!session.unlocked) throw new Error('Bóveda bloqueada.');
  const item = session.entries.get(entryId);
  if (!item) throw new Error('Entrada no encontrada.');

  const pwdPlain = memoryGuard.unprotectToString(item._pwdEnvelope);
  const totpSecret = memoryGuard.unprotectToString(item._totpEnvelope);
  const totpCode = totpSecret ? (generateTotp(totpSecret).rawCode || '') : '';

  const res = await performAutoType({
    username: item.username,
    password: pwdPlain,
    totpCode,
    mode,
    mainWindow,
  });

  return res;
});

ipcMain.handle('entry:duplicate', (_evt, entryId) => {
  if (!session.unlocked) throw new Error('La bóveda está bloqueada.');
  const existing = session.entries.get(entryId);
  if (!existing) throw new Error('Entrada no encontrada.');

  const newId = crypto.randomUUID();
  const pwdPlain = memoryGuard.unprotectToString(existing._pwdEnvelope);
  const totpPlain = memoryGuard.unprotectToString(existing._totpEnvelope);
  const pwdEnvelope = memoryGuard.protectString(pwdPlain);
  const totpEnvelope = memoryGuard.protectString(totpPlain);
  const now = new Date().toISOString();

  session.entries.set(newId, {
    ...existing,
    id: newId,
    title: `${existing.title} (Copia)`,
    createdAt: now,
    updatedAt: now,
    _pwdEnvelope: pwdEnvelope,
    _totpEnvelope: totpEnvelope,
  });

  session.dirty = true;
  return { id: newId, state: getPublicState() };
});

ipcMain.handle('secret:totp', (_evt, { entryId }) => {
  if (!session.unlocked) throw new Error('Bóveda bloqueada.');
  const item = session.entries.get(entryId);
  if (!item || !item.hasTotp) return null;

  const secret = memoryGuard.unprotectToString(item._totpEnvelope);
  if (!secret) return null;
  try {
    return generateTotp(secret);
  } catch (err) {
    return { error: err.message };
  }
});

ipcMain.handle('crypto:generate-password', (_evt, opts = {}) => {
  const password = generateSecurePassword(opts);
  const entropy = calculatePasswordEntropy(password);
  return { password, entropy };
});

ipcMain.handle('crypto:evaluate-password', (_evt, password = '') => {
  return calculatePasswordEntropy(String(password));
});

function mergeImportedDataIntoSession(imported) {
  const groupIdMap = new Map();
  const rootGroupId = session.groups[0]?.id || 'g-root';

  for (const grp of imported.groups || []) {
    const newId = `g-${crypto.randomUUID().slice(0, 8)}`;
    groupIdMap.set(grp.id, newId);
    session.groups.push({
      id: newId,
      parentId: rootGroupId,
      name: grp.name,
      icon: 'folder',
    });
  }

  let importedCount = 0;
  for (const raw of imported.entries || []) {
    const id = crypto.randomUUID();
    const pwdPlain = String(raw.password || '');
    const totpPlain = String(raw.totpSecret || '');
    const pwdEnvelope = memoryGuard.protectString(pwdPlain);
    const totpEnvelope = memoryGuard.protectString(totpPlain);
    const entropy = calculatePasswordEntropy(pwdPlain);

    session.entries.set(id, {
      id,
      groupId: groupIdMap.get(raw.groupId) || rootGroupId,
      title: raw.title || 'Entrada importada',
      username: raw.username || '',
      url: raw.url || '',
      notes: raw.notes || '',
      tags: ['keepass-import'],
      hasPassword: pwdPlain.length > 0,
      hasTotp: totpPlain.length > 0,
      entropy,
      protectedStats: {
        encryptedBytes: pwdEnvelope.byteLength,
        algorithm: 'chacha20-poly1305-ephemeral',
      },
      createdAt: raw.modifiedAt || new Date().toISOString(),
      updatedAt: raw.modifiedAt || new Date().toISOString(),
      _pwdEnvelope: pwdEnvelope,
      _totpEnvelope: totpEnvelope,
    });
    importedCount++;
  }

  session.dirty = true;
  return importedCount;
}

ipcMain.handle('importer:keepass', (_evt, { filePath }) => {
  if (!session.unlocked) throw new Error('Desbloquee o cree una bóveda antes de importar.');
  if (!filePath || !fs.existsSync(filePath)) {
    throw new Error('Archivo de importación KeePass no encontrado.');
  }
  const imported = importKeePassFile(filePath);
  const importedCount = mergeImportedDataIntoSession(imported);
  return {
    importedCount,
    sourceFormat: imported.sourceFormat || 'KeePass',
    state: getPublicState(),
  };
});

ipcMain.handle('importer:load-sample', () => {
  if (!session.unlocked) throw new Error('Desbloquee o cree una bóveda antes de importar.');
  const samplePath = path.join(__dirname, '..', 'samples', 'keepass_export_sample.xml');
  if (!fs.existsSync(samplePath)) {
    throw new Error('No se encontró samples/keepass_export_sample.xml');
  }
  const imported = importKeePassFile(samplePath);
  const importedCount = mergeImportedDataIntoSession(imported);
  return {
    importedCount,
    sourceFormat: imported.sourceFormat || 'KeePass 2.x XML',
    state: getPublicState(),
  };
});

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  wipeSessionMemory();
  clipboard.clear();
  if (process.platform !== 'darwin') app.quit();
});
