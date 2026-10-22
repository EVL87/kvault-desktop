'use strict';

const { contextBridge, ipcRenderer } = require('electron');

/**
 * Puente IPC estrictamente tipado (Context Isolation + Sandbox).
 * El Renderer (UI) NUNCA recibe el objeto ProtectedMemory ni las llaves criptográficas;
 * solo interactúa mediante descriptores de metadatos y solicitudes efímeras.
 */
contextBridge.exposeInMainWorld('kvault', Object.freeze({
  // Gestión de bóveda (.kvlt) y Llaves Físicas FIDO2 / U2F (Yubico / Flipper Zero)
  createVault: (opts) => ipcRenderer.invoke('vault:create', opts),
  openVault: (opts) => ipcRenderer.invoke('vault:open', opts),
  openVaultWithHardwareKey: (opts) => ipcRenderer.invoke('vault:open-hardware', opts),
  inspectHardwareSlot: (filePath) => ipcRenderer.invoke('hardware:inspect-slot', { filePath }),
  configureHardwareKey: (opts) => ipcRenderer.invoke('hardware:configure', opts),
  removeHardwareKey: () => ipcRenderer.invoke('hardware:remove'),
  saveVault: () => ipcRenderer.invoke('vault:save'),
  lockVault: () => ipcRenderer.invoke('vault:lock'),
  getState: () => ipcRenderer.invoke('vault:get-state'),

  // Diálogos nativos del SO
  pickFile: (opts) => ipcRenderer.invoke('dialog:pick-file', opts),
  pickSaveFile: (opts) => ipcRenderer.invoke('dialog:pick-save-file', opts),

  // Operaciones sobre entradas y grupos
  upsertEntry: (entryInput) => ipcRenderer.invoke('entry:upsert', entryInput),
  duplicateEntry: (entryId) => ipcRenderer.invoke('entry:duplicate', entryId),
  deleteEntry: (entryId) => ipcRenderer.invoke('entry:delete', entryId),
  createGroup: (groupInput) => ipcRenderer.invoke('group:create', groupInput),

  // Acceso efímero a secretos en ProtectedMemory, apertura de URL, portapapeles seguro y Auto-Type
  revealSecret: (entryId, field) => ipcRenderer.invoke('secret:reveal', { entryId, field }),
  copySecret: (entryId, field) => ipcRenderer.invoke('secret:copy', { entryId, field }),
  wipeClipboardNow: () => ipcRenderer.invoke('clipboard:wipe-now'),
  openUrl: (entryId) => ipcRenderer.invoke('url:open', { entryId }),
  runAutoType: (entryId, mode = 'enter') => ipcRenderer.invoke('autotype:run', { entryId, mode }),
  getTotp: (entryId) => ipcRenderer.invoke('secret:totp', { entryId }),

  // Utilidades criptográficas, tema e importador KeePass 2.x
  setThemeMode: (mode) => ipcRenderer.invoke('theme:set', { mode }),
  generatePassword: (opts) => ipcRenderer.invoke('crypto:generate-password', opts),
  evaluatePassword: (password) => ipcRenderer.invoke('crypto:evaluate-password', password),
  importKeePassFile: (filePath) => ipcRenderer.invoke('importer:keepass', { filePath }),
  loadSampleKeePass: () => ipcRenderer.invoke('importer:load-sample'),

  // Suscripción a eventos desde Main Process (ej. temporizador de portapapeles o auto-lock)
  onClipboardStatus: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('clipboard:status', handler);
    return () => ipcRenderer.removeListener('clipboard:status', handler);
  },
  onVaultLocked: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('vault:locked', handler);
    return () => ipcRenderer.removeListener('vault:locked', handler);
  },
}));
