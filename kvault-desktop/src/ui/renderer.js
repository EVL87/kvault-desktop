'use strict';

(() => {
  const api = window.kvault;

  let appState = {
    unlocked: false,
    groups: [],
    entries: [],
    selectedGroupId: 'ALL',
    selectedEntryId: null,
    searchQuery: '',
    revealedPasswordEntryId: null,
    totpInterval: null,
    toastTimer: null,
  };

  // Referencias DOM — Lock Screen
  const lockScreen = document.getElementById('lockScreen');
  const workbench = document.getElementById('workbench');
  const tabCreateBtn = document.getElementById('tabCreateBtn');
  const tabOpenBtn = document.getElementById('tabOpenBtn');
  const createVaultForm = document.getElementById('createVaultForm');
  const openVaultForm = document.getElementById('openVaultForm');
  const lockError = document.getElementById('lockError');

  // Referencias DOM — Workbench
  const splitView = document.getElementById('splitView');
  const paneLeft = document.getElementById('paneLeft');
  const paneBottom = document.getElementById('paneBottom');
  const inspectorToggleIcon = document.getElementById('inspectorToggleIcon');
  const inspCollapsedSummary = document.getElementById('inspCollapsedSummary');
  const groupTreeList = document.getElementById('groupTreeList');
  const entryTableBody = document.getElementById('entryTableBody');
  const searchInput = document.getElementById('searchInput');
  const vaultTitleLabel = document.getElementById('vaultTitleLabel');

  // Auditoría
  const auditTotalEntries = document.getElementById('auditTotalEntries');
  const auditAvgEntropy = document.getElementById('auditAvgEntropy');
  const auditWeakCount = document.getElementById('auditWeakCount');
  const auditTotpCount = document.getElementById('auditTotpCount');

  // Inspector
  const inspectorEmpty = document.getElementById('inspectorEmpty');
  const inspectorContent = document.getElementById('inspectorContent');
  const inspectorActions = document.getElementById('inspectorActions');
  const inspEntryId = document.getElementById('inspEntryId');
  const inspTitle = document.getElementById('inspTitle');
  const inspTags = document.getElementById('inspTags');
  const inspUsername = document.getElementById('inspUsername');
  const inspPassword = document.getElementById('inspPassword');
  const inspMemoryBadge = document.getElementById('inspMemoryBadge');
  const inspEntropyBadge = document.getElementById('inspEntropyBadge');
  const inspTotpBlock = document.getElementById('inspTotpBlock');
  const inspTotpCode = document.getElementById('inspTotpCode');
  const inspTotpRemaining = document.getElementById('inspTotpRemaining');
  const inspTotpBar = document.getElementById('inspTotpBar');
  const inspUrl = document.getElementById('inspUrl');
  const inspNotes = document.getElementById('inspNotes');
  const inspTimestamps = document.getElementById('inspTimestamps');
  const btnToggleRevealPwd = document.getElementById('btnToggleRevealPwd');

  // Status Bar & Context Menu & Toast
  const statusDot = document.getElementById('statusDot');
  const statusVaultState = document.getElementById('statusVaultState');
  const statusCipherInfo = document.getElementById('statusCipherInfo');
  const statusClipboardTimer = document.getElementById('statusClipboardTimer');
  const statusFilePath = document.getElementById('statusFilePath');
  const contextMenu = document.getElementById('contextMenu');
  const actionToast = document.getElementById('actionToast');

  // Modales
  const entryModal = document.getElementById('entryModal');
  const entryForm = document.getElementById('entryForm');
  const entryModalTitle = document.getElementById('entryModalTitle');
  const entryIdField = document.getElementById('entryIdField');
  const entryTitleField = document.getElementById('entryTitleField');
  const entryGroupField = document.getElementById('entryGroupField');
  const entryUserField = document.getElementById('entryUserField');
  const entryUrlField = document.getElementById('entryUrlField');
  const entryPasswordField = document.getElementById('entryPasswordField');
  const entryTotpField = document.getElementById('entryTotpField');
  const entryTagsField = document.getElementById('entryTagsField');
  const entryNotesField = document.getElementById('entryNotesField');

  const generatorModal = document.getElementById('generatorModal');
  const genOutputText = document.getElementById('genOutputText');
  const genEntropyBadge = document.getElementById('genEntropyBadge');
  const genLengthRange = document.getElementById('genLengthRange');
  const genLengthLabel = document.getElementById('genLengthLabel');

  const hardwareModal = document.getElementById('hardwareModal');
  const hardwareForm = document.getElementById('hardwareForm');
  const hwStatusBadge = document.getElementById('hwStatusBadge');
  const hwAuthModeSelect = document.getElementById('hwAuthModeSelect');
  const hwCurrentPwdInput = document.getElementById('hwCurrentPwdInput');
  const shortcutsModal = document.getElementById('shortcutsModal');

  function showToast(msg) {
    if (appState.toastTimer) clearTimeout(appState.toastTimer);
    actionToast.textContent = msg;
    actionToast.classList.remove('hidden');
    appState.toastTimer = setTimeout(() => {
      actionToast.classList.add('hidden');
    }, 2400);
  }

  function showError(msg) {
    if (!msg) {
      lockError.classList.add('hidden');
      lockError.textContent = '';
      return;
    }
    lockError.textContent = `[ERROR]: ${msg}`;
    lockError.classList.remove('hidden');
  }

  function applyState(state) {
    appState.unlocked = Boolean(state.unlocked);
    appState.groups = state.groups || [];
    appState.entries = state.entries || [];
    appState.hardwareSlot = state.hardwareSlot || { enabled: false, authMode: 'password_only' };

    if (!appState.unlocked) {
      stopTotpLoop();
      hideContextMenu();
      lockScreen.classList.remove('hidden');
      workbench.classList.add('hidden');
      statusDot.classList.add('dot-warn');
      statusVaultState.textContent = 'LOCKED (RAM ZEROIZED)';
      statusCipherInfo.textContent = 'AEAD: --';
      statusFilePath.textContent = 'Archivo: Ninguno';
      return;
    }

    lockScreen.classList.add('hidden');
    workbench.classList.remove('hidden');

    statusDot.classList.remove('dot-warn');
    statusVaultState.textContent = state.dirty ? 'UNLOCKED [MODIFICADO*]' : 'UNLOCKED [SYNC]';
    statusCipherInfo.textContent = `AEAD: ${(state.cipherName || '').toUpperCase()}`;
    statusFilePath.textContent = state.filePath ? `Archivo: ${state.filePath}` : 'Archivo: [En Memoria — Sin guardar]';
    vaultTitleLabel.textContent = state.meta?.name || 'KVault';

    if (state.audit) {
      auditTotalEntries.textContent = String(state.audit.totalEntries);
      auditAvgEntropy.textContent = `${state.audit.avgEntropy} bits`;
      auditWeakCount.textContent = String(state.audit.weakCount);
      auditWeakCount.style.color = state.audit.weakCount > 0 ? 'var(--status-danger)' : 'var(--status-ok)';
      auditTotpCount.textContent = String(state.audit.totpCount);
    }

    renderGroupTree();
    renderEntryTable();
    renderInspector();
  }

  function renderGroupTree() {
    groupTreeList.innerHTML = '';

    const allLi = document.createElement('li');
    allLi.className = `group-item ${appState.selectedGroupId === 'ALL' ? 'active' : ''}`;
    allLi.innerHTML = `<span>[*] Todos los Registros</span><span class="group-count">${appState.entries.length}</span>`;
    allLi.addEventListener('click', () => {
      appState.selectedGroupId = 'ALL';
      renderGroupTree();
      renderEntryTable();
      renderInspector();
    });
    groupTreeList.appendChild(allLi);

    for (const grp of appState.groups) {
      const count = appState.entries.filter((e) => e.groupId === grp.id).length;
      const li = document.createElement('li');
      li.className = `group-item ${appState.selectedGroupId === grp.id ? 'active' : ''}`;
      const prefix = grp.parentId ? '  ├─ ' : '■ ';
      li.innerHTML = `<span>${prefix}${escapeHtml(grp.name)}</span><span class="group-count">${count}</span>`;
      li.addEventListener('click', () => {
        appState.selectedGroupId = grp.id;
        renderGroupTree();
        renderEntryTable();
        renderInspector();
      });
      groupTreeList.appendChild(li);
    }
  }

  function getFilteredEntries() {
    const q = appState.searchQuery.trim().toLowerCase();
    return appState.entries.filter((e) => {
      if (appState.selectedGroupId !== 'ALL' && e.groupId !== appState.selectedGroupId) {
        return false;
      }
      if (!q) return true;
      const haystack = `${e.title} ${e.username} ${e.url} ${(e.tags || []).join(' ')}`.toLowerCase();
      return haystack.includes(q);
    });
  }

  function getEntropyBadgeHtml(entropy) {
    if (!entropy) return '<span class="badge">--</span>';
    const bits = entropy.bits || 0;
    let cls = 'badge-ok';
    if (bits < 55) cls = 'badge-danger';
    else if (bits < 75) cls = 'badge-warn';
    return `<span class="badge ${cls}">${bits}b (${escapeHtml(entropy.level)})</span>`;
  }

  // ==========================================================================
  // ACCIONES RÁPIDAS ESTILO KEEPASS (COPIAR, ABRIR URL, AUTO-TYPE, EDITAR)
  // ==========================================================================

  async function doCopyField(entryId, field) {
    if (!entryId) return;
    try {
      const res = await api.copySecret(entryId, field);
      showToast(`Copiado (Excluido de Win+V): ${res.label || field} — Purga en 12s`);
    } catch (err) {
      showToast(`Error: ${err.message}`);
    }
  }

  async function doOpenUrl(entryId) {
    if (!entryId) return;
    try {
      const res = await api.openUrl(entryId);
      showToast(`Abriendo URL: ${res.url}`);
    } catch (err) {
      showToast(`Error URL: ${err.message}`);
    }
  }

  async function doAutoType(entryId, mode = 'enter') {
    if (!entryId) return;
    try {
      showToast(`Auto-Type iniciado (${mode})... cambiando a ventana anterior`);
      await api.runAutoType(entryId, mode);
    } catch (err) {
      showToast(`Error Auto-Type: ${err.message}`);
    }
  }

  async function openEditModalForEntry(entryId) {
    const entry = appState.entries.find((e) => e.id === entryId);
    if (!entry) return;
    entryModalTitle.textContent = `Editar Entrada: ${entry.title}`;
    entryIdField.value = entry.id;
    entryTitleField.value = entry.title;
    entryUserField.value = entry.username;
    entryUrlField.value = entry.url;
    entryPasswordField.value = await api.revealSecret(entry.id, 'password');
    entryTotpField.value = entry.hasTotp ? await api.revealSecret(entry.id, 'totp') : '';
    entryTagsField.value = (entry.tags || []).join(', ');
    entryNotesField.value = entry.notes || '';
    populateGroupSelect(entry.groupId);
    entryModal.classList.remove('hidden');
    entryTitleField.focus();
  }

  async function doDuplicateEntry(entryId) {
    if (!entryId) return;
    const res = await api.duplicateEntry(entryId);
    appState.selectedEntryId = res.id;
    applyState(res.state);
    showToast('Entrada duplicada');
  }

  async function doDeleteEntry(entryId) {
    if (!entryId) return;
    const state = await api.deleteEntry(entryId);
    appState.selectedEntryId = null;
    applyState(state);
    showToast('Entrada eliminada');
  }

  // ==========================================================================
  // TABLA CENTRAL CON DOBLE CLIC POR CELDA Y MENÚ CONTEXTUAL (COMO KEEPASS)
  // ==========================================================================

  function renderEntryTable() {
    entryTableBody.innerHTML = '';
    const filtered = getFilteredEntries();

    if (filtered.length > 0 && !filtered.some((e) => e.id === appState.selectedEntryId)) {
      appState.selectedEntryId = filtered[0].id;
      appState.revealedPasswordEntryId = null;
    } else if (filtered.length === 0) {
      appState.selectedEntryId = null;
    }

    for (const entry of filtered) {
      const tr = document.createElement('tr');
      if (entry.id === appState.selectedEntryId) tr.classList.add('selected');

      const totpBadge = entry.hasTotp
        ? '<span class="badge badge-ok" title="Doble clic para copiar código TOTP">TOTP</span>'
        : '<span class="mono" style="color: var(--text-muted);">--</span>';

      tr.innerHTML = `
        <td class="cell-interactive" data-col="title" style="font-weight: 600;" title="Doble clic para editar entrada">${escapeHtml(entry.title)}</td>
        <td class="mono cell-interactive" data-col="username" title="Doble clic para copiar Usuario [Ctrl+B]">${escapeHtml(entry.username || '--')}</td>
        <td class="mono cell-interactive ${entry.url ? 'cell-link' : ''}" data-col="url" title="Doble clic para abrir URL en navegador [Ctrl+U]">${escapeHtml(entry.url || '--')}</td>
        <td class="cell-interactive" data-col="totp" style="text-align: center;" title="Doble clic para copiar 2FA TOTP [Ctrl+T]">${totpBadge}</td>
        <td class="cell-interactive" data-col="password" title="Doble clic para copiar Contraseña [Ctrl+C]">${getEntropyBadgeHtml(entry.entropy)}</td>
      `;

      // Clic simple: seleccionar fila
      tr.addEventListener('click', () => {
        appState.selectedEntryId = entry.id;
        appState.revealedPasswordEntryId = null;
        renderEntryTable();
        renderInspector();
      });

      // Doble clic sobre cada celda: ejecuta la acción específica de KeePass
      tr.addEventListener('dblclick', async (ev) => {
        const cell = ev.target.closest('td');
        const col = cell ? cell.dataset.col : 'title';
        appState.selectedEntryId = entry.id;

        if (col === 'url' && entry.url) {
          await doOpenUrl(entry.id);
        } else if (col === 'username') {
          await doCopyField(entry.id, 'username');
        } else if (col === 'totp' && entry.hasTotp) {
          await doCopyField(entry.id, 'totp');
        } else if (col === 'password') {
          await doCopyField(entry.id, 'password');
        } else {
          await openEditModalForEntry(entry.id);
        }
      });

      // Clic derecho: abre menú contextual estilo KeePass
      tr.addEventListener('contextmenu', (ev) => {
        ev.preventDefault();
        appState.selectedEntryId = entry.id;
        appState.revealedPasswordEntryId = null;
        renderEntryTable();
        renderInspector();
        showContextMenu(ev.clientX, ev.clientY);
      });

      entryTableBody.appendChild(tr);
    }
  }

  async function renderInspector() {
    stopTotpLoop();
    const entry = appState.entries.find((e) => e.id === appState.selectedEntryId);
    if (!entry) {
      inspectorEmpty.classList.remove('hidden');
      inspectorContent.classList.add('hidden');
      inspectorActions.classList.add('hidden');
      if (inspCollapsedSummary) inspCollapsedSummary.textContent = '';
      return;
    }

    inspectorEmpty.classList.add('hidden');
    inspectorContent.classList.remove('hidden');
    inspectorActions.classList.remove('hidden');

    if (inspCollapsedSummary) {
      inspCollapsedSummary.textContent = `— ${entry.title}`;
    }
    inspEntryId.textContent = `UUID: ${entry.id.slice(0, 13)}...`;
    inspTitle.textContent = entry.title;
    inspUsername.textContent = entry.username || '--';
    inspUrl.textContent = entry.url || '--';
    inspNotes.textContent = entry.notes || 'Sin notas.';
    inspTimestamps.textContent = `Creado: ${entry.createdAt} | Modificado: ${entry.updatedAt}`;

    inspTags.innerHTML = '';
    for (const tag of entry.tags || []) {
      const span = document.createElement('span');
      span.className = 'badge';
      span.textContent = `#${tag}`;
      inspTags.appendChild(span);
    }

    const memBytes = entry.protectedStats?.encryptedBytes ?? 0;
    inspMemoryBadge.textContent = `ProtectedMemory: ${memBytes}B Ciphertext (ChaCha20)`;
    inspEntropyBadge.innerHTML = getEntropyBadgeHtml(entry.entropy);

    if (appState.revealedPasswordEntryId === entry.id) {
      const plain = await api.revealSecret(entry.id, 'password');
      inspPassword.textContent = plain;
      btnToggleRevealPwd.textContent = 'Ocultar';
    } else {
      inspPassword.textContent = '••••••••••••••••••••••••';
      btnToggleRevealPwd.textContent = 'Revelar';
    }

    if (entry.hasTotp) {
      inspTotpBlock.classList.remove('hidden');
      await refreshTotpWidget(entry.id);
      appState.totpInterval = setInterval(() => refreshTotpWidget(entry.id), 1000);
    } else {
      inspTotpBlock.classList.add('hidden');
    }
  }

  async function refreshTotpWidget(entryId) {
    const res = await api.getTotp(entryId);
    if (!res || res.error || !res.valid) {
      inspTotpCode.textContent = 'ERR-SEED';
      inspTotpRemaining.textContent = '--';
      inspTotpBar.style.width = '0%';
      return;
    }
    const rem = res.remainingSeconds ?? res.remaining ?? 0;
    inspTotpCode.textContent = res.code;
    inspTotpRemaining.textContent = `${rem}s`;
    const pct = Math.max(0, Math.min(100, (rem / res.period) * 100));
    inspTotpBar.style.width = `${pct}%`;
  }

  function stopTotpLoop() {
    if (appState.totpInterval) {
      clearInterval(appState.totpInterval);
      appState.totpInterval = null;
    }
  }

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ==========================================================================
  // MENÚ CONTEXTUAL DE CLIC DERECHO
  // ==========================================================================

  function showContextMenu(x, y) {
    contextMenu.classList.remove('hidden');
    const menuWidth = 300;
    const menuHeight = 320;
    const left = Math.min(x, window.innerWidth - menuWidth - 8);
    const top = Math.min(y, window.innerHeight - menuHeight - 8);
    contextMenu.style.left = `${Math.max(4, left)}px`;
    contextMenu.style.top = `${Math.max(4, top)}px`;
  }

  function hideContextMenu() {
    contextMenu.classList.add('hidden');
  }

  window.addEventListener('click', () => hideContextMenu());

  inspectorContent.addEventListener('contextmenu', (ev) => {
    if (!appState.selectedEntryId) return;
    ev.preventDefault();
    showContextMenu(ev.clientX, ev.clientY);
  });

  contextMenu.addEventListener('click', async (ev) => {
    const item = ev.target.closest('.ctx-item');
    if (!item || !appState.selectedEntryId) return;
    const action = item.dataset.action;
    const id = appState.selectedEntryId;
    hideContextMenu();

    switch (action) {
      case 'autotype-enter':
        await doAutoType(id, 'enter');
        break;
      case 'autotype-tab-space':
        await doAutoType(id, 'tab_space');
        break;
      case 'autotype-no-submit':
        await doAutoType(id, 'no_submit');
        break;
      case 'copy-password':
        await doCopyField(id, 'password');
        break;
      case 'copy-username':
        await doCopyField(id, 'username');
        break;
      case 'copy-totp':
        await doCopyField(id, 'totp');
        break;
      case 'open-url':
        await doOpenUrl(id);
        break;
      case 'copy-url':
        await doCopyField(id, 'url');
        break;
      case 'edit-entry':
        await openEditModalForEntry(id);
        break;
      case 'duplicate-entry':
        await doDuplicateEntry(id);
        break;
      case 'delete-entry':
        await doDeleteEntry(id);
        break;
    }
  });

  // ==========================================================================
  // EVENTOS LOCK SCREEN
  // ==========================================================================

  const lockWorkstation = document.getElementById('lockWorkstation');
  const lockSpecPane = document.getElementById('lockSpecPane');
  const btnToggleCoreSpec = document.getElementById('btnToggleCoreSpec');

  if (btnToggleCoreSpec) {
    btnToggleCoreSpec.addEventListener('click', () => {
      const isCollapsed = lockWorkstation.classList.toggle('spec-collapsed');
      if (isCollapsed) {
        lockSpecPane.classList.add('hidden');
        btnToggleCoreSpec.textContent = 'CORE SPEC [+]';
      } else {
        lockSpecPane.classList.remove('hidden');
        btnToggleCoreSpec.textContent = 'CORE SPEC [−]';
      }
    });
  }

  tabCreateBtn.addEventListener('click', () => {
    tabCreateBtn.classList.add('active');
    tabOpenBtn.classList.remove('active');
    createVaultForm.classList.remove('hidden');
    openVaultForm.classList.add('hidden');
    showError(null);
  });

  tabOpenBtn.addEventListener('click', () => {
    tabOpenBtn.classList.add('active');
    tabCreateBtn.classList.remove('active');
    openVaultForm.classList.remove('hidden');
    createVaultForm.classList.add('hidden');
    showError(null);
  });

  document.getElementById('pickCreatePathBtn').addEventListener('click', async () => {
    const filePath = await api.pickSaveFile({ defaultPath: 'secops_vault.kvlt' });
    if (filePath) document.getElementById('createFilePathInput').value = filePath;
  });

  async function refreshOpenHardwareSlotBanner(filePath) {
    const banner = document.getElementById('openHardwareBanner');
    const titleEl = document.getElementById('openHwBannerTitle');
    const btnHw = document.getElementById('btnOpenWithHardwareKey');

    if (!filePath) {
      banner.classList.add('hidden');
      return;
    }

    const slotInfo = await api.inspectHardwareSlot(filePath);
    if (!slotInfo || !slotInfo.enabled) {
      banner.classList.add('hidden');
      btnHw.classList.add('hidden');
      return;
    }

    banner.classList.remove('hidden');

    if (slotInfo.authMode === 'hardware_passwordless') {
      titleEl.textContent = 'Llave Física';
      btnHw.classList.remove('hidden');
      btnHw.disabled = false;
    } else if (slotInfo.authMode === 'hardware_2fa') {
      titleEl.textContent = 'DFA (Pass + Key)';
      btnHw.classList.add('hidden');
      btnHw.disabled = true;
    }
  }

  document.getElementById('pickOpenPathBtn').addEventListener('click', async () => {
    const filePath = await api.pickFile({
      title: 'Abrir bóveda KVault (.kvlt)',
      filters: [{ name: 'KVault (.kvlt)', extensions: ['kvlt'] }],
    });
    if (filePath) {
      document.getElementById('openFilePathInput').value = filePath;
      await refreshOpenHardwareSlotBanner(filePath);
    }
  });

  document.getElementById('openFilePathInput').addEventListener('change', async (e) => {
    await refreshOpenHardwareSlotBanner(e.target.value.trim());
  });

  document.getElementById('pickOpenKeyFileBtn').addEventListener('click', async () => {
    const filePath = await api.pickFile({ title: 'Seleccionar KeyFile' });
    if (filePath) document.getElementById('openKeyFileInput').value = filePath;
  });

  createVaultForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    showError(null);
    try {
      const authMode = document.getElementById('createAuthModeSelect').value;
      const state = await api.createVault({
        name: document.getElementById('createNameInput').value.trim(),
        cipherId: Number(document.getElementById('createCipherSelect').value),
        masterPassword: document.getElementById('createMasterPwd').value,
        filePath: document.getElementById('createFilePathInput').value || null,
        seedSample: document.getElementById('seedSampleCheckbox').checked,
        authMode,
      });
      document.getElementById('createMasterPwd').value = '';
      applyState(state);
    } catch (err) {
      showError(err.message);
    }
  });

  openVaultForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    showError(null);
    try {
      const state = await api.openVault({
        filePath: document.getElementById('openFilePathInput').value.trim(),
        masterPassword: document.getElementById('openMasterPwd').value,
        keyFilePath: document.getElementById('openKeyFileInput').value || null,
      });
      document.getElementById('openMasterPwd').value = '';
      applyState(state);
    } catch (err) {
      showError(err.message);
    }
  });

  document.getElementById('btnOpenWithHardwareKey').addEventListener('click', async () => {
    showError(null);
    try {
      const filePath = document.getElementById('openFilePathInput').value.trim();
      const keyFilePath = document.getElementById('openKeyFileInput').value || null;
      const state = await api.openVaultWithHardwareKey({ filePath, keyFilePath });
      document.getElementById('openMasterPwd').value = '';
      applyState(state);
      showToast('Bóveda desbloqueada con Llave Física FIDO2 / U2F');
    } catch (err) {
      showError(err.message);
    }
  });

  // ==========================================================================
  // EVENTOS WORKBENCH, TOOLBAR E INSPECTOR
  // ==========================================================================

  searchInput.addEventListener('input', () => {
    appState.searchQuery = searchInput.value;
    renderEntryTable();
    renderInspector();
  });

  document.getElementById('btnLockVault').addEventListener('click', async () => {
    const state = await api.lockVault();
    applyState(state);
  });

  document.getElementById('btnSaveVault').addEventListener('click', async () => {
    try {
      const res = await api.saveVault();
      if (res.state) applyState(res.state);
      if (res.saved) showToast(`Bóveda guardada en ${res.filePath}`);
    } catch (err) {
      showToast(`Error al guardar: ${err.message}`);
    }
  });

  document.getElementById('btnNewGroup').addEventListener('click', async () => {
    const name = prompt('Nombre del nuevo grupo:');
    if (!name || !name.trim()) return;
    const res = await api.createGroup({ name: name.trim() });
    applyState(res.state);
  });

  document.getElementById('btnImportKeePass').addEventListener('click', async () => {
    const filePath = await api.pickFile({
      title: 'Importar exportación KeePass 2.x (.xml o .csv)',
      filters: [{ name: 'KeePass XML / CSV', extensions: ['xml', 'csv'] }],
    });
    if (!filePath) return;
    try {
      const res = await api.importKeePassFile(filePath);
      applyState(res.state);
      showToast(`Importadas ${res.importedCount} entradas (${res.sourceFormat})`);
    } catch (err) {
      showToast(`Error al importar: ${err.message}`);
    }
  });

  // Botones del Inspector Derecho + Doble Clic en campos del Inspector
  btnToggleRevealPwd.addEventListener('click', async () => {
    if (!appState.selectedEntryId) return;
    if (appState.revealedPasswordEntryId === appState.selectedEntryId) {
      appState.revealedPasswordEntryId = null;
    } else {
      appState.revealedPasswordEntryId = appState.selectedEntryId;
    }
    await renderInspector();
  });

  document.getElementById('btnCopyPwd').addEventListener('click', () => doCopyField(appState.selectedEntryId, 'password'));
  document.getElementById('btnCopyUser').addEventListener('click', () => doCopyField(appState.selectedEntryId, 'username'));
  document.getElementById('btnCopyTotp').addEventListener('click', () => doCopyField(appState.selectedEntryId, 'totp'));
  document.getElementById('btnOpenUrl').addEventListener('click', () => doOpenUrl(appState.selectedEntryId));
  document.getElementById('btnCopyUrl').addEventListener('click', () => doCopyField(appState.selectedEntryId, 'url'));

  inspUrl.addEventListener('dblclick', () => doOpenUrl(appState.selectedEntryId));
  inspUsername.addEventListener('dblclick', () => doCopyField(appState.selectedEntryId, 'username'));
  inspPassword.addEventListener('dblclick', () => doCopyField(appState.selectedEntryId, 'password'));
  inspTotpCode.addEventListener('dblclick', () => doCopyField(appState.selectedEntryId, 'totp'));

  document.getElementById('btnEditEntry').addEventListener('click', (ev) => {
    ev.stopPropagation();
    openEditModalForEntry(appState.selectedEntryId);
  });
  document.getElementById('btnDeleteEntry').addEventListener('click', (ev) => {
    ev.stopPropagation();
    doDeleteEntry(appState.selectedEntryId);
  });

  // Colapsar / Expandir Árbol de Grupos (Panel Izquierdo) e Inspector Horizontal (Panel Inferior)
  function toggleGroupTreePane() {
    const isCollapsed = paneLeft.classList.toggle('collapsed');
    splitView.classList.toggle('left-collapsed', isCollapsed);
  }

  function toggleBottomInspectorPane() {
    const isCollapsed = paneBottom.classList.toggle('collapsed');
    if (inspectorToggleIcon) {
      inspectorToggleIcon.textContent = isCollapsed ? '▲' : '▼';
    }
  }

  document.getElementById('btnToggleGroups').addEventListener('click', toggleGroupTreePane);
  document.getElementById('btnExpandGroupsRail').addEventListener('click', toggleGroupTreePane);
  document.getElementById('btnToggleInspector').addEventListener('click', toggleBottomInspectorPane);

  // ==========================================================================
  // MODAL DE ENTRADA (CREAR / EDITAR)
  // ==========================================================================

  function populateGroupSelect(selectedId) {
    entryGroupField.innerHTML = '';
    for (const grp of appState.groups) {
      const opt = document.createElement('option');
      opt.value = grp.id;
      opt.textContent = grp.name;
      if (grp.id === selectedId) opt.selected = true;
      entryGroupField.appendChild(opt);
    }
  }

  async function openNewEntryModal() {
    entryModalTitle.textContent = 'Nueva Entrada en Bóveda';
    entryIdField.value = '';
    entryTitleField.value = '';
    entryUserField.value = '';
    entryUrlField.value = '';
    const gen = await api.generatePassword({ length: 24 });
    entryPasswordField.value = gen.password;
    entryTotpField.value = '';
    entryTagsField.value = '';
    entryNotesField.value = '';
    const defaultGrp =
      appState.selectedGroupId !== 'ALL' ? appState.selectedGroupId : appState.groups[0]?.id;
    populateGroupSelect(defaultGrp);
    entryModal.classList.remove('hidden');
    entryTitleField.focus();
  }

  document.getElementById('btnNewEntry').addEventListener('click', openNewEntryModal);

  document.getElementById('btnModalGeneratePwd').addEventListener('click', async () => {
    const gen = await api.generatePassword({ length: 24 });
    entryPasswordField.value = gen.password;
  });

  const closeEntryModal = () => entryModal.classList.add('hidden');
  document.getElementById('btnCloseEntryModal').addEventListener('click', closeEntryModal);
  document.getElementById('btnCancelEntryModal').addEventListener('click', closeEntryModal);

  entryForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await api.upsertEntry({
      id: entryIdField.value || null,
      groupId: entryGroupField.value,
      title: entryTitleField.value,
      username: entryUserField.value,
      url: entryUrlField.value,
      password: entryPasswordField.value,
      totpSecret: entryTotpField.value,
      tags: entryTagsField.value,
      notes: entryNotesField.value,
    });
    entryPasswordField.value = '';
    entryTotpField.value = '';
    closeEntryModal();
    appState.selectedEntryId = res.id;
    applyState(res.state);
    showToast('Entrada cifrada en ProtectedMemory');
  });

  // ==========================================================================
  // MODAL GENERADOR CSPRNG
  // ==========================================================================

  async function refreshGeneratorPreview() {
    const length = Number(genLengthRange.value);
    genLengthLabel.textContent = String(length);
    const res = await api.generatePassword({
      length,
      upper: document.getElementById('genUpper').checked,
      lower: document.getElementById('genLower').checked,
      digits: document.getElementById('genDigits').checked,
      symbols: document.getElementById('genSymbols').checked,
    });
    genOutputText.textContent = res.password;
    genEntropyBadge.innerHTML = getEntropyBadgeHtml(res.entropy);
  }

  document.getElementById('btnOpenGenerator').addEventListener('click', async () => {
    await refreshGeneratorPreview();
    generatorModal.classList.remove('hidden');
  });

  genLengthRange.addEventListener('input', refreshGeneratorPreview);
  document.getElementById('btnRegeneratePwd').addEventListener('click', refreshGeneratorPreview);
  document.getElementById('btnCloseGenModal').addEventListener('click', () => generatorModal.classList.add('hidden'));
  document.getElementById('btnCloseGenModal2').addEventListener('click', () => generatorModal.classList.add('hidden'));

  // ==========================================================================
  // MODAL CONFIGURACIÓN DE LLAVE FÍSICA (FIDO2 / FLIPPER ZERO U2F)
  // ==========================================================================

  function openHardwareModal() {
    const hw = appState.hardwareSlot || { enabled: false, authMode: 'password_only' };
    hwCurrentPwdInput.value = '';
    if (hw.enabled) {
      hwStatusBadge.className = 'badge badge-ok';
      hwStatusBadge.textContent = hw.authMode === 'hardware_2fa' ? 'DFA (Pass + Key)' : 'Llave Física';
      hwAuthModeSelect.value = hw.authMode;
    } else {
      hwStatusBadge.className = 'badge';
      hwStatusBadge.textContent = 'Contraseña';
      hwAuthModeSelect.value = 'hardware_2fa';
    }
    hardwareModal.classList.remove('hidden');
  }

  document.getElementById('btnOpenHardwareModal').addEventListener('click', openHardwareModal);
  const closeHwModal = () => hardwareModal.classList.add('hidden');
  document.getElementById('btnCloseHwModal').addEventListener('click', closeHwModal);
  document.getElementById('btnCancelHwModal').addEventListener('click', closeHwModal);

  const closeShortcutsModal = () => shortcutsModal.classList.add('hidden');
  document.getElementById('btnOpenShortcutsModal').addEventListener('click', () => shortcutsModal.classList.remove('hidden'));
  document.getElementById('btnCloseShortcutsModal').addEventListener('click', closeShortcutsModal);
  document.getElementById('btnCloseShortcutsModal2').addEventListener('click', closeShortcutsModal);

  hardwareForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const authMode = hwAuthModeSelect.value;
      const currentMasterPassword = hwCurrentPwdInput.value;
      showToast('Esperando llave física...');
      const state = await api.configureHardwareKey({
        authMode,
        currentMasterPassword,
      });
      hwCurrentPwdInput.value = '';
      closeHwModal();
      applyState(state);
      showToast(
        authMode === 'password_only'
          ? 'Modo actualizado: Contraseña'
          : authMode === 'hardware_2fa'
          ? 'Modo actualizado: DFA (Pass + Key)'
          : 'Modo actualizado: Llave Física'
      );
    } catch (err) {
      showToast(`Error: ${err.message}`);
    }
  });

  // ==========================================================================
  // ATAJOS DE TECLADO COMPLETOS ESTILO KEEPASS 2.X
  // ==========================================================================

  window.addEventListener('keydown', async (e) => {
    if (!appState.unlocked) return;

    const activeTag = document.activeElement ? document.activeElement.tagName : '';
    const isTypingInInput = activeTag === 'INPUT' || activeTag === 'TEXTAREA' || activeTag === 'SELECT';
    const isModalOpen =
      !entryModal.classList.contains('hidden') ||
      !generatorModal.classList.contains('hidden') ||
      !hardwareModal.classList.contains('hidden') ||
      !shortcutsModal.classList.contains('hidden');

    // Escape cierra modales o menú contextual
    if (e.key === 'Escape') {
      hideContextMenu();
      if (!entryModal.classList.contains('hidden')) closeEntryModal();
      if (!generatorModal.classList.contains('hidden')) generatorModal.classList.add('hidden');
      if (!hardwareModal.classList.contains('hidden')) closeHwModal();
      if (!shortcutsModal.classList.contains('hidden')) closeShortcutsModal();
      return;
    }

    if (e.key === 'F1') {
      e.preventDefault();
      shortcutsModal.classList.toggle('hidden');
      return;
    }

    // Atajos globales que funcionan siempre (incluso con foco en búsqueda)
    if (e.ctrlKey && e.key.toLowerCase() === 'l') {
      e.preventDefault();
      const state = await api.lockVault();
      applyState(state);
      return;
    }
    if (e.ctrlKey && e.key.toLowerCase() === 's') {
      e.preventDefault();
      const res = await api.saveVault();
      if (res.state) applyState(res.state);
      if (res.saved) showToast(`Guardado: ${res.filePath}`);
      return;
    }
    if (e.ctrlKey && e.key.toLowerCase() === 'f') {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
      return;
    }
    if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'x') {
      e.preventDefault();
      await api.wipeClipboardNow();
      showToast('Portapapeles + Historial Win+V purgados');
      return;
    }
    if (e.ctrlKey && e.key.toLowerCase() === 'i') {
      e.preventDefault();
      await openNewEntryModal();
      return;
    }

    // Si está escribiendo dentro de un modal o input, no interceptar Ctrl+C / Ctrl+V / flechas
    if (isTypingInInput || isModalOpen) return;

    const id = appState.selectedEntryId;
    const key = e.key.toLowerCase();

    // Ctrl+V -> Auto-Type {USERNAME}{TAB}{PASSWORD}{ENTER}
    // Ctrl+Shift+V -> Auto-Type {USERNAME}{TAB}{PASSWORD}{TAB}{SPACE}
    if (e.ctrlKey && key === 'v') {
      e.preventDefault();
      await doAutoType(id, e.shiftKey ? 'tab_space' : 'enter');
      return;
    }

    // Ctrl+C -> Copiar Contraseña
    if (e.ctrlKey && !e.shiftKey && key === 'c') {
      e.preventDefault();
      await doCopyField(id, 'password');
      return;
    }

    // Ctrl+B -> Copiar Usuario (Atajo clásico de KeePass)
    if (e.ctrlKey && key === 'b') {
      e.preventDefault();
      await doCopyField(id, 'username');
      return;
    }

    // Ctrl+T -> Copiar Token TOTP
    if (e.ctrlKey && key === 't') {
      e.preventDefault();
      await doCopyField(id, 'totp');
      return;
    }

    // Ctrl+U -> Abrir URL | Ctrl+Shift+U -> Copiar URL
    if (e.ctrlKey && key === 'u') {
      e.preventDefault();
      if (e.shiftKey) {
        await doCopyField(id, 'url');
      } else {
        await doOpenUrl(id);
      }
      return;
    }

    // Ctrl+K -> Duplicar entrada (Atajo clásico de KeePass)
    if (e.ctrlKey && key === 'k') {
      e.preventDefault();
      await doDuplicateEntry(id);
      return;
    }

    // Enter o F2 -> Editar entrada seleccionada
    if (e.key === 'Enter' || e.key === 'F2') {
      e.preventDefault();
      await openEditModalForEntry(id);
      return;
    }

    // Delete -> Eliminar entrada seleccionada
    if (e.key === 'Delete') {
      e.preventDefault();
      await doDeleteEntry(id);
      return;
    }

    // Navegación con Flechas Arriba / Abajo en la tabla
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const filtered = getFilteredEntries();
      if (!filtered.length) return;
      const idx = filtered.findIndex((item) => item.id === appState.selectedEntryId);
      const nextIdx =
        e.key === 'ArrowDown'
          ? Math.min(filtered.length - 1, idx + 1)
          : Math.max(0, idx - 1);
      appState.selectedEntryId = filtered[nextIdx].id;
      appState.revealedPasswordEntryId = null;
      renderEntryTable();
      renderInspector();
    }
  });

  statusClipboardTimer.addEventListener('click', async () => {
    await api.wipeClipboardNow();
    showToast('Portapapeles purgado manualmente');
  });

  api.onClipboardStatus((data) => {
    if (data.active) {
      statusClipboardTimer.textContent = `Portapapeles: [${data.label}] Auto-Wipe en ${data.remainingSeconds}s (Clic para purgar ya)`;
      statusClipboardTimer.style.color = 'var(--badge-warn-text)';
    } else {
      statusClipboardTimer.textContent = `Portapapeles: ${data.label || 'Purgado'}`;
      statusClipboardTimer.style.color = 'var(--status-ok)';
    }
  });

  // ==========================================================================
  // GESTIÓN DE TEMA VISUAL: OSCURO / CLARO / AUTOMÁTICO (OS)
  // ==========================================================================
  const themeSelectToolbar = document.getElementById('themeSelectToolbar');
  const themeSelectStatus = document.getElementById('themeSelectStatus');
  const osLightQuery = window.matchMedia('(prefers-color-scheme: light)');

  function resolveEffectiveTheme(mode) {
    if (mode === 'light' || mode === 'dark') return mode;
    return osLightQuery.matches ? 'light' : 'dark';
  }

  async function applyThemeMode(mode, savePreference = true) {
    const validMode = ['system', 'dark', 'light'].includes(mode) ? mode : 'system';
    if (savePreference) {
      localStorage.setItem('kvault_theme_mode', validMode);
    }
    if (themeSelectToolbar) themeSelectToolbar.value = validMode;
    if (themeSelectStatus) themeSelectStatus.value = validMode;

    if (api.setThemeMode) {
      await api.setThemeMode(validMode).catch(() => {});
    }

    const effective = resolveEffectiveTheme(validMode);
    document.documentElement.dataset.theme = effective;
  }

  if (themeSelectToolbar) {
    themeSelectToolbar.addEventListener('change', (e) => applyThemeMode(e.target.value));
  }
  if (themeSelectStatus) {
    themeSelectStatus.addEventListener('change', (e) => applyThemeMode(e.target.value));
  }
  osLightQuery.addEventListener('change', () => {
    const savedMode = localStorage.getItem('kvault_theme_mode') || 'system';
    if (savedMode === 'system') {
      applyThemeMode('system', false);
    }
  });

  const initialThemeMode = localStorage.getItem('kvault_theme_mode') || 'system';
  applyThemeMode(initialThemeMode, false);

  // Inicializar estado
  api.getState().then(applyState);
})();
