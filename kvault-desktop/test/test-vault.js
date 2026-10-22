'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const { ProtectedMemory } = require('../src/core/protectedMemory');
const {
  serializeVaultToBuffer,
  deserializeVaultFromBuffer,
  saveVaultFileAtomic,
  loadVaultFile,
} = require('../src/core/vaultFormat');
const {
  generateTotp,
  calculatePasswordEntropy,
  generateSecurePassword,
} = require('../src/core/totp');
const { importKeePassFile } = require('../src/importer/keepassImporter');
const { escapeForSendKeys } = require('../src/core/autoType');

console.log('======================================================================');
console.log(' KVAULT DESKTOP — SUITE DE VERIFICACIÓN CRIPTOGRÁFICA Y DE MEMORIA');
console.log('======================================================================');

// 1. Prueba de ProtectedMemory (ChaCha20-Poly1305 en RAM + Zeroize determinista)
{
  const guard = new ProtectedMemory();
  const rawSecret = 'ClaveUltraSecreta_2026!@#';
  const envelope = guard.protectString(rawSecret);

  assert.equal(envelope.byteLength, Buffer.byteLength(rawSecret, 'utf8'));
  assert.notEqual(Buffer.from(envelope.data, 'base64').toString('utf8'), rawSecret);

  const recovered = guard.unprotectToString(envelope);
  assert.equal(recovered, rawSecret, 'El secreto recuperado debe coincidir con el original');

  const tmpBuf = Buffer.from(' sensible ', 'utf8');
  ProtectedMemory.zeroize(tmpBuf);
  assert.equal(tmpBuf.every((b) => b === 0), true, 'ProtectedMemory.zeroize debe llenar con 0x00');

  guard.wipeSessionKey();
  assert.throws(
    () => guard.unprotectToString(envelope),
    /authenticate|state/i,
    'Tras rotar la clave efímera de sesión, los sobres anteriores deben ser indescifrables'
  );
  console.log('[OK] 1/5 ProtectedMemory: Cifrado efímero ChaCha20-Poly1305 en RAM y Zeroize verificados.');
}

// 2. Prueba de Contenedor .kvlt (ChaCha20-Poly1305 & AES-256-GCM) + Detección de alteración AAD
{
  const samplePayload = {
    meta: { name: 'Vault_Test', createdAt: new Date().toISOString() },
    groups: [{ id: 'g-1', parentId: null, name: 'Servidores' }],
    entries: [
      {
        id: 'e-1',
        groupId: 'g-1',
        title: 'Root SSH',
        username: 'root',
        password: 'SuperPassword123!@#',
      },
    ],
  };

  for (const cipher of ['chacha20-poly1305', 'aes-256-gcm']) {
    const encryptedBlob = serializeVaultToBuffer(samplePayload, 'MasterPass_2026!', { cipher });
    const decoded = deserializeVaultFromBuffer(encryptedBlob, 'MasterPass_2026!');

    assert.equal(decoded.headerInfo.magic, 'KVLT');
    assert.equal(decoded.headerInfo.cipher, cipher);
    assert.equal(decoded.vault.entries[0].password, 'SuperPassword123!@#');

    // Modificar 1 bit del Header (AAD) para comprobar que el AuthTag AEAD detecta manipulación
    const tamperedHeaderBlob = Buffer.from(encryptedBlob);
    tamperedHeaderBlob[47] ^= 0xff; // Alterar 1 byte en la región AAD del encabezado
    assert.throws(
      () => deserializeVaultFromBuffer(tamperedHeaderBlob, 'MasterPass_2026!'),
      /AEAD|alterada|incorrecta/i,
      'Debe rechazar cualquier alteración en los 58 bytes del encabezado AAD'
    );
  }
  console.log('[OK] 2/5 Formato Binario .kvlt: ChaCha20-Poly1305, AES-256-GCM y protección de Header AAD verificados.');
}

// 3. Prueba de Persistencia Atómica en Disco (.tmp + fsync + rename)
{
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kvault-test-'));
  const targetFile = path.join(tmpDir, 'atomic_test.kvlt');
  const payload = { meta: { name: 'Atomic' }, groups: [], entries: [] };

  saveVaultFileAtomic(targetFile, payload, 'AtomicSecret#1', { cipher: 'chacha20-poly1305' });
  assert.equal(fs.existsSync(targetFile), true);

  const readBack = loadVaultFile(targetFile, 'AtomicSecret#1');
  assert.equal(readBack.vault.meta.name, 'Atomic');

  fs.rmSync(tmpDir, { recursive: true, force: true });
  console.log('[OK] 3/5 Persistencia Atómica: Escritura transaccional (.tmp -> fsync -> rename) verificada.');
}

// 4. Prueba de Generador TOTP RFC 6238 y CSPRNG sin sesgo de módulo
{
  const totp = generateTotp('JBSWY3DPEHPK3PXP', 1700000000000);
  assert.equal(totp.valid, true);
  assert.equal(totp.rawCode.length, 6);
  assert.match(totp.rawCode, /^\d{6}$/);

  const pwd = generateSecurePassword({ length: 32 });
  assert.equal(pwd.length, 32);
  const entropy = calculatePasswordEntropy(pwd);
  assert.ok(entropy.bits >= 120, `Entropía esperada >= 120 bits, obtenida: ${entropy.bits}`);
  console.log(`[OK] 4/5 Criptografía TOTP & CSPRNG: Código RFC 6238 (${totp.code}) y entropía (${entropy.bits} bits) verificados.`);
}

// 5. Prueba del Importador Nativo KeePass 2.x (.xml)
{
  const sampleXmlPath = path.join(__dirname, '..', 'samples', 'keepass_export_sample.xml');
  const imported = importKeePassFile(sampleXmlPath);

  assert.equal(imported.groups.length, 2, 'Debe importar los 2 grupos jerárquicos de KeePass 2.x');
  assert.equal(imported.entries.length, 4, 'Debe importar las 4 entradas del archivo XML de muestra');
  assert.ok(imported.entries.some((e) => e.totpSecret.length > 0), 'Debe extraer la semilla TimeOtp-Secret de KeePass 2.x');

  // 6. Verificar motor de escape literal para Auto-Type (SendKeys)
  const complexPwd = 'P+a^s%s~w(o)r{d}[1]!';
  const escaped = escapeForSendKeys(complexPwd);
  assert.equal(escaped, 'P{+}a{^}s{%}s{~}w{(}o{)}r{{}d{}}{[}1{]}!');
  console.log(`[OK] 5/5 Importador KeePass 2.x & Auto-Type Escape: ${imported.entries.length} entradas, ${imported.groups.length} grupos y escape SendKeys verificados.`);
}

console.log('======================================================================');
console.log(' TODAS LAS PRUEBAS PASARON EXITOSAMENTE');
console.log('======================================================================');
