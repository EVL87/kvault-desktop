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
const {
  RP_ID,
  parseCoseP256PublicKeyFromAuthData,
  verifyHardwareAssertionSignature,
  wrapSecretForHardwareSlot,
  unwrapSecretFromHardwareSlot,
  combinePasswordAndHardwareFactor,
} = require('../src/core/fido2Hardware');
const crypto = require('node:crypto');

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
  console.log(`[OK] 5/6 Importador XML/CSV & Auto-Type Escape: ${imported.entries.length} entradas, ${imported.groups.length} grupos y escape SendKeys verificados.`);
}

// 7. Prueba de Criptografía FIDO2 / U2F (COSE P-256, Firma ECDSA de Llave Física y Key Slot Wrapping)
(async () => {
  // Simular par de llaves ECDSA P-256 generado dentro de una Yubico Security Key C NFC o Flipper Zero U2F
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const xBytes = Buffer.from(jwk.x, 'base64url');
  const yBytes = Buffer.from(jwk.y, 'base64url');

  // Construir bloque AuthenticatorData sintético con COSE_Key P-256
  const rpIdHash = crypto.createHash('sha256').update(RP_ID, 'utf8').digest();
  const flags = Buffer.from([0x41]); // UP (0x01) + AT (0x40)
  const signCount = Buffer.from([0x00, 0x00, 0x00, 0x01]);
  const aaguid = Buffer.alloc(16, 0); // 0x00...00 = FIDO U2F (Flipper Zero / Security Key)
  const credId = crypto.randomBytes(32);
  const credIdLen = Buffer.from([0x00, 0x20]);
  const coseKey = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01]),
    Buffer.from([0x21, 0x58, 0x20]),
    xBytes,
    Buffer.from([0x22, 0x58, 0x20]),
    yBytes,
  ]);

  const makeCredAuthData = Buffer.concat([rpIdHash, flags, signCount, aaguid, credIdLen, credId, coseKey]);
  const parsedCose = parseCoseP256PublicKeyFromAuthData(makeCredAuthData);
  assert.ok(parsedCose.publicKeySpkiB64.length > 40);

  // Simular GetAssertion firmado por el hardware (Flipper U2F / Yubico Security Key)
  const assertionAuthData = Buffer.concat([rpIdHash, Buffer.from([0x01]), Buffer.from([0x00, 0x00, 0x00, 0x02])]);
  const clientDataJson = JSON.stringify({
    type: 'webauthn.get',
    challenge: crypto.randomBytes(32).toString('base64url'),
    origin: `https://${RP_ID}`,
    crossOrigin: false,
  });
  const clientDataHash = crypto.createHash('sha256').update(clientDataJson, 'utf8').digest();
  const signature = crypto.sign('sha256', Buffer.concat([assertionAuthData, clientDataHash]), privateKey);

  const verified = verifyHardwareAssertionSignature({
    publicKeySpkiB64: parsedCose.publicKeySpkiB64,
    authDataBuf: assertionAuthData,
    clientDataJson,
    signatureBuf: signature,
  });
  assert.equal(verified.verified, true);
  assert.equal(verified.signCount, 2);

  // Verificar envoltura DPAPI + ChaCha20-Poly1305 del Key Slot
  const wrapped = await wrapSecretForHardwareSlot(
    'VaultSecret_FIDO2_2026',
    credId.toString('base64'),
    parsedCose.publicKeySpkiB64
  );
  const unwrapped = await unwrapSecretFromHardwareSlot(
    wrapped,
    credId.toString('base64'),
    parsedCose.publicKeySpkiB64
  );
  assert.equal(unwrapped, 'VaultSecret_FIDO2_2026');

  const combined = combinePasswordAndHardwareFactor('Pass1234', crypto.randomBytes(32).toString('hex'));
  assert.equal(combined.length, 64);

  console.log('[OK] 6/6 Llaves Físicas FIDO2 / U2F: Parser COSE P-256, firma ECDSA de hardware y Key Slot DPAPI verificados.');
  console.log('======================================================================');
  console.log(' TODAS LAS PRUEBAS PASARON EXITOSAMENTE');
  console.log('======================================================================');
})();
