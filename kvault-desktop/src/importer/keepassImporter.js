'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const MAX_IMPORT_FILE_BYTES = 32 * 1024 * 1024; // 32 MB máx
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Módulo de Migración e Importación de Bóvedas Externas (XML Jerárquico y CSV)
 *
 * Soporta:
 * 1. Archivos de exportación XML (`<KeePassFile><Root><Group>...`) incluyendo:
 *    - Árbol jerárquico de grupos y subgrupos (`<Group><Name>...</Name><Entry>...`)
 *    - Campos estándar (`Title`, `UserName`, `Password`, `URL`, `Notes`)
 *    - Semillas 2FA TOTP (`TimeOtp-Secret-Base32`, `otp`, `TOTP Seed`)
 * 2. Archivos CSV estándar (`"Account","Login Name","Password","Web Site","Comments"`).
 */

function decodeXmlEntities(str) {
  if (!str) return '';
  return str
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function extractTagValue(xmlBlock, tagName, decode = true) {
  const regex = new RegExp(`<${tagName}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tagName}>`, 'i');
  const match = xmlBlock.match(regex);
  if (!match) return '';
  const raw = match[1];
  return decode ? decodeXmlEntities(raw.trim()) : raw;
}

/**
 * Extrae las entradas `<Entry>...</Entry>` directas de un bloque XML (excluyendo previamente `<History>`).
 */
function parseEntriesFromGroupBlock(groupBodyWithoutSubgroups, groupId) {
  const entries = [];
  // Eliminar bloques <History> ANTES de buscar <Entry> para evitar que <Entry> anidados en <History>
  // trunquen el bloque padre o sobrescriban las contraseñas actuales con claves antiguas.
  const cleanedGroupBody = groupBodyWithoutSubgroups.replace(/<History\b[^>]*>[\s\S]*?<\/History>/gi, '');
  const entryRegex = /<Entry\b[^>]*>([\s\S]*?)<\/Entry>/gi;
  let match;

  while ((match = entryRegex.exec(cleanedGroupBody)) !== null) {
    const rawEntry = match[1];
    const fields = Object.create(null);

    const stringBlockRegex = /<String\b[^>]*>([\s\S]*?)<\/String>/gi;
    let blockMatch;
    while ((blockMatch = stringBlockRegex.exec(rawEntry)) !== null) {
      const block = blockMatch[1];
      const k = extractTagValue(block, 'Key', true);
      const rawVal = extractTagValue(block, 'Value', false);
      const v = decodeXmlEntities(rawVal);
      if (k && !FORBIDDEN_KEYS.has(k)) {
        fields[k] = v;
      }
    }

    const totpSecret =
      fields['TimeOtp-Secret-Base32'] ||
      fields['otp'] ||
      fields['TOTP Seed'] ||
      fields['TOTP'] ||
      '';

    const lastMod = extractTagValue(rawEntry, 'LastModificationTime', true) || new Date().toISOString();

    entries.push({
      id: crypto.randomUUID({ disableEntropyCache: true }),
      groupId,
      title: fields['Title'] || 'Sin título',
      username: fields['UserName'] || '',
      password: fields['Password'] || '',
      url: fields['URL'] || '',
      notes: fields['Notes'] || '',
      totpSecret,
      modifiedAt: lastMod,
    });
  }

  return entries;
}

/**
 * Parsea un documento XML de KeePass 2.x (`<KeePassFile>`) y devuelve grupos y entradas normalizados.
 * @param {string} xmlContent
 * @returns {{ groups: Array, entries: Array, sourceFormat: string }}
 */
function importKeePassXml(xmlContent) {
  const text = String(xmlContent ?? '');
  if (!/<KeePassFile\b/i.test(text) && !/<Group\b/i.test(text)) {
    throw new Error('El archivo no contiene una estructura XML válida de KeePass 2.x (<KeePassFile> / <Group>).');
  }

  const groups = [];
  const entries = [];

  // Analizador de etiquetas <Group> anidadas por pila
  const tokenRegex = /<\/?Group\b[^>]*>/gi;
  const stack = [];
  let tokenMatch;

  while ((tokenMatch = tokenRegex.exec(text)) !== null) {
    const token = tokenMatch[0];
    const isClosing = token.startsWith('</');
    const isSelfClosing = token.endsWith('/>');

    if (!isClosing && !isSelfClosing) {
      stack.push({
        openTagStartIdx: tokenMatch.index,
        startIdx: tokenMatch.index + token.length,
        childRanges: [],
      });
    } else if (isClosing && stack.length > 0) {
      const current = stack.pop();
      const endIdx = tokenMatch.index;
      const fullGroupInner = text.slice(current.startIdx, endIdx);

      // Recortar los subgrupos hijos para quedarnos solo con los datos directos de este grupo
      let directContent = '';
      let cursor = 0;
      for (const range of current.childRanges) {
        directContent += fullGroupInner.slice(cursor, range.relStart);
        cursor = range.relEnd;
      }
      directContent += fullGroupInner.slice(cursor);

      const groupName = extractTagValue(directContent, 'Name', true) || 'General';
      const groupId = crypto.randomUUID({ disableEntropyCache: true });
      current.groupId = groupId;

      groups.push({
        id: groupId,
        name: groupName,
        depth: stack.length,
      });

      const groupEntries = parseEntriesFromGroupBlock(directContent, groupId);
      entries.push(...groupEntries);

      if (stack.length > 0) {
        const parent = stack[stack.length - 1];
        parent.childRanges.push({
          relStart: current.openTagStartIdx - parent.startIdx,
          relEnd: endIdx + token.length - parent.startIdx,
        });
      }
    }
  }

  // Ordenar grupos en orden de aparición original
  groups.reverse();

  return {
    groups,
    entries,
    sourceFormat: 'KeePass 2.x XML (.xml)',
  };
}

/**
 * Parsea un archivo CSV exportado de KeePass 1.x / 2.x.
 * @param {string} csvContent
 * @returns {{ groups: Array, entries: Array, sourceFormat: string }}
 */
function importKeePassCsv(csvContent) {
  const lines = String(csvContent ?? '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  if (lines.length < 2) {
    throw new Error('El archivo CSV de KeePass está vacío o no contiene filas de datos.');
  }

  const parseCsvRow = (line) => {
    const cols = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === ',' && !inQuotes) {
        cols.push(cur);
        cur = '';
      } else {
        cur += ch;
      }
    }
    cols.push(cur);
    return cols;
  };

  const defaultGroupId = crypto.randomUUID({ disableEntropyCache: true });
  const groups = [{ id: defaultGroupId, name: 'Importado CSV KeePass', depth: 0 }];
  const entries = [];

  for (let i = 1; i < lines.length; i++) {
    const cols = parseCsvRow(lines[i]);
    if (cols.length >= 3) {
      entries.push({
        id: crypto.randomUUID({ disableEntropyCache: true }),
        groupId: defaultGroupId,
        title: cols[0] || 'Entrada CSV',
        username: cols[1] || '',
        password: cols[2] || '',
        url: cols[3] || '',
        notes: cols[4] || '',
        totpSecret: cols[5] || '',
        modifiedAt: new Date().toISOString(),
      });
    }
  }

  return {
    groups,
    entries,
    sourceFormat: 'KeePass CSV (.csv)',
  };
}

/**
 * Importa un archivo `.xml` o `.csv` de KeePass directamente desde ruta de disco.
 * @param {string} filePath
 */
function importKeePassFile(filePath) {
  const stat = fs.statSync(filePath);
  if (!stat.isFile() || stat.size > MAX_IMPORT_FILE_BYTES) {
    throw new Error('El archivo de importación excede el tamaño máximo permitido (32 MB).');
  }
  const ext = path.extname(filePath).toLowerCase();
  const content = fs.readFileSync(filePath, 'utf8');
  if (ext === '.csv') {
    return importKeePassCsv(content);
  }
  return importKeePassXml(content);
}

module.exports = {
  importKeePassXml,
  importKeePassCsv,
  importKeePassFile,
};
