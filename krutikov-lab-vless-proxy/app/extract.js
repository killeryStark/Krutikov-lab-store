const fs = require('fs');
const zlib = require('zlib');

const [zipPath, outPath, entryName] = process.argv.slice(2);
if (!zipPath || !outPath || !entryName) {
  console.error('usage: node extract.js <zip> <out> <entry>');
  process.exit(1);
}

const buf = fs.readFileSync(zipPath);
let eocd = -1;
for (let i = buf.length - 22; i >= 0 && i >= buf.length - 65557; i--) {
  if (buf.readUInt32LE(i) === 0x06054b50) {
    eocd = i;
    break;
  }
}
if (eocd < 0) throw new Error('zip: не найден конец центрального каталога');

const count = buf.readUInt16LE(eocd + 10);
let offset = buf.readUInt32LE(eocd + 16);

for (let i = 0; i < count; i++) {
  if (buf.readUInt32LE(offset) !== 0x02014b50) throw new Error('zip: повреждён центральный каталог');
  const method = buf.readUInt16LE(offset + 10);
  const compSize = buf.readUInt32LE(offset + 20);
  const nameLen = buf.readUInt16LE(offset + 28);
  const extraLen = buf.readUInt16LE(offset + 30);
  const commentLen = buf.readUInt16LE(offset + 32);
  const localOffset = buf.readUInt32LE(offset + 42);
  const name = buf.toString('utf8', offset + 46, offset + 46 + nameLen);
  if (name === entryName) {
    if (buf.readUInt32LE(localOffset) !== 0x04034b50) throw new Error('zip: повреждён локальный заголовок');
    const localNameLen = buf.readUInt16LE(localOffset + 26);
    const localExtraLen = buf.readUInt16LE(localOffset + 28);
    const start = localOffset + 30 + localNameLen + localExtraLen;
    const data = buf.subarray(start, start + compSize);
    const out = method === 0 ? data : method === 8 ? zlib.inflateRawSync(data) : null;
    if (!out) throw new Error('zip: метод сжатия ' + method + ' не поддерживается');
    fs.writeFileSync(outPath, out, { mode: 0o755 });
    console.log('[extract] ' + name + ' → ' + outPath + ' (' + out.length + ' байт)');
    process.exit(0);
  }
  offset += 46 + nameLen + extraLen + commentLen;
}

throw new Error('zip: файл ' + entryName + ' не найден');
