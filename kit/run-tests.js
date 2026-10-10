// Entry for `node --test kit/`: Node 25 resolves a directory argument as a
// module (package.json "main"), not as a folder to scan, so this loads every
// *.test.js file. Running `node --test kit/*.test.js` works too.
import { readdirSync } from 'node:fs';

const dir = new URL('.', import.meta.url);
for (const f of readdirSync(dir).filter((n) => n.endsWith('.test.js')).sort()) {
  await import(new URL(f, dir).href);
}
