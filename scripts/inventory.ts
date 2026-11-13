import { readFile, writeFile } from 'node:fs/promises';
import { inventory } from '../dist/catalogue.js';

const path = new URL('../command-inventory.json', import.meta.url);
const content = `${JSON.stringify(inventory, null, 2)}\n`;
if (process.argv.includes('--check')) {
  if (await readFile(path, 'utf8') !== content) throw new Error('Command inventory is stale; run npm run build');
} else {
  await writeFile(path, content);
}
