import { subscribe } from 'node:diagnostics_channel';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = process.env.ARTIUM_FIXTURE_ROOT;
const clockOffset = process.env.ARTIUM_FIXTURE_CLOCK_OFFSET_FILE;
if (clockOffset) {
  // Time is a true external boundary; advance expiry without sleeping in a journey.
  const now = Date.now;
  Date.now = () => now() + Number(readFileSync(clockOffset, 'utf8'));
}
const executable = join(root, 'tools/node_modules/@knowttl/technitium-axi/bin/technitium-axi.js');
// Observe actual process starts without replacing the host runner or adapter.
subscribe('child_process', ({ process: child }) => {
  child.once('spawn', () => {
    if (child.spawnargs[1] !== executable) return;
    console.log(JSON.stringify({ event: 'tool-spawn', pid: child.pid, argv: child.spawnargs,
      executableSha256: createHash('sha256').update(readFileSync(executable)).digest('hex') }));
  });
});
const { serverDefaults } = await import(pathToFileURL(join(root, 'dist/src/server/config.js')));
serverDefaults.host = '127.0.0.1';
serverDefaults.port = Number(process.env.ARTIUM_FIXTURE_PORT);
serverDefaults.temporaryDirectory = join(process.env.ARTIUM_FIXTURE_SCRATCH, 'calls');
await import(pathToFileURL(join(root, 'dist/src/server/main.js')));
