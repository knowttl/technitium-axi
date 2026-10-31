import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readdir, rm, watch } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const runner = fileURLToPath(new URL('../scripts/journey.mjs', import.meta.url));
function start(args, env = process.env) {
  const child = spawn(process.execPath, [runner, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', bytes => { stdout += bytes; });
  child.stderr.on('data', bytes => { stderr += bytes; });
  const finished = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  return { child, finished };
}

for (const args of [
  ['--task', 'unknown', '--paths', 'native', '--offline'],
  ['--task', 'B1.01', '--paths', 'missing', '--offline'],
  ['--task', 'B1.01', '--paths', 'native'],
  ['--task', 'B1.01', '--paths', 'native', '--offline', '--unknown'],
]) test(`rejects unsupported journey selection ${args.join(' ')}`, async () => {
  const result = await start(args).finished;
  assert.notEqual(result.code, 0);
  assert.equal(result.stdout, '');
});

test('removes the installation root when a selected host path is unavailable', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'technitium-failure-'));
  try {
    const result = await start(['--task', 'B1.01', '--paths', 'artium', '--offline'],
      { ...process.env, TMPDIR: temporary, ARTIUM_FIXTURE_ROOT: '', ARTIUM_FIXTURE_MANIFEST: '' }).finished;
    assert.notEqual(result.code, 0);
    const report = JSON.parse(result.stdout.trim());
    assert.equal(report.failed, 1);
    assert.equal(report.actual, 0);
    assert.match(report.error, /Set ARTIUM_FIXTURE_ROOT and ARTIUM_FIXTURE_MANIFEST/);
    assert.deepEqual(await readdir(temporary), []);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});

test('cancellation removes active journey roots and exits', { timeout: 30000 }, async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'technitium-cancellation-'));
  const controller = new AbortController();
  const events = watch(temporary, { signal: controller.signal });
  const run = start(['--task', 'B1.02', '--paths', 'native', '--offline'],
    { ...process.env, TMPDIR: temporary });
  try {
    for await (const event of events) {
      if (event.filename?.startsWith('technitium-journey-')) break;
    }
    run.child.kill('SIGTERM');
    const result = await run.finished;
    assert.notEqual(result.code, 0);
    assert.deepEqual(await readdir(temporary), []);
  } finally {
    controller.abort();
    run.child.kill('SIGKILL');
    await run.finished;
    await rm(temporary, { recursive: true, force: true });
  }
});
