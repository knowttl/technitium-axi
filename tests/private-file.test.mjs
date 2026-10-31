import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { PrivateFiles } from '../dist/private-file.js';

const execute = promisify(execFile);

for (const secret of [false, true]) {
  test(`Windows refuses existing files with secret=${secret}`, async () => {
    const temporary = await mkdtemp(join(tmpdir(), 'technitium-private-'));
    try {
      const path = join(temporary, 'private.json');
      await writeFile(path, 'SYNTHETIC-private', { mode: 0o600 });
      await assert.rejects(new PrivateFiles('win32').read(path, secret), {
        code: 'CONFIG_INSECURE', message: 'Windows file ownership and ACL verification is PENDING',
      });
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });
}

test('Windows refuses file writes before creating directories or replacing data', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'technitium-private-'));
  try {
    const files = new PrivateFiles('win32');
    const path = join(temporary, 'existing.json');
    await writeFile(path, 'original', { mode: 0o600 });
    await assert.rejects(files.write(path, 'replacement'), { code: 'CONFIG_INSECURE' });
    await assert.rejects(files.write(join(temporary, 'new', 'result.json'), 'result'), { code: 'CONFIG_INSECURE' });
    assert.equal(await readFile(path, 'utf8'), 'original');
    assert.deepEqual(await readdir(temporary), ['existing.json']);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});

test('Windows environment-only profiles work when the default config is absent', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'technitium-private-'));
  try {
    const cli = new URL('../dist/cli.js', import.meta.url).href;
    const result = await execute(process.execPath, ['--input-type=module', '-e',
      `Object.defineProperty(process, 'platform', { value: 'win32' });
       const { main } = await import(${JSON.stringify(cli)});
       await main(['auth', 'status', '--json']);`], {
      env: { PATH: process.env.PATH, APPDATA: temporary, LOCALAPPDATA: temporary,
        TECHNITIUM_AXI_ORIGIN: 'https://127.0.0.1:9443', TECHNITIUM_AXI_AUTH: 'token',
        TECHNITIUM_AXI_TOKEN_KIND: 'api', TECHNITIUM_AXI_TOKEN: 'SYNTHETIC-env-canary' },
    });
    assert.deepEqual(JSON.parse(result.stdout), { profile: 'env', source: 'environment',
      origin: 'https://127.0.0.1:9443', tokenKind: 'api', tokenSource: { env: 'TECHNITIUM_AXI_TOKEN' } });
    assert.equal(result.stderr, '');
  } finally { await rm(temporary, { recursive: true, force: true }); }
});
