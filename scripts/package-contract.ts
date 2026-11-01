import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
if (process.argv.at(-1) !== '--namespace') {
  // Match the offline journeys: children inherit a namespace with no outbound interface.
  execFileSync('unshare', ['--user', '--map-root-user', '--net', '--pid', '--fork', '--mount-proc',
    '--kill-child=SIGTERM', process.execPath, fileURLToPath(import.meta.url), '--namespace'],
  { cwd: root, stdio: 'inherit', timeout: 30_000 });
  process.exit(0);
}
const interfaces = readFileSync('/proc/net/dev', 'utf8').split('\n').slice(2)
  .filter(line => line.includes(':')).map(line => line.split(':')[0]!.trim());
assert.deepEqual(interfaces, ['lo'], 'Only loopback may exist');

// Published source paths pinned by the package admission contract.
const modules = ['cli', 'catalogue', 'read-contracts', 'archive-contract', 'reads', 'vendor',
  'credentials', 'private-file', 'errors'];
const files = ['package.json', 'README.md', 'LICENSE', 'bin/technitium-axi.js',
  'axi-credential.schema.json', 'command-inventory.json', ...modules.map(name => `dist/${name}.js`)];
const temporary = mkdtempSync(join(tmpdir(), 'technitium-contract-'));
const env = { PATH: process.env.PATH, HOME: temporary, XDG_CONFIG_HOME: temporary,
  npm_config_cache: process.env.npm_config_cache ?? join(homedir(), '.npm'),
  npm_config_offline: 'true', npm_config_audit: 'false', npm_config_fund: 'false',
  npm_config_update_notifier: 'false' };
const run = (command: string, args: string[], cwd = temporary): string =>
  execFileSync(command, args, { cwd, env, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });

try {
  // prepack builds and verifies generated contracts, as it does for publication.
  run('npm', ['pack', '--offline', '--pack-destination', temporary], root);
  const tarballs = readdirSync(temporary).filter(name => name.endsWith('.tgz'));
  assert.equal(tarballs.length, 1);
  const tarball = join(temporary, tarballs[0]!);
  const entries = run('tar', ['-tzf', tarball]).trim().split('\n');
  // An exact allowlist excludes tests, source maps, config, credentials, and extra build files.
  assert.deepEqual(entries.sort(), files.map(name => `package/${name}`).sort());
  const source = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version: string };
  const prefix = join(temporary, 'installed');
  run('npm', ['install', '--prefix', prefix, '--offline', '--ignore-scripts', '--no-package-lock', tarball]);
  const installed = join(prefix, 'node_modules', '@knowttl', 'technitium-axi');
  const manifest = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8')) as {
    name: string; version: string; bin: Record<string, string>;
  };
  assert.equal(manifest.name, '@knowttl/technitium-axi');
  assert.equal(manifest.version, source.version);
  assert.deepEqual(manifest.bin, { 'technitium-axi': 'bin/technitium-axi.js' });
  const bin = join(prefix, 'node_modules', '.bin', 'technitium-axi');
  assert.equal(realpathSync(bin), join(installed, 'bin', 'technitium-axi.js'));
  assert.match(run(bin, ['--help']), /technitium-axi/);
  assert.equal(run(bin, ['--version']).trim(), source.version);

  const require = createRequire(join(prefix, 'package.json'));
  for (const name of modules) {
    const resolved = require.resolve(`@knowttl/technitium-axi/dist/${name}.js`);
    assert.equal(resolved, join(installed, 'dist', `${name}.js`));
    await import(pathToFileURL(resolved).href);
  }
  for (const [command, file] of [['schema', 'axi-credential.schema.json'], ['inventory', 'command-inventory.json']] as const) {
    assert.deepEqual(JSON.parse(run(bin, [command, '--json'])),
      JSON.parse(readFileSync(require.resolve(`@knowttl/technitium-axi/${file}`), 'utf8')));
  }
  console.log('Package contract passed (outbound network denied).');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
