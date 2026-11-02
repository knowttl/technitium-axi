import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, realpath, rm } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv';
import { decode } from '@toon-format/toon';
import { fakeVendors } from './vendor-fixture.mjs';
import { credentialJourney, credentialTasks } from './credential-journey.mjs';
import { readJourney, readTasks, monitorTasks } from './read-journey.mjs';
import { writeJourney, writeTasks } from './write-journey.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2);
const inside = args.at(-1) === '--namespace';
if (inside) args.pop();
let task;
let paths;
let offline = false;
let operation;
for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--task' && !task) task = args[++i];
  else if (arg === '--paths' && !paths) paths = args[++i]?.split(',');
  else if (arg === '--offline' && !offline) offline = true;
  else if (arg === '--operation' && !operation) operation = args[++i];
  else throw new Error(`Unknown or repeated journey argument: ${arg}`);
}
assert.ok(['B1.01', 'B1.02', ...Object.keys(credentialTasks), ...readTasks, ...writeTasks].includes(task), 'Select a supported --task');
assert.equal(operation, /^B[12]\.OP-/.test(task) ? task.slice(3) : undefined, 'Operation selection must match the operation task');
assert.ok(paths?.length && new Set(paths).size === paths.length && paths.every(path => ['native', 'artium'].includes(path)), 'Select --paths native,artium');
assert.ok(offline, '--offline is required');

const children = new Set();
const cancellation = new AbortController();
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => cancellation.abort());
async function run(executable, argv, options = {}) {
  const { stdin, ...spawnOptions } = options;
  const child = spawn(executable, argv, { cwd: root, stdio: [stdin === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
    signal: cancellation.signal, ...spawnOptions });
  if (child.stdin) { child.stdin.on('error', () => {}); child.stdin.end(stdin); }
  children.add(child);
  let stdout = '';
  let stderr = '';
  let failure;
  child.stdout.on('data', bytes => { stdout += bytes; });
  child.stderr.on('data', bytes => { stderr += bytes; });
  return await new Promise((resolve, reject) => {
    child.once('error', error => { failure = error; });
    child.once('close', (code, signal) => {
      children.delete(child);
      if (failure) reject(failure);
      else if (signal) reject(new Error(`Journey child terminated: ${signal}`));
      else resolve({ code, stdout, stderr });
    });
  });
}

if (!inside) {
  assert.equal(process.platform, 'linux', 'Offline journey requires Linux user/network namespaces and iproute2');
  const result = await run('unshare', ['--user', '--map-root-user', '--net', '--pid', '--fork', '--mount-proc', '--kill-child=SIGTERM', 'sh', '-c',
    'ip link set lo up && exec "$@"', 'journey', process.execPath, fileURLToPath(import.meta.url), ...args, '--namespace']);
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exitCode = result.code;
} else {
  // The kernel blocks egress for every descendant, including native subprocesses.
  // A flag alone cannot opt out: verify the namespace has only loopback interfaces.
  const interfaces = (await readFile('/proc/net/dev', 'utf8')).split('\n').slice(2).filter(line => line.includes(':')).map(line => line.split(':')[0].trim());
  assert.deepEqual(interfaces, ['lo'], 'Journey namespace must contain only loopback');
  const temporary = await mkdtemp(join(tmpdir(), 'technitium-journey-'));
  let vendors;
  const checks = [];
  const identityTask = Object.hasOwn(credentialTasks, task);
  const readTask = readTasks.includes(task);
  const writeTask = writeTasks.includes(task);
  assert.ok(!writeTask || !paths.includes('artium'), 'Hosted write admission is a separate release-candidate check; this journey proves the native path only');
  const expected = (paths.includes('native') ? (writeTask ? 1 : readTask ? (task === 'B2.05' ? monitorTasks.length : task === 'B2.01' ? 2 : 1) : identityTask ? credentialTasks[task].length : task === 'B1.02' ? 7 : 5) : 0) + (paths.includes('artium') ? (readTask ? 6 : identityTask ? 5 : 4) : 0);
  try {
    const home = join(temporary, 'home');
    await mkdir(home, { mode: 0o700 });
    const env = { PATH: `${dirname(process.execPath)}:/usr/local/bin:/usr/bin:/bin:/usr/sbin`,
      HOME: home, XDG_CONFIG_HOME: join(home, 'config'), XDG_STATE_HOME: join(home, 'state'),
      APPDATA: join(home, 'config'), LOCALAPPDATA: join(home, 'state'),
      TMPDIR: temporary, NODE_DISABLE_COMPILE_CACHE: '1',
      npm_config_cache: join(temporary, 'cache'), npm_config_offline: 'true',
      npm_config_audit: 'false', npm_config_fund: 'false' };
    // Use the prepared npm cache only during offline installation;
    // never expose the caller's home to the tool.
    const cache = process.env.npm_config_cache ?? join(homedir(), '.npm');
    const installEnvironment = { ...env, npm_config_cache: cache };
    const packed = await run('npm', ['pack', '--offline', '--json', '--pack-destination', temporary], { env: installEnvironment });
    assert.equal(packed.code, 0, packed.stderr);
    const pack = JSON.parse(packed.stdout.slice(packed.stdout.indexOf('[\n')))[0];
    const tarball = join(temporary, pack.filename);
    const sha256 = createHash('sha256').update(await readFile(tarball)).digest('hex');
    const prefix = join(temporary, 'installed');
    const installed = await run('npm', ['install', '--prefix', prefix, '--offline', '--ignore-scripts', '--no-package-lock', tarball],
      { cwd: temporary, env: installEnvironment });
    assert.equal(installed.code, 0, installed.stderr);
    const executable = join(prefix, 'node_modules', '.bin', 'technitium-axi');
    const packageRoot = join(prefix, 'node_modules', '@knowttl', 'technitium-axi');
    assert.equal(await realpath(executable), join(packageRoot, 'bin', 'technitium-axi.js'));
    const setup = JSON.parse(await readFile(new URL('../tests/fixtures/setup.json', import.meta.url), 'utf8'));
    const invoke = argv => run(executable, argv, { cwd: home, env });
    if (task === 'B1.02' || identityTask || readTask || writeTask) {
      vendors = await fakeVendors(temporary, run, env);
      await vendors.check();
    }
    if (paths.includes('native') && identityTask) {
      checks.push(...await credentialJourney({ task, temporary, env, run, executable, vendors }));
    }
    if (paths.includes('native') && readTask) {
      checks.push(...await readJourney({ task, temporary, env, run, executable, vendors }));
    }
    if (paths.includes('native') && writeTask) checks.push(...await writeJourney({ task, temporary, env, run, executable, vendors }));
    if (paths.includes('native') && !identityTask && !readTask && !writeTask) {
      for (const flag of ['--version', '-v', '-V']) {
        const result = await invoke([flag]);
        assert.deepEqual(result, { code: 0, stdout: `${setup.response.version}\n`, stderr: '' });
      }
      checks.push('native:installed-version');
      const help = await invoke(['--help']);
      assert.equal(help.code, 0, help.stderr);
      assert.deepEqual(decode(help.stdout).commands.map(command => command.command), setup.response.commands);
      checks.push('native:offline-help');
      const schema = await invoke(['schema', '--json']);
      assert.equal(schema.code, 0, schema.stderr);
      const profileSchema = JSON.parse(schema.stdout);
      const ajv = new Ajv({ strict: true });
      ajv.addKeyword({ keyword: 'x-secret', schemaType: 'boolean' });
      const validate = ajv.compile(profileSchema);
      assert.equal(validate(setup.seed.profile), true, JSON.stringify(validate.errors));
      for (const invalid of [
        { ...setup.seed.profile, token: 'inline-canary' },
        { ...setup.seed.profile, unexpected: true },
        { ...setup.seed.profile, origin: 'https://example.test/path' },
        { ...setup.seed.profile, token: { env: 'INVALID-NAME' } },
        { ...setup.seed.profile, token: { env: 'TOKEN', file: '/tmp/token' } },
        { ...setup.seed.profile, writes: { allowWrites: true, operations: ['*'] } },
      ]) assert.equal(validate(invalid), false);
      assert.equal(profileSchema.properties.token['x-secret'], setup.expected.secretAnnotation);
      assert.deepEqual(profileSchema, JSON.parse(await readFile(join(packageRoot, 'axi-credential.schema.json'), 'utf8')));
      checks.push('native:credential-contract');
      const inventory = await invoke(['inventory', '--json']);
      assert.equal(inventory.code, 0, inventory.stderr);
      const contract = JSON.parse(inventory.stdout);
      assert.deepEqual(contract, JSON.parse(await readFile(join(packageRoot, 'command-inventory.json'), 'utf8')));
      assert.deepEqual(contract.commands.map(command => command.command), setup.response.commands);
      for (const command of contract.commands) {
        const result = await invoke([command.command, '--help']);
        assert.equal(result.code, 0, result.stderr);
        assert.equal(decode(result.stdout).command, command.command);
      }
      checks.push('native:inventory-discovery');
      for (const argv of [['--bogus'], ['schema', '--bogus'], ['bogus'], ['schema', 'extra'], ['--token=inline-canary']]) {
        const result = await invoke(argv);
        assert.equal(result.code, setup.expected.unknownFlagExit);
        assert.equal(decode(result.stdout).error.code, 'USAGE');
        assert.ok(!`${result.stdout}${result.stderr}`.includes('inline-canary'));
      }
      checks.push('native:usage-errors');
      if (task === 'B1.02') {
        checks.push('native:two-https-boundaries', 'native:kernel-egress-denied');
        const result = await invoke(['inventory']);
        assert.equal(result.code, 0, result.stderr);
        assert.deepEqual(decode(result.stdout).commands.map(command => command.command), setup.response.commands);
        assert.equal(vendors.traces.length, 2, 'Discovery must not contact vendor endpoints');
      }
    }
    if (paths.includes('artium')) {
      const { artiumJourney } = await import('./artium-journey.mjs');
      checks.push(...await artiumJourney({ temporary, sha256, env, run, packageRoot,
        origins: vendors?.origins, vendors, task, identityTask, readTask, signal: cancellation.signal }));
    }
    if (vendors && !identityTask && !readTask && !writeTask) assert.equal(vendors.traces.length, 2, 'Discovery must not contact either fake vendor');
    assert.ok(checks.length > 0, 'Zero assertions executed');
    assert.equal(checks.length, expected, 'Selected journey did not execute every expected case');
    console.log(JSON.stringify({ task, paths, expected, actual: checks.length, failed: 0,
      pending: task === 'B3.02' ? 1 : 0, skipped: 0,
      ...(task === 'B3.02' ? { limitations: ['DNAME deletion and B3.02 full-management coverage remain pending shipped-library mapping and independent review'] } : {}),
      platformEvidence: { linux: 'native', windows: identityTask ? 'PENDING - native Windows verification deferred' : 'not selected' }, package: { version: pack.version, sha256, integrity: pack.integrity }, checks }));
  } catch (error) {
    console.log(JSON.stringify({ task, paths, expected, actual: checks.length, failed: 1,
      pending: Math.max(0, expected - checks.length - 1), skipped: 0, error: error.message }));
    process.exitCode = 1;
  } finally {
    for (const child of children) child.kill('SIGKILL');
    await vendors?.close();
    await rm(temporary, { recursive: true, force: true });
  }
}
