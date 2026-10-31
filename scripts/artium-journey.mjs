import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decode } from '@toon-format/toon';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');

export async function artiumJourney({ temporary, sha256, env, run, packageRoot, origins, signal }) {
  const root = process.env.ARTIUM_FIXTURE_ROOT;
  const manifestPath = process.env.ARTIUM_FIXTURE_MANIFEST;
  assert.ok(root && manifestPath, 'Set ARTIUM_FIXTURE_ROOT and ARTIUM_FIXTURE_MANIFEST to the prepared local admission fixture');
  const fixture = JSON.parse(await readFile(new URL('../tests/fixtures/host-contract.json', import.meta.url), 'utf8'));
  const manifestBytes = await readFile(manifestPath);
  assert.equal(hash(manifestBytes), fixture.source.manifestSha256, 'Unreviewed fixture manifest');
  const manifest = JSON.parse(manifestBytes);
  assert.equal(manifest.fixtureCommit, fixture.source.fixtureRevision);
  for (const [file, digest] of Object.entries(fixture.source.files)) {
    assert.equal(hash(await readFile(join(root, file))), digest, `Host fixture drift: ${file}`);
  }
  const pin = manifest.tools.find(tool => tool.tool === 'technitium-axi');
  assert.equal(hash(await readFile(pin.tarball)), pin.sha256);
  assert.equal(sha256, pin.sha256, 'Current tarball differs from the reviewed host package pin');
  const hostPackage = join(root, 'tools/node_modules/@knowttl/technitium-axi');
  assert.ok((await realpath(hostPackage)).startsWith(`${root}/tools/node_modules/`), 'Host package must be installed, not linked to a source checkout');
  const hostExecutable = join(hostPackage, 'bin/technitium-axi.js');
  for (const file of ['package.json', 'bin/technitium-axi.js', 'dist/cli.js', 'dist/catalogue.js', 'axi-credential.schema.json', 'command-inventory.json']) {
    assert.deepEqual(await readFile(join(hostPackage, file)), await readFile(join(packageRoot, file)), `Installed package differs: ${file}`);
  }
  const scratch = join(temporary, 'host');
  await mkdir(scratch, { mode: 0o700 });
  const password = 'SYNTHETIC-bootstrap-password-1';
  const replacement = 'SYNTHETIC-replacement-password-2';
  const bootstrap = join(scratch, 'bootstrap-password');
  await writeFile(bootstrap, password, { mode: 0o600 });
  const reservation = createServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  const serverEnv = { ...env, ARTIUM_FIXTURE_ROOT: root, ARTIUM_FIXTURE_PORT: String(port), ARTIUM_FIXTURE_SCRATCH: scratch,
    ARTIUM_AXI_MASTER_KEY: Buffer.alloc(32, 17).toString('base64'), ARTIUM_AXI_DATABASE_FILE: join(scratch, 'data', 'artium.db'),
    ARTIUM_AXI_ADMIN_USERNAME: 'fixture-admin', ARTIUM_AXI_ADMIN_PASSWORD_FILE: bootstrap };
  const server = spawn(process.execPath, [fileURLToPath(new URL('./artium-server.mjs', import.meta.url))], {
    cwd: root, env: serverEnv, signal, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const closed = new Promise(resolve => server.once('close', resolve));
  const startups = [];
  const traces = [];
  let output = '';
  let errors = '';
  const ready = new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error(`Artium startup timed out: ${errors}`)), 20000);
    server.once('error', reject);
    server.once('close', () => { clearTimeout(deadline); reject(new Error(`Artium exited before readiness: ${errors}`)); });
    server.stdout.on('data', bytes => {
      output += bytes;
      let newline;
      while ((newline = output.indexOf('\n')) >= 0) {
        const line = output.slice(0, newline);
        output = output.slice(newline + 1);
        if (line) startups.push(JSON.parse(line));
      }
    });
    server.stderr.on('data', bytes => {
      errors += bytes;
      if (errors.split('\n').some(line => { try { return JSON.parse(line).event === 'listening'; } catch { return false; } })) {
        clearTimeout(deadline);
        resolve();
      }
    });
  });
  async function request(path, body, actor, method = body === undefined ? 'GET' : 'POST', identity = 'fixture-admin') {
    const encoded = body === undefined ? undefined : JSON.stringify(body);
    const headers = { accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...actor };
    const response = await fetch(`${origin}${path}`, { method, headers, body: encoded, signal });
    traces.push({ method, path, headers: { accept: headers.accept, contentType: headers['content-type'] ?? null,
      authorization: headers.authorization ? 'present' : 'absent' }, inputHash: hash(encoded ?? ''), identity });
    const value = response.status === 204 ? null : await response.json();
    return { status: response.status, value };
  }
  const success = async (...args) => {
    const response = await request(...args);
    assert.ok(response.status >= 200 && response.status < 300, `${args[0]}: ${JSON.stringify(response.value)}`);
    return response.value;
  };
  const cli = join(root, 'dist/cli/artium-axi.mjs');
  const clientEnv = identity => ({ ...env, XDG_CONFIG_HOME: join(scratch, identity), ARTIUM_AXI_URL: origin, ARTIUM_AXI_TEST_HTTP: '1' });
  async function login(identity, initial, next) {
    const client = clientEnv(identity);
    const first = await run(process.execPath, [cli, 'login', '--username', identity, '--password-stdin'], { env: client, stdin: initial });
    assert.notEqual(first.code, 0, 'Initial password must require replacement');
    assert.equal(decode(first.stdout).error.code, 'PASSWORD_CHANGE_REQUIRED');
    const changed = await run(process.execPath, [cli, 'passwd', '--password-stdin'], { env: client, stdin: next });
    assert.equal(changed.code, 0, changed.stdout + changed.stderr);
    const second = await run(process.execPath, [cli, 'login', '--username', identity, '--password-stdin'], { env: client, stdin: next });
    assert.equal(second.code, 0, second.stdout + second.stderr);
    const session = JSON.parse(await readFile(join(scratch, identity, 'artium-axi/session.json'), 'utf8'));
    return { authorization: `Bearer ${session.accessToken}` };
  }
  try {
    await ready;
    assert.deepEqual(await success('/health/ready'), { status: 'ok' });
    const admin = await login('fixture-admin', password, replacement);
    const reauth = await success('/v1/auth/reauth', { password: replacement }, admin);
    admin['x-artium-reauth-ticket'] = reauth.ticket;
    const tool = await success('/v1/admin/tools/technitium-axi', undefined, admin);
    await success('/v1/admin/tools/technitium-axi/credential', {
      expectedRevision: 0, expectedToolRevision: tool.revision,
      value: { origin: origins?.[0] ?? 'https://127.0.0.1:9443', auth: 'token', tokenKind: 'api', token: 'SYNTHETIC-staged-token-alpha' },
    }, admin, 'PUT');
    const current = await success('/v1/admin/tools/technitium-axi', undefined, admin);
    await success('/v1/admin/tools/technitium-axi', { enabled: true, expectedRevision: current.revision }, admin, 'PATCH');
    const role = await success('/v1/admin/roles', { name: 'Synthetic discovery readers' }, admin);
    await success(`/v1/admin/roles/${role.id}/tools`, { tools: ['technitium-axi'], expectedRevision: role.revision }, admin, 'PUT');
    const actors = {};
    for (const identity of fixture.seed.callers) {
      await success('/v1/admin/users', { username: identity, displayName: identity, temporaryPassword: `SYNTHETIC-initial-${identity}`,
        administrator: false, roleIds: fixture.seed.granted.includes(identity) ? [role.id] : [] }, admin);
      actors[identity] = await login(identity, `SYNTHETIC-initial-${identity}`, `SYNTHETIC-replacement-${identity}`);
    }
    for (const flag of ['--version', '-v', '-V']) {
      const version = await run(process.execPath, [cli, 'technitium-axi', flag], { env: clientEnv('alpha') });
      assert.equal(version.code, 0, version.stdout + version.stderr);
      assert.equal(version.stdout, `${fixture.expected.version}\n`);
    }
    const help = await run(process.execPath, [cli, 'technitium-axi', '--help'], { env: clientEnv('alpha') });
    assert.equal(help.code, 0, help.stdout + help.stderr);
    assert.deepEqual(decode(help.stdout).commands.map(command => command.command), ['schema', 'inventory']);
    for (const [command, file] of [['schema', 'axi-credential.schema.json'], ['inventory', 'command-inventory.json']]) {
      const result = await run(process.execPath, [cli, 'technitium-axi', command, '--json'], { env: clientEnv('alpha') });
      assert.equal(result.code, 0, result.stdout + result.stderr);
      assert.deepEqual(JSON.parse(result.stdout), JSON.parse(await readFile(join(packageRoot, file), 'utf8')));
    }
    const runPath = fixture.request.run.path;
    const result = await success(runPath, { args: ['--version'] }, actors.alpha, 'POST', 'alpha');
    assert.deepEqual(Object.keys(result).sort(), fixture.response.runFields.toSorted());
    assert.equal(result.stdout, `${fixture.expected.version}\n`);
    assert.equal(result.exitCode, 0);
    assert.equal(result.source, 'technitium-axi');
    const denied = await request(runPath, { args: ['--help'] }, actors.beta, 'POST', 'beta');
    assert.equal(denied.value.error.code, fixture.expected.ungrantedCaller);
    const cases = [
      [{ args: ['--bogus'] }, fixture.expected.unknownFlag],
      [{ args: ['--help'], stdin: '' }, fixture.expected.fileOnDiscovery],
      [{ args: ['--help'], files: [fixture.request.inputFile.example] }, fixture.expected.fileOnDiscovery],
      [{ args: ['--help'], files: [{ ...fixture.request.inputFile.example, name: '../input.json' }] }, fixture.expected.invalidFile],
      [{ args: ['--help'], files: [{ ...fixture.request.inputFile.example, size: 3 }] }, fixture.expected.invalidFile],
      [{ args: ['--help'], files: [{ ...fixture.request.inputFile.example, contentBase64: 'e31=' }] }, fixture.expected.invalidFile],
      [{ args: ['--help'], files: [fixture.request.inputFile.example, fixture.request.inputFile.example] }, fixture.expected.invalidFile],
    ];
    for (const [body, expected] of cases) {
      const rejected = await request(runPath, body, actors.alpha, 'POST', 'alpha');
      assert.equal(rejected.value.error.code, expected);
    }
    const preparePath = `${fixture.request.transfer.prefixes[0]}/prepare`;
    const acceptedShape = await request(preparePath, fixture.request.transfer.prepare, admin);
    assert.equal(acceptedShape.value.error.code, 'TOOL_DISABLED', 'Valid transfer input reaches the real disabled-tool policy');
    for (const invalid of [
      { ...fixture.request.transfer.prepare, targetDigest: 'not-a-sha256' },
      { ...fixture.request.transfer.prepare, unexpected: true },
      { ...fixture.request.transfer.prepare, selection: { operation: 'not-admitted', selector: 'alpha', type: 'bin' } },
    ]) {
      const rejected = await request(preparePath, invalid, admin);
      assert.equal(rejected.value.error.code, 'INVALID_INPUT');
    }
    const unsupported = await request('/v1/transfers/technitium/prepare', fixture.request.transfer.prepare, actors.alpha, 'POST', 'alpha');
    assert.equal(unsupported.value.error.code, fixture.expected.technitiumTransferRoute);
    assert.ok(startups.length >= 7, 'Host must start the actual packaged executable for public calls');
    for (const startup of startups) {
      assert.equal(startup.argv[0], process.execPath);
      assert.equal(startup.argv[1], hostExecutable);
      assert.equal(startup.executableSha256, hash(await readFile(join(packageRoot, 'bin/technitium-axi.js'))));
      assert.ok(Number.isInteger(startup.pid) && startup.pid > 0);
    }
    assert.ok(startups.some(startup => startup.argv.slice(2).join(' ') === 'schema --json'));
    assert.ok(startups.some(startup => startup.argv.slice(2).join(' ') === 'inventory --json'));
    assert.deepEqual(await readdir(join(scratch, 'calls')), []);
    const publicStartups = startups.map(startup => ({ ...startup,
      argv: ['node', '<host-installed-package>/bin/technitium-axi.js', ...startup.argv.slice(2)],
    }));
    console.log(JSON.stringify({ host: { fixtureRevision: manifest.fixtureCommit, manifestSha256: hash(manifestBytes),
      packageSha256: sha256, argvPaths: 'normalized after exact installed-path checks', processStarts: publicStartups, requests: traces } }));
    return ['artium:public-discovery', 'artium:authenticated-run-and-denial', 'artium:file-and-transfer-contract', 'artium:installed-process-provenance'];
  } finally {
    server.kill('SIGTERM');
    const deadline = setTimeout(() => server.kill('SIGKILL'), 5000);
    await closed;
    clearTimeout(deadline);
  }
}
