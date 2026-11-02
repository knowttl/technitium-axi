import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { archive } from './read-journey.mjs';

// Synthetic cases based on the pinned vendor Apps and Settings API contracts.
const cases = [
  ['070', 'download-and-install', 'downloadAndInstall', '1.0'],
  ['071', 'download-and-update', 'downloadAndUpdate', '2.0'],
  ['072', 'install', 'install', '1.0'],
  ['073', 'update', 'update', '2.0'],
  ['074', 'uninstall', 'uninstall', null],
  ['076', 'config set', 'config/set', '1.0'],
  ['085', 'restore', 'restore', null],
];
export const appsRestoreTasks = cases.map(([id]) => `B4.OP-${id}`);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

export async function appsRestoreJourney({ task, directory, env, run, executable, vendors, config, token, secret, configure, success, failure }) {
  const [id, action, endpoint, version] = cases.find(([id]) => task === `B4.OP-${id}`);
  const operation = `OP-${id}`;
  const command = id === '085' ? 'settings restore' : `app ${action}`;
  await configure([operation]);
  const packageBytes = archive(id === '085' ? ['dns.config', 'zones/restored.test.zone', 'apps/TestApp/dnsApp.config', 'scopes/restored.scope', 'auth.config', 'logs/restored.log'] : ['TestApp.dll', 'dnsApp.config']);
  const packageFile = join(directory, 'package.zip');
  await writeFile(packageFile, packageBytes, { mode: 0o600 });
  const opaque = `oddKey=${secret}\nunknown=+%&=\r\n`;
  const configFile = join(directory, 'app.config');
  await writeFile(configFile, opaque, { mode: 0o600 });
  const read = async (args, resultFile) => {
    const result = await run(executable, [...args, '--config', config, '--json', ...(resultFile ? ['--result-file', resultFile] : [])],
      { env: { ...env, WRITE_TOKEN: token } });
    assert.equal(result.code, 0, result.stdout);
    assert.equal(result.stderr, '');
    for (const canary of [token, secret]) for (const value of [canary, JSON.stringify(canary).slice(1, -1), encodeURIComponent(canary), Buffer.from(canary).toString('base64')]) assert.ok(!result.stdout.includes(value), result.stdout);
    return JSON.parse(result.stdout);
  };
  const execute = async input => {
    const before = vendors.traces.length;
    const preview = await success(command, input);
    assert.equal(vendors.traces.length, before, 'Preview must not dispatch');
    const resultFile = join(directory, `result-${before}.json`);
    if (id === '085') {
      const deniedResult = join(directory, 'denied-result.json');
      await writeFile(deniedResult, 'unchanged', { mode: 0o644 });
      await failure('CONFIG_INSECURE', command, input, ['--execute', '--confirm', preview.preview.digest, '--result-file', deniedResult]);
      assert.equal(vendors.traces.length, before, 'Denied restore result custody must prevent dispatch');
      assert.equal(await readFile(deniedResult, 'utf8'), 'unchanged');
    }
    const result = await success(command, input, ['--execute', '--confirm', preview.preview.digest, '--result-file', resultFile]);
    assert.equal((await stat(resultFile)).mode & 0o777, 0o600);
    const bytes = await readFile(resultFile);
    assert.equal(result.result.sha256, hash(bytes));
    return { result, bytes };
  };
  let calls = 0;
  let fault = false;
  let input;
  let expectedResponse;
  if (id !== '085') {
    const app = (name, version) => ({ name, version, dnsApps: [{ classPath: 'Test.App' }] });
    const keep = app('KeepApp', '9.0');
    let apps = ['070', '072'].includes(id) ? [keep] : [keep, app('TestApp', '1.0')];
    const configs = { KeepApp: 'keep', TestApp: 'old' };
    const record = { name: 'app.test', type: 'APP', rData: { appName: 'TestApp', classPath: 'Test.App' } };
    vendors.responders.set('/api/apps/list', () => ({ body: { status: 'ok', response: { apps } } }));
    vendors.responders.set('/api/apps/config/get', (incoming, bytes) => ({ body: { status: 'ok', response: { config: configs[new URLSearchParams(bytes.toString()).get('name')] } } }));
    vendors.responders.set('/api/zones/records/get', () => ({ body: { status: 'ok', response: { zone: { name: 'app.test', type: 'Primary' }, records: [record] } } }));
    input = { parameters: { name: 'TestApp' } };
    if (['070', '071'].includes(id)) input.parameters.url = `https://packages.example.test/test-v${version}.zip`;
    if (['070', '071'].includes(id)) await failure('USAGE', command, { parameters: { ...input.parameters, url: 'http://packages.example.test/app.zip' } });
    if (['072', '073'].includes(id)) input.upload = { file: packageFile };
    if (id === '076') input.parameters.config = { file: configFile };
    vendors.responders.set(`/api/apps/${endpoint}`, (incoming, bytes) => {
      calls++;
      assert.equal(incoming.method, 'POST');
      assert.equal(incoming.headers.authorization, `Bearer ${token}`);
      const upload = ['072', '073'].includes(id);
      const parameters = upload ? new URL(incoming.url, 'https://fixture.test').searchParams : new URLSearchParams(bytes.toString());
      assert.deepEqual(Object.fromEntries(parameters), { ...input.parameters, ...(id === '076' ? { config: opaque } : {}) });
      if (upload) checkMultipart(incoming, bytes, packageBytes);
      if (fault) return { body: { status: 'error', errorMessage: secret } };
      if (id === '076') configs.TestApp = parameters.get('config');
      else {
        apps = apps.filter(row => row.name !== 'TestApp');
        if (version !== null) apps.push(app('TestApp', version));
      }
      expectedResponse = { status: 'ok', response: id === '076' || id === '074' ? {} : { [version === '1.0' ? 'installedApp' : 'updatedApp']: app('TestApp', version) } };
      return { body: expectedResponse };
    });
    const result = await execute(input);
    assert.deepEqual(JSON.parse(result.bytes), expectedResponse);
    assert.deepEqual((await read(['app', 'list'])).response.apps, version === null ? [keep] : [keep, app('TestApp', version)]);
    if (id === '076') {
      const protectedConfig = join(directory, 'config-result.json');
      await read(['app', 'config', 'get', '--name', 'TestApp'], protectedConfig);
      assert.equal(JSON.parse(await readFile(protectedConfig, 'utf8')).response.config, opaque);
      await read(['app', 'config', 'get', '--name', 'KeepApp'], protectedConfig);
      assert.equal(JSON.parse(await readFile(protectedConfig, 'utf8')).response.config, 'keep');
    }
    if (id === '074') {
      const recordsFile = join(directory, 'records.json');
      await read(['zone', 'record', 'get', '--zone', 'app.test', '--domain', 'app.test'], recordsFile);
      assert.deepEqual(JSON.parse(await readFile(recordsFile, 'utf8')).response.records, [record]);
    }
  } else {
    const seed = { dnsSettings: { defaultRecordTtl: 300, proxy: { password: secret }, tsigKeys: [{ keyName: 'restored', sharedSecret: secret, algorithmName: 'hmac-sha256' }] },
      zones: { 'restored.test': 'archived' }, apps: { TestApp: 'archived' }, scopes: { restored: 'archived' }, authConfig: { restored: 'archived' }, logs: { 'restored.log': 'archived' } };
    let state;
    vendors.responders.set('/api/settings/restore', (incoming, bytes) => {
      calls++;
      assert.equal(incoming.method, 'POST');
      assert.equal(incoming.headers.authorization, `Bearer ${token}`);
      const parameters = Object.fromEntries(new URL(incoming.url, 'https://fixture.test').searchParams);
      assert.deepEqual(parameters, Object.fromEntries(Object.entries(input.parameters).map(([key, value]) => [key, String(value)])));
      checkMultipart(incoming, bytes, packageBytes);
      for (const key of Object.keys(seed)) {
        if (parameters[key] !== 'true') continue;
        state[key] = ['dnsSettings', 'authConfig'].includes(key) || parameters.deleteExistingFiles === 'true' ? structuredClone(seed[key]) : { ...state[key], ...seed[key] };
        if (fault) return { body: { status: 'error', errorMessage: secret } };
      }
      expectedResponse = { status: 'ok', response: state.dnsSettings };
      return { body: expectedResponse };
    });
    for (const deleteExistingFiles of [false, true]) {
      state = { dnsSettings: { defaultRecordTtl: 3600 }, zones: { extra: 'keep' }, apps: { extra: 'keep' }, scopes: { extra: 'keep' }, authConfig: { extra: 'keep' }, logs: { extra: 'keep' } };
      input = { parameters: { node: 'primary.example.test', dnsSettings: true, zones: true, apps: true, scopes: true, authConfig: true, logs: true, deleteExistingFiles }, upload: { file: packageFile } };
      const result = await execute(input);
      assert.deepEqual(JSON.parse(result.bytes), { status: 'ok', response: seed.dnsSettings });
      assert.deepEqual(state, Object.fromEntries(Object.entries(seed).map(([key, value]) => [key, ['dnsSettings', 'authConfig'].includes(key) || deleteExistingFiles ? value : { extra: 'keep', ...value }])));
    }
    input = { parameters: { dnsSettings: false, webServiceSettings: false, logs: true }, upload: { file: packageFile } };
    state.zones['keep.test'] = 'keep';
    state.logs = { extra: 'keep' };
    const before = structuredClone(state);
    const result = await execute(input);
    assert.deepEqual(JSON.parse(result.bytes), { status: 'ok', response: seed.dnsSettings });
    assert.deepEqual(state, { ...before, logs: { extra: 'keep', 'restored.log': 'archived' } });
    // A later handler may fail after an earlier category has already been restored.
    state.dnsSettings.defaultRecordTtl = 999;
    input.parameters = { dnsSettings: true, apps: true };
    fault = true;
    const preview = await success(command, input);
    await failure('OUTCOME_UNKNOWN', command, input, ['--execute', '--confirm', preview.preview.digest]);
    assert.equal(state.dnsSettings.defaultRecordTtl, 300);
    await failure('REPLAY_DENIED', command, input, ['--execute', '--confirm', preview.preview.digest]);
  }
  if (id !== '085') {
    fault = true;
    const preview = await success(command, input);
    const before = calls;
    await failure('OUTCOME_UNKNOWN', command, input, ['--execute', '--confirm', preview.preview.digest]);
    await failure('REPLAY_DENIED', command, input, ['--execute', '--confirm', preview.preview.digest]);
    assert.equal(calls, before + 1);
  }
  if (['072', '073', '085'].includes(id)) {
    const invalidFile = join(directory, 'invalid.zip');
    await writeFile(invalidFile, 'invalid zip', { mode: 0o600 });
    await failure('UPLOAD_INVALID', command, { ...input, upload: { file: invalidFile } });
  }
  const journal = join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d');
  for (const name of await readdir(journal)) {
    const bytes = await readFile(join(journal, name), 'utf8');
    for (const canary of [token, secret]) for (const value of [canary, JSON.stringify(canary).slice(1, -1), encodeURIComponent(canary), Buffer.from(canary).toString('base64')]) assert.ok(!bytes.includes(value));
  }
}

function checkMultipart(incoming, bytes, expected) {
  const boundary = incoming.headers['content-type'].match(/^multipart\/form-data; boundary=(.+)$/)?.[1];
  assert.ok(boundary, 'ZIP uploads require multipart transport');
  const start = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="package.zip"\r\nContent-Type: application/zip\r\n\r\n`);
  assert.deepEqual(bytes, Buffer.concat([start, expected, Buffer.from(`\r\n--${boundary}--\r\n`)]));
}
