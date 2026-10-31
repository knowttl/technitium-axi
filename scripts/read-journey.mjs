import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { decode } from '@toon-format/toon';
import { crc32 } from 'node:zlib';
import { monitorJourney } from './monitor-journey.ts';
import monitor from '../tests/fixtures/monitor-reads.json' with { type: 'json' };

export const monitorTasks = Object.keys(monitor.operations).map(id => `B2.${id}`);
export const readTasks = ['B2.01', 'B2.02', 'B2.03', 'B2.04', 'B2.05', ...monitorTasks];
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

// Stored ZIP records keep independently reviewed entry names and payload bytes visible.
function archive(names) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const name of names) {
    const filename = Buffer.from(name);
    const bytes = name.endsWith('/.exists') ? Buffer.alloc(0) : Buffer.from(`SYNTHETIC-${name}`);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50); header.writeUInt16LE(20, 4);
    header.writeUInt32LE(crc32(bytes), 14); header.writeUInt32LE(bytes.length, 18); header.writeUInt32LE(bytes.length, 22); header.writeUInt16LE(filename.length, 26);
    local.push(header, filename, bytes);
    const index = Buffer.alloc(46);
    index.writeUInt32LE(0x02014b50); index.writeUInt16LE(20, 4); index.writeUInt16LE(20, 6);
    index.writeUInt32LE(crc32(bytes), 16); index.writeUInt32LE(bytes.length, 20); index.writeUInt32LE(bytes.length, 24);
    index.writeUInt16LE(filename.length, 28); index.writeUInt32LE(offset, 42);
    central.push(index, filename);
    offset += header.length + filename.length + bytes.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(names.length, 8); end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}

export async function readJourney({ task, temporary, env, run, executable, vendors, invokeHosted, selectedToken, configureHosted }) {
  const matrix = JSON.parse(await readFile(new URL('../tests/fixtures/read-matrix.json', import.meta.url), 'utf8'));
  const worlds = JSON.parse(await readFile(new URL('../tests/fixtures/archive-worlds.json', import.meta.url), 'utf8'));
  const directory = join(temporary, invokeHosted ? 'hosted-reads' : 'reads');
  await mkdir(directory, { mode: 0o700 });
  const config = join(directory, 'config.json');
  const token = selectedToken ?? 'SYNTHETIC-read-"/+=canary';
  vendors.tokens.set('alpha', token);
  const profile = { origin: vendors.origins[0], auth: 'token', tokenKind: 'api', token: { env: 'READ_TOKEN' },
    caFile: vendors.caFile, tlsServerName: 'localhost' };
  const configure = async tokenKind => configureHosted ? configureHosted(tokenKind)
    : writeFile(config, JSON.stringify({ version: 1, profiles: { alpha: { ...profile, tokenKind } } }), { mode: 0o600 });
  await configure('api');
  const invoke = async (args, json = true) => {
    if (invokeHosted) return await invokeHosted(args, json);
    const result = await run(executable, [...args, ...(json ? ['--json'] : []), ...(args[0] === 'inventory' ? [] : ['--config', config])], { env: { ...env, READ_TOKEN: token } });
    assert.equal(result.stderr, '');
    assert.ok(!result.stdout.includes(token));
    return { ...result, value: json ? JSON.parse(result.stdout) : decode(result.stdout) };
  };
  const success = async (...args) => {
    const result = await invoke(...args);
    assert.equal(result.code, 0, `${args[0].join(' ')}: ${result.stdout}`);
    return result.value;
  };
  const fail = async (args, code) => {
    const result = await invoke(args);
    assert.notEqual(result.code, 0, result.stdout);
    if (invokeHosted && code === 'USAGE') assert.ok(['USAGE', 'INVALID_INPUT'].includes(result.value.error.code), result.stdout);
    else assert.equal(result.value.error.code, code, result.stdout);
  };
  const argumentsFor = row => [...row.command.split(' '), ...row.parameters.flatMap(parameter => [parameter.flag, parameter.requested])];
  const respond = row => vendors.responders.set(row.path, () => ({ body: row.response }));
  const checks = [];
  if (task === 'B2.05') {
    for (const selected of monitorTasks) checks.push(...await monitorJourney({ row: matrix.operations.find(row => row.operation === selected.slice(3)),
      directory, vendors, success, fail, archive, components: worlds.backupComponents }));
    return checks;
  }
  if (task.startsWith('B2.OP-')) return await monitorJourney({ row: matrix.operations.find(row => row.operation === task.slice(3)),
    directory, vendors, success, fail, archive, components: worlds.backupComponents });
  if (task === 'B2.01') {
    const codec = JSON.parse(await readFile(new URL('../package.json', import.meta.resolve('@toon-format/toon')), 'utf8'));
    assert.equal(codec.version, '2.3.1', 'The journey decoder must match the Artium TOON contract');
    const profileRow = matrix.operations.find(row => row.operation === 'OP-012');
    respond(profileRow);
    const profileOutput = await success([...argumentsFor(profileRow), '--full'], false);
    assert.deepEqual(profileOutput.response, profileRow.ordinaryResponse);
    assert.deepEqual(profileOutput.output.collections, {
      memberOfGroups: { returned: 1, available: 1, complete: true },
      sessions: { returned: 1, available: 1, complete: true },
    });
    checks.push('packaged-toon-2.3.1-collections-compatibility');
    const inventory = await success(['inventory']);
    assert.deepEqual(inventory.commands.filter(command => command.operation).map(command => command.operation).sort(),
      ['OP-001', 'OP-006', ...matrix.operations.map(row => row.operation)].sort());
    for (const row of matrix.operations.filter(row => row.kind === 'json')) {
      respond(row);
      const args = [...argumentsFor(row), '--full'];
      const expectedForm = new URLSearchParams(row.parameters.filter(parameter => parameter.location === 'form').map(parameter => [parameter.name, parameter.requested]));
      const actual = await success(args);
      if (row.operation === 'OP-075') assert.equal(actual.sha256, hash(JSON.stringify(row.response)));
      else assert.deepEqual(actual.response, row.ordinaryResponse, `${row.operation} approved output differs`);
      const trace = vendors.traces.at(-1);
      assert.equal(trace.path, row.path);
      assert.equal(trace.method, 'POST');
      assert.equal(trace.inputHash, hash(expectedForm.toString()));
      assert.equal(trace.bearerHash, hash(token));
      if (row.operation !== 'OP-012') {
        const toon = await success(args, false);
        assert.deepEqual({ ...toon, result: undefined }, { ...actual, result: undefined });
      }
      const invalid = row.parameters.find(parameter => parameter.invalid !== null);
      const required = row.parameters.find(parameter => parameter.required);
      if (invalid || required) {
        const parameter = invalid ?? required;
        const failing = [...args];
        const index = failing.indexOf(parameter.flag);
        failing.splice(index, 2, ...(invalid ? [parameter.flag, parameter.invalid] : []));
        const count = vendors.traces.length;
        await fail(failing, 'USAGE');
        assert.equal(vendors.traces.length, count, 'Invalid read input reached the vendor');
      } else {
        vendors.responders.set(row.path, () => ({ body: { status: 'ok' } }));
        await fail(args, 'UPSTREAM_INVALID');
      }
    }
    const options = matrix.operations.find(row => row.operation === 'OP-031');
    vendors.responders.set(options.path, () => ({ body: { status: 'ok', response: { ...options.response.response, catalog: 'catalog1' } } }));
    assert.equal((await success(argumentsFor(options))).response.catalog, 'catalog1');
    vendors.responders.set(options.path, () => ({ body: { status: 'ok', response: { ...options.response.response, catalog: 7 } } }));
    await fail(argumentsFor(options), 'UPSTREAM_INVALID');
    checks.push('read-contracts-and-wire-matrix');
  }
  if (task === 'B2.02') {
    for (const row of matrix.operations.filter(row => row.kind !== 'json' || ['OP-075', 'OP-079', 'OP-050'].includes(row.operation))) {
      const bytes = row.kind === 'json' ? Buffer.from(JSON.stringify(row.response)) : row.kind === 'zip'
        ? Buffer.from('504b0506000000000000000000000000000000000000', 'hex')
        : Buffer.from(row.kind === 'csv' ? 'name,value\nsynthetic,7\n' : 'SYNTHETIC-download-bytes\n');
      const contentType = row.kind === 'json' ? 'application/json' : row.kind === 'zip' ? 'application/zip' : row.kind === 'csv' ? 'text/csv' : 'text/plain';
      vendors.responders.set(row.path, () => ({ bytes, contentType, ...(row.operation === 'OP-125' ? { headers: { 'last-modified': worlds.baseline } } : {}) }));
      const destination = join(directory, `${row.operation}.result`);
      const value = await success([...argumentsFor(row), '--result-file', destination]);
      assert.equal(vendors.traces.at(-1).inputHash, hash(new URLSearchParams(row.parameters.filter(parameter => parameter.location === 'form').map(parameter => [parameter.name, parameter.requested])).toString()));
      assert.deepEqual(await readFile(destination), bytes);
      assert.equal(value.result.sha256, hash(bytes));
      assert.equal((await stat(destination)).mode & 0o777, 0o600);
      for (const canary of ['SYNTHETIC-opaque-canary', 'SYNTHETIC-tsig-canary', 'SYNTHETIC-proxy-canary']) assert.ok(!JSON.stringify(value).includes(canary));
      vendors.responders.set(row.path, () => ({ body: { status: 'error', errorMessage: token } }));
      await fail([...argumentsFor(row), '--result-file', destination], 'UPSTREAM_ERROR');
      assert.deepEqual(await readFile(destination), bytes, 'Failed read replaced the last valid result');
    }
    for (const world of worlds.transferWorlds) {
      const bytes = archive(world.entries);
      const row = matrix.operations.find(row => row.operation === 'OP-125');
      vendors.responders.set(row.path, () => ({ bytes, contentType: 'application/zip', headers: { 'last-modified': worlds.baseline } }));
      const destination = join(directory, `${world.name}.zip`);
      const value = await success([...row.command.split(' '), '--include-zones', world.includeZones,
        '--if-modified-since', worlds.baseline, '--result-file', destination]);
      assert.deepEqual(await readFile(destination), bytes);
      assert.equal(value.result.sha256, hash(bytes));
      assert.equal(vendors.traces.at(-1).headers['if-modified-since'], worlds.baseline);
      assert.equal(vendors.traces.at(-1).inputHash, hash(new URLSearchParams({ includeZones: world.includeZones }).toString()));
    }
    checks.push('exact-protected-formats-and-json-error-refusal');
  }
  if (task === 'B2.03') {
    const row = matrix.operations.find(row => row.operation === 'OP-020');
    const zones = Array.from({ length: 203 }, (_, index) => ({ name: `z${index}.example.test`, type: 'Primary', disabled: false }));
    vendors.responders.set(row.path, (_request, body) => {
      const page = Number(new URLSearchParams(body.toString()).get('pageNumber'));
      return { body: { status: 'ok', response: { zones: zones.slice((page - 1) * 100, page * 100), pageNumber: page, totalPages: 3, totalZones: 203 } } };
    });
    const first = await success(['zone', 'list']);
    assert.equal(first.response.zones.length, 100);
    assert.equal(first.output.complete, false);
    assert.equal(first.output.nextPage, 2);
    const full = await success(['zone', 'list', '--full']);
    assert.deepEqual(full.response.zones, zones);
    assert.equal(full.output.complete, true);
    const bounded = await success(['zone', 'list', '--full', '--max-pages', '2']);
    assert.equal(bounded.response.zones.length, 200);
    assert.equal(bounded.output.complete, false);
    assert.equal(bounded.output.nextPage, 3);
    assert.deepEqual((await success(['zone', 'list', '--fields', 'name'])).response.zones[0], { name: 'z0.example.test' });
    const empty = { pageNumber: 0, totalPages: 0, totalZones: 0, zones: [] };
    for (const args of [['zone', 'list'], ['zone', 'list', '--full'], ['zone', 'list', '--page-number', '2']]) {
      vendors.responders.set(row.path, () => ({ body: { status: 'ok', response: empty } }));
      const result = await success(args);
      assert.deepEqual(result.response, empty);
      assert.equal(result.output.complete, true);
      assert.equal(result.output.requests, 1);
      assert.equal(result.output.nextPage, undefined);
    }
    for (const ending of [empty, { ...empty, totalPages: 1 }, { ...empty, totalZones: 1 }, { ...empty, zones: [zones[0]] },
      { ...empty, pageNumber: 3 }]) {
      for (const subsequent of [false, true]) {
        vendors.responders.set(row.path, (_request, body) => {
          const page = Number(new URLSearchParams(body.toString()).get('pageNumber'));
          return { body: { status: 'ok', response: subsequent && page === 1
            ? { zones: [zones[0]], pageNumber: 1, totalPages: 2, totalZones: 2 } : ending } };
        });
        if (ending === empty) {
          const result = await success(['zone', 'list', '--full']);
          assert.deepEqual(result.response.zones, subsequent ? [zones[0]] : []);
          assert.equal(result.output.pages, subsequent ? 2 : 1);
          assert.equal(result.output.complete, !subsequent);
          if (subsequent) assert.equal(result.output.stoppedBy, 'PROVIDER_TOTAL_MISMATCH');
        } else await fail(['zone', 'list', '--full'], 'UPSTREAM_INVALID');
      }
    }
    let attempts = 0;
    vendors.responders.set(row.path, () => ++attempts === 1 ? { status: 503, body: {} } : { body: row.response });
    assert.equal((await success(argumentsFor(row))).response.zones.length, row.response.response.zones.length);
    assert.equal(attempts, 2);
    await configure('single-use');
    attempts = 0;
    await fail(argumentsFor(row), 'UPSTREAM_HTTP');
    assert.equal(attempts, 1);
    await configure('api');
    for (const [response, code] of [
      [{ status: 429, body: {}, headers: { 'retry-after': '9' } }, 'RATE_LIMITED'],
      [{ status: 403, body: {} }, 'PERMISSION_DENIED'],
      [{ status: 404, bytes: Buffer.alloc(0) }, 'UNSUPPORTED_OPERATION'],
      [{ body: { status: 'invalid-token' } }, 'AUTH_REQUIRED'],
      [{ body: { status: '2fa-required' } }, 'TWO_FACTOR_REQUIRED'],
      [{ body: { status: 'error', errorMessage: token } }, 'UPSTREAM_ERROR'],
      [{ bytes: Buffer.from('{') }, 'UPSTREAM_INVALID'],
      [{ body: { status: 'ok', response: {} } }, 'UPSTREAM_INVALID'],
      [{ body: { status: 'ok', response: { zones: 'wrong' } } }, 'UPSTREAM_INVALID'],
    ]) {
      vendors.responders.set(row.path, () => response);
      await fail(argumentsFor(row), code);
    }
    respond(row);
    await fail([...argumentsFor(row), '--max-bytes', '10'], 'RESPONSE_LIMIT');
    checks.push('paging-caps-retries-and-structured-errors');
  }
  if (task === 'B2.04') {
    const before = vendors.traces.length;
    const inventory = await success(['inventory']);
    const backup = inventory.commands.find(command => command.operation === 'OP-084').archive;
    const transfer = inventory.commands.find(command => command.operation === 'OP-125').archive;
    assert.deepEqual(backup, transfer);
    assert.deepEqual(Object.keys(backup.backup).sort(), Object.keys(worlds.backupComponents).sort());
    assert.deepEqual(backup.backup.zones, ['zones/*.zone']);
    assert.equal(transfer.transfer.appEntries.unchanged, 'apps/<name>/.exists');
    assert.equal(transfer.transfer.response.status, 200);
    assert.equal(transfer.transfer.response.contentType, 'application/zip');
    assert.ok(transfer.transfer.excludedEntries.includes('zones/*.zone'));
    assert.equal(vendors.traces.length, before, 'Archive review must not execute a transfer');
    checks.push('source-reviewed-backup-and-transfer-entry-map');
  }
  return checks;
}
