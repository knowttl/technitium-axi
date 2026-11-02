import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export const zoneTasks = [22, 23, 25, 26, 27, 28, 29, 30, 32, 34].map(id => `B3.OP-${String(id).padStart(3, '0')}`);

// Synthetic vendor worlds based on the reviewed zones handlers, not live observations.
export async function zoneJourney({ task, directory, env, run, executable, vendors, config, token, configure, success, failure, execute }) {
  const id = task.slice(3);
  await configure([id]);
  const record = (name, type, rData, ttl = 300) => ({ name, type, ttl, rData });
  const seed = (name, type = 'Primary', serial = 42) => ({ name, type, disabled: false, records: [
    record(name, 'SOA', { serial }), record(`api.${name}`, 'A', { ipAddress: '192.0.2.10' }),
    record(`keep.${name}`, 'TXT', { text: 'stay' }),
  ], notifyNameServers: ['192.0.2.1'], updateNetworkACL: ['192.0.2.0/24'], queryAccessNetworkACL: ['192.0.2.0/24'],
  zoneTransferTsigKeyNames: ['key'], primaryZoneTransferProtocol: 'Tls', userPermissions: [{ username: 'reader', canView: true, canModify: false, canDelete: false }],
  groupPermissions: [{ name: 'Operators', canView: true, canModify: true, canDelete: true }] });
  const zones = new Map([['example.test', seed('example.test')], ['source.test', seed('source.test')], ['keep.test', seed('keep.test', 'Primary', 9)]]);
  const keep = structuredClone(zones.get('keep.test'));
  let reads = 0;
  const read = async (command, flags) => {
    const destination = join(directory, `readback-${reads++}.json`);
    const result = await run(executable, [...command.split(' '), ...flags, '--config', config, '--result-file', destination, '--json'], { env: { ...env, WRITE_TOKEN: token } });
    assert.equal(result.code, 0, result.stdout + result.stderr);
    return JSON.parse(await readFile(destination, 'utf8')).response;
  };
  const options = zone => read('zone options get', ['--zone', zone]);
  const records = async zone => (await read('zone record get', ['--zone', zone, '--domain', zone, '--list-zone', 'true'])).records;
  const parameters = bytes => Object.fromEntries(new URLSearchParams(bytes.toString()));
  const ok = response => ({ body: { status: 'ok', ...(response ? { response } : {}) } });
  const denied = () => ({ body: { status: 'error', errorMessage: 'Synthetic rejected operation' } });
  vendors.responders.set('/api/zones/options/get', (_incoming, bytes) => {
    const zone = zones.get(parameters(bytes).zone);
    return zone ? ok(Object.fromEntries(Object.entries(zone).filter(([key]) => !['records', 'userPermissions', 'groupPermissions'].includes(key)))) : denied();
  });
  let transfer;
  vendors.responders.set('/api/zones/records/get', (_incoming, bytes) => {
    const p = parameters(bytes);
    assert.equal(p.listZone, 'true');
    if (transfer) transfer();
    const zone = zones.get(p.zone);
    return zone ? ok({ zone: { name: zone.name, type: zone.type }, records: zone.records }) : denied();
  });
  const rejected = async (command, input) => {
    const before = structuredClone([...zones]);
    const preview = await success(command, input);
    await failure('OUTCOME_UNKNOWN', command, input, ['--execute', '--confirm', preview.preview.digest]);
    assert.deepEqual([...zones], before);
  };
  if (id === 'OP-022') {
    vendors.responders.set('/api/zones/create', (incoming, bytes) => {
      const multipart = incoming.headers['content-type'].startsWith('multipart/form-data;');
      const p = multipart ? Object.fromEntries(new URL(incoming.url, 'https://fixture.test').searchParams) : parameters(bytes);
      if (zones.has(p.zone)) return denied();
      zones.set(p.zone, { ...seed(p.zone, p.type), ...p });
      if (multipart) {
        assert.ok(bytes.includes(Buffer.from('uploaded 60 IN A 192.0.2.80\n')));
        zones.get(p.zone).records.push(record(`uploaded.${p.zone}`, 'A', { ipAddress: '192.0.2.80' }, 60));
      }
      return ok({ domain: p.zone });
    });
    for (const type of ['Primary', 'Secondary', 'Stub', 'Forwarder', 'SecondaryForwarder', 'Catalog', 'SecondaryCatalog']) {
      const zone = `${type.toLowerCase()}.test`;
      const p = { zone, type, ...(type.startsWith('Secondary') || type === 'Stub' ? { primaryNameServerAddresses: ['192.0.2.53'] } : {}),
        ...(type.startsWith('Secondary') ? { zoneTransferProtocol: 'Tcp', tsigKeyName: 'key' } : {}),
        ...(type === 'Forwarder' ? { protocol: 'Udp', forwarder: '192.0.2.53', dnssecValidation: true } : {}) };
      await execute('zone create', { parameters: p });
      assert.equal((await options(zone)).type, type);
      assert.equal((await records(zone))[0].rData.serial, 42);
      for (const key of ['primaryNameServerAddresses', 'zoneTransferProtocol', 'tsigKeyName', 'protocol', 'forwarder', 'dnssecValidation']) {
        if (Object.hasOwn(p, key)) assert.equal(zones.get(zone)[key], String(p[key]));
      }
    }
    await rejected('zone create', { parameters: { zone: 'example.test', type: 'Primary' } });
    const file = join(directory, 'create.zone');
    await writeFile(file, 'uploaded 60 IN A 192.0.2.80\n', { mode: 0o600 });
    for (const type of ['Primary', 'Forwarder']) {
      const zone = `uploaded-${type.toLowerCase()}.test`;
      await execute('zone create', { parameters: { zone, type }, upload: { file } });
      assert.deepEqual((await records(zone)).at(-1), record(`uploaded.${zone}`, 'A', { ipAddress: '192.0.2.80' }, 60));
    }
    await failure('USAGE', 'zone create', { parameters: { zone: 'invalid.test', type: 'SecondaryCatalog' } });
  }
  if (id === 'OP-023') {
    const text = '$ORIGIN example.test.\n@ 300 IN SOA ns.example.test. hostmaster.example.test. 42 60 60 3600 60\napi 300 IN A 192.0.2.20\n';
    const file = join(directory, 'import.zone');
    await writeFile(file, text, { mode: 0o600 });
    vendors.responders.set('/api/zones/import', (incoming, bytes) => {
      const contentType = incoming.headers['content-type'];
      const p = contentType === 'application/x-www-form-urlencoded' ? parameters(bytes) : Object.fromEntries(new URL(incoming.url, 'https://fixture.test').searchParams);
      if (contentType === 'application/x-www-form-urlencoded') assert.equal(p.records, text);
      else if (contentType === 'text/plain') assert.deepEqual(bytes, Buffer.from(text));
      else {
        const boundary = contentType.split('boundary=')[1];
        assert.deepEqual(bytes, Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="zone.txt"\r\nContent-Type: text/plain\r\n\r\n${text}\r\n--${boundary}--\r\n`));
      }
      const zone = zones.get(p.zone);
      if (!zone) return denied();
      if (p.overwriteZone === 'true') zone.records = zone.records.filter(row => row.type === 'SOA');
      if (p.overwrite !== 'false') zone.records = zone.records.filter(row => row.type !== 'A');
      zone.records.push(record('api.example.test', 'A', { ipAddress: '192.0.2.20' }));
      if (p.overwriteSoaSerial === 'true') zone.records[0].rData.serial = 42;
      return ok();
    });
    for (const transport of ['form', 'text', 'multipart']) for (const flags of [{}, { overwrite: false }, { overwrite: true }, { overwriteZone: true }, { overwriteSoaSerial: true }]) {
      zones.set('example.test', seed('example.test', 'Primary', 99));
      const p = { zone: 'example.test', ...flags };
      const input = transport === 'form' ? { parameters: { ...p, records: text } } : { parameters: p, upload: { file, format: transport } };
      await execute('zone import', input);
      const actual = await records('example.test');
      assert.deepEqual(actual.filter(row => row.type === 'A'), [
        ...(flags.overwrite === false ? [record('api.example.test', 'A', { ipAddress: '192.0.2.10' })] : []),
        record('api.example.test', 'A', { ipAddress: '192.0.2.20' }),
      ]);
      assert.equal(actual.some(row => row.type === 'TXT'), !flags.overwriteZone);
      assert.equal(actual[0].rData.serial, flags.overwriteSoaSerial ? 42 : 99);
    }
    await rejected('zone import', { parameters: { zone: 'missing.test', records: text } });
    const raw = { parameters: { zone: 'example.test' }, upload: { file, format: 'text' } };
    const rawPreview = await success('zone import', raw);
    await failure('CONFIRMATION_MISMATCH', 'zone import', { ...raw, upload: { file, format: 'multipart' } }, ['--execute', '--confirm', rawPreview.preview.digest]);
    await failure('USAGE', 'zone import', { parameters: { zone: 'example.test' }, upload: { file, format: 'text/plain; charset=utf-8' } });
  }
  if (id === 'OP-025') {
    vendors.responders.set('/api/zones/clone', (_incoming, bytes) => {
      const p = parameters(bytes);
      if (zones.has(p.zone) || !zones.has(p.sourceZone)) return denied();
      const zone = structuredClone(zones.get(p.sourceZone));
      zone.name = p.zone;
      zone.records = zone.records.map(row => ({ ...row, name: row.name.replace(p.sourceZone, p.zone) }));
      zones.set(p.zone, zone);
      return ok();
    });
    const before = await records('source.test');
    const input = { parameters: { sourceZone: 'source.test', zone: 'clone.test' } };
    await execute('zone clone', input);
    assert.deepEqual(await records('clone.test'), before.map(row => ({ ...row, name: row.name.replace('source.test', 'clone.test') })));
    assert.deepEqual(await records('source.test'), before);
    await rejected('zone clone', input);
  }
  if (['OP-026', 'OP-027', 'OP-028'].includes(id)) {
    const action = { 'OP-026': 'convert', 'OP-027': 'enable', 'OP-028': 'disable' }[id];
    const zone = zones.get('example.test');
    zone.type = 'Secondary';
    zone.disabled = action === 'enable';
    const before = await records('example.test');
    vendors.responders.set(`/api/zones/${action}`, (_incoming, bytes) => {
      const p = parameters(bytes);
      const selected = zones.get(p.zone);
      if (!selected || (action === 'convert' && p.type !== 'Primary')) return denied();
      if (action === 'convert') selected.type = p.type;
      else selected.disabled = action === 'disable';
      return ok();
    });
    const input = { parameters: { zone: 'example.test', ...(action === 'convert' ? { type: 'Primary' } : {}) } };
    await execute(`zone ${action}`, input);
    const actual = await options('example.test');
    assert.equal(action === 'convert' ? actual.type : actual.disabled, action === 'convert' ? 'Primary' : action === 'disable');
    assert.deepEqual(await records('example.test'), before);
    if (action === 'enable') await execute('zone enable', input);
    await rejected(`zone ${action}`, { parameters: action === 'convert' ? { zone: 'example.test', type: 'Catalog' } : { zone: 'missing.test' } });
  }
  if (id === 'OP-029') {
    vendors.responders.set('/api/zones/delete', (_incoming, bytes) => {
      const p = parameters(bytes);
      if (p.zone) return zones.delete(p.zone) ? ok() : denied();
      const deleted = [], failed = {};
      for (const zone of p.zones.split(',')) if (zones.delete(zone)) deleted.push(zone); else failed[zone] = 'No such zone';
      return ok({ deleted, failed });
    });
    vendors.responders.set('/api/zones/list', () => ok({ pageNumber: 1, totalPages: 1, totalZones: zones.size, zones: [...zones.values()].map(({ name, type, disabled }) => ({ name, type, disabled })) }));
    await execute('zone delete', { parameters: { zone: 'example.test' } });
    assert.deepEqual((await read('zone list', ['--full'])).zones.map(row => row.name).sort(), ['keep.test', 'source.test']);
    zones.set('example.test', seed('example.test'));
    const batch = { parameters: { zones: ['example.test', 'missing.test'] } };
    const preview = await success('zone delete', batch);
    assert.deepEqual(preview.preview.target, batch.parameters.zones);
    const partial = await success('zone delete', batch, ['--execute', '--confirm', preview.preview.digest]);
    assert.equal(partial.status, 'partial');
    assert.deepEqual(partial.deleted, ['example.test']);
    assert.deepEqual(partial.failed, { 'missing.test': 'No such zone' });
    await rejected('zone delete', { parameters: { zone: 'missing.test' } });
    await failure('USAGE', 'zone delete', { parameters: { zones: [] } });
  }
  if (id === 'OP-030') {
    zones.set('example.test', seed('example.test', 'Secondary', 1));
    let dispatches = 0, waiting = 0, pending = false;
    vendors.responders.set('/api/zones/resync', (_incoming, bytes) => {
      assert.equal(parameters(bytes).zone, 'example.test');
      dispatches++;
      waiting = 2;
      return ok();
    });
    transfer = () => {
      if (!pending && waiting && --waiting === 0) {
        zones.get('example.test').records[0].rData.serial++;
        zones.get('example.test').records[1].rData.ipAddress = '192.0.2.20';
      }
    };
    const input = { parameters: { zone: 'example.test' } };
    await execute('zone resync', input);
    assert.deepEqual(await records('example.test'), [record('example.test', 'SOA', { serial: 2 }), record('api.example.test', 'A', { ipAddress: '192.0.2.20' }), record('keep.example.test', 'TXT', { text: 'stay' })]);
    pending = true;
    const preview = await success('zone resync', input);
    const unknown = await failure('OUTCOME_UNKNOWN', 'zone resync', input, ['--execute', '--confirm', preview.preview.digest]);
    assert.match(unknown.error.message, /audit ID/);
    await failure('REPLAY_DENIED', 'zone resync', input, ['--execute', '--confirm', preview.preview.digest]);
    const auditId = unknown.error.message.match(/audit ID ([a-f0-9-]+)/)[1];
    await failure('OUTCOME_UNKNOWN', 'zone resync', input, ['--confirm', preview.preview.digest, '--reconcile', auditId]);
    zones.get('example.test').records[0].rData.serial = 3;
    const reconciled = await success('zone resync', input, ['--confirm', preview.preview.digest, '--reconcile', auditId]);
    assert.equal(reconciled.status, 'reconciled');
    assert.equal(reconciled.auditId, auditId);
    assert.equal(dispatches, 2);
  }
  if (id === 'OP-032' || id === 'OP-034') {
    const permission = id === 'OP-034';
    const command = permission ? 'zone permission set' : 'zone options set';
    const path = permission ? 'permissions' : 'options';
    const zone = zones.get('example.test');
    const baseline = permission ? { userPermissions: structuredClone(zone.userPermissions), groupPermissions: structuredClone(zone.groupPermissions) }
      : { notifyNameServers: ['192.0.2.1'], disabled: false, updateNetworkACL: ['192.0.2.0/24'], primaryZoneTransferProtocol: 'Tls' };
    const values = permission ? { userPermissions: [{ username: 'reader', canView: true, canModify: true, canDelete: false }], groupPermissions: [{ name: 'Operators', canView: false, canModify: false, canDelete: false }] }
      : { notifyNameServers: ['192.0.2.2'], disabled: false, updateNetworkACL: [], primaryZoneTransferProtocol: 'Tcp' };
    if (permission) vendors.responders.set('/api/zones/permissions/get', () => ok({ section: 'Zones', subItem: zone.name, userPermissions: zone.userPermissions, groupPermissions: zone.groupPermissions }));
    let writes = 0;
    vendors.responders.set(`/api/zones/${path}/set`, (_incoming, bytes) => {
      const p = parameters(bytes);
      assert.deepEqual(Object.keys(p).sort(), ['zone', ...Object.keys(values)].sort());
      for (const [key, value] of Object.entries(values)) {
        const expected = permission ? value.flatMap(row => [row[key === 'userPermissions' ? 'username' : 'name'], row.canView, row.canModify, row.canDelete]).join('|') : Array.isArray(value) ? value.join(',') : String(value);
        assert.equal(p[key], expected);
        zone[key] = structuredClone(value);
      }
      writes++;
      return ok();
    });
    const input = { parameters: { zone: 'example.test', ...values }, baseline };
    const preview = await success(command, input);
    const field = permission ? 'userPermissions' : 'notifyNameServers';
    zone[field].push(permission ? { username: 'other', canView: true, canModify: false, canDelete: false } : '192.0.2.3');
    await failure('CONFLICT', command, input, ['--execute', '--confirm', preview.preview.digest]);
    assert.equal(writes, 0);
    zone[field] = structuredClone(baseline[field]);
    await success(command, input, ['--execute', '--confirm', preview.preview.digest]);
    const actual = permission ? await read('zone permission get', ['--zone', 'example.test']) : await options('example.test');
    for (const [key, value] of Object.entries(values)) assert.deepEqual(actual[key], value);
    assert.deepEqual(zone.queryAccessNetworkACL, ['192.0.2.0/24']);
    assert.deepEqual(zone.zoneTransferTsigKeyNames, ['key']);
    if (permission) {
      vendors.responders.set('/api/zones/permissions/set', (_incoming, bytes) => {
        assert.deepEqual(parameters(bytes), { zone: 'example.test', userPermissions: '' });
        zone.userPermissions = [];
        return ok();
      });
      await execute(command, { parameters: { zone: 'example.test', userPermissions: [] }, baseline: { userPermissions: values.userPermissions } });
      const cleared = await read('zone permission get', ['--zone', 'example.test']);
      assert.deepEqual(cleared.userPermissions, []);
      assert.deepEqual(cleared.groupPermissions, values.groupPermissions);
    }
  }
  assert.deepEqual(zones.get('keep.test'), keep, 'Other zones remain unchanged');
  assert.deepEqual(await records('keep.test'), keep.records);
}
