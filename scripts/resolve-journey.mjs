import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const a = (name, address) => ({ name, type: 'A', ttl: 300, rData: { ipAddress: address } });
const old = a('www.example.test', '192.0.2.10');
const answer = a('www.example.test', '192.0.2.20');
const keep = { name: 'keep.example.test', type: 'TXT', ttl: 60, rData: { text: 'keep' } };
const soa = name => ({ name, type: 'SOA', ttl: 300, rData: { primaryNameServer: 'ns.example.test', responsiblePerson: 'hostmaster.example.test', serial: 43, refresh: 3600, retry: 600, expire: 86400, minimum: 60 } });
const permissions = (name, modify = true) => ({ section: 'Zones', subItem: name,
  userPermissions: [{ username: 'planner', canView: true, canModify: modify, canDelete: true }],
  groupPermissions: ['Administrators', 'DNS Administrators'].map(name => ({ name, canView: true, canModify: true, canDelete: true })) });
const zone = (name, type = 'Primary', records = [old, keep], modify = true) => ({ name, type, records, permissions: permissions(name, modify) });
const decoy = zone('other.test', 'Primary', [a('other.test', '192.0.2.99')]);
const initial = (type = 'Primary', modify = true) => [zone('example.test', type, [old, keep], modify), decoy];

// Contract worlds encode the pinned WebServiceApi.ResolveQueryAsync branches.
// They prove transport, grant separation and observable results, not vendor internals.
export async function resolveJourney({ directory, env, run, executable, vendors, configure, success, failure }) {
  const command = 'dns-client resolve';
  const base = { server: '192.0.2.53', domain: 'www.example.test', type: 'A', import: true };
  const newRecord = a('new.test', '192.0.2.20');
  const childRecord = a('child.example.test', '192.0.2.20');
  const transferred = [soa('example.test'), answer, keep, { name: 'example.test', type: 'NS', ttl: 300, rData: { nameServer: 'ns.example.test' } }];
  const rows = [
    { name: 'existing-allow', before: initial(), after: [zone('example.test', 'Primary', [keep, answer]), decoy], section: false, selected: true },
    { name: 'existing-deny', before: initial('Primary', false), denied: true, section: true, selected: false },
    { name: 'new-allow', before: initial(), parameters: { domain: 'new.test' }, after: [...initial(), zone('new.test', 'Primary', [newRecord])], section: true, selected: false },
    { name: 'new-deny', before: initial(), parameters: { domain: 'new.test' }, denied: true, section: false, selected: false },
    { name: 'axfr-sync', before: [zone('example.test', 'Primary', [...transferred, a('stale.example.test', '192.0.2.1')]), decoy],
      parameters: { domain: 'example.test', type: 'AXFR', protocol: 'Tcp' }, after: [zone('example.test', 'Primary', transferred), decoy], selected: true },
    ...['missing', 'mismatched'].map(closing => ({ name: `axfr-${closing}-soa`, before: initial(), parameters: { domain: 'example.test', type: 'AXFR', protocol: 'Tcp' }, denied: true, selected: true })),
    { name: 'soa-matching', before: initial(), parameters: { domain: 'child.example.test', type: 'SOA' }, section: true,
      after: [...initial(), zone('child.example.test', 'Primary', [soa('child.example.test')])] },
    { name: 'soa-parent', before: initial(), parameters: { domain: 'child.example.test', type: 'SOA' }, selected: true,
      after: [zone('example.test', 'Primary', [old, keep, soa('example.test')]), decoy] },
    { name: 'forwarder-a', before: initial('Forwarder'), after: [zone('example.test', 'Forwarder', [keep, answer]), decoy], selected: true },
    { name: 'forwarder-axfr', before: initial('Forwarder'), parameters: { domain: 'example.test', type: 'AXFR', protocol: 'Tcp' }, denied: true, selected: true },
    ...['Secondary', 'Stub', 'SecondaryForwarder', 'Catalog', 'SecondaryCatalog'].map(type => ({ name: `unsupported-${type}`, before: initial(type), parameters: { domain: 'example.test' }, denied: true, selected: true })),
    { name: 'unsupported-parent-allow', before: initial('Secondary'), parameters: { domain: 'child.example.test' }, section: true,
      after: [...initial('Secondary'), zone('child.example.test', 'Primary', [childRecord])] },
    { name: 'unsupported-parent-deny', before: initial('Secondary'), parameters: { domain: 'child.example.test' }, section: false, denied: true },
    ...['www.example.test', 'new.test'].map(domain => ({ name: `dnssec-warning-${domain}`, before: initial(), parameters: { domain, dnssec: true }, warning: true })),
    { name: 'resolve-only', before: initial(), parameters: { import: false }, read: true },
    { name: 'resolve-omitted-import', before: initial(), read: true, omitImport: true },
  ];
  const observer = join(directory, 'observer.json');
  const observerToken = 'SYNTHETIC-fixture-observer';
  vendors.tokens.set('beta', observerToken);
  await writeFile(observer, JSON.stringify({ version: 1, profiles: { 'fixture-observer': { origin: vendors.origins[1], auth: 'token', tokenKind: 'api',
    token: { env: 'OBSERVER_TOKEN' }, caFile: vendors.caFile, tlsServerName: 'localhost' } } }), { mode: 0o600 });
  let world;
  let sequence = 0;
  const selectedZone = bytes => world.find(zone => zone.name === new URLSearchParams(bytes.toString()).get('zone'));
  const observe = incoming => assert.equal(incoming.headers.authorization, `Bearer ${observerToken}`, 'Readbacks use the observer, never the mutation caller');
  vendors.responders.set('/api/zones/list', (incoming) => {
    observe(incoming);
    return { body: { status: 'ok', response: { pageNumber: 1, totalPages: 1, totalZones: world.length, zones: world.map(({ name, type }) => ({ name, type, disabled: false })) } } };
  });
  vendors.responders.set('/api/zones/records/get', (incoming, bytes) => {
    observe(incoming);
    assert.equal(new URLSearchParams(bytes.toString()).get('listZone'), 'true');
    const zone = selectedZone(bytes);
    return { body: { status: 'ok', response: { zone: { name: zone.name, type: zone.type }, records: zone.records } } };
  });
  vendors.responders.set('/api/zones/permissions/get', (incoming, bytes) => {
    observe(incoming);
    assert.equal(new URLSearchParams(bytes.toString()).get('includeUsersAndGroups'), 'true');
    return { body: { status: 'ok', response: selectedZone(bytes).permissions } };
  });
  const read = async (command, flags = []) => {
    const resultFile = join(directory, `resolve-observed-${sequence++}.json`);
    const result = await run(executable, [...command.split(' '), ...flags, '--config', observer, '--result-file', resultFile, '--json'], { env: { ...env, OBSERVER_TOKEN: observerToken } });
    assert.equal(result.code, 0, result.stdout + result.stderr);
    return JSON.parse(await readFile(resultFile, 'utf8')).response;
  };
  const verify = async expected => {
    const inventory = await read('zone list', ['--full']);
    assert.deepEqual(inventory.zones, expected.map(({ name, type }) => ({ name, type, disabled: false })));
    for (const zone of expected) {
      assert.deepEqual((await read('zone record get', ['--zone', zone.name, '--domain', zone.name, '--list-zone', 'true'])).records, zone.records);
      assert.deepEqual(await read('zone permission get', ['--zone', zone.name, '--include-users-and-groups', 'true']), zone.permissions);
    }
  };
  for (const row of rows) {
    world = structuredClone(row.before);
    await configure(row.read ? [] : ['OP-077.import']);
    const parameters = { ...base, ...row.parameters };
    if (row.omitImport) delete parameters.import;
    const input = { parameters };
    const expected = row.after ?? row.before;
    const records = parameters.type === 'AXFR' ? transferred : parameters.type === 'SOA' ? [soa(row.name === 'soa-parent' ? 'example.test' : parameters.domain)] : [a(parameters.domain, '192.0.2.20')];
    const reply = { Identifier: 1, IsResponse: true, OPCODE: 'StandardQuery', RCODE: 'NoError', QDCOUNT: 1, ANCOUNT: records.length,
      Question: [{ Name: parameters.domain, Type: parameters.type, Class: 'IN' }],
      Answer: records.map(record => ({ Name: record.name, Type: record.type, Class: 'IN', TTL: `${record.ttl} (5 mins)`,
        RDATA: record.type === 'A' ? { IPAddress: record.rData.ipAddress } : record.type === 'TXT' ? { Text: record.rData.text }
          : record.type === 'NS' ? { NameServer: record.rData.nameServer } : { PrimaryNameServer: record.rData.primaryNameServer, ResponsiblePerson: record.rData.responsiblePerson,
            Serial: 43, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 60 } })), Authority: [], Additional: [] };
    let calls = 0;
    vendors.responders.set('/api/dnsClient/resolve', (incoming, bytes) => {
      assert.notEqual(incoming.headers.authorization, `Bearer ${observerToken}`);
      assert.equal(incoming.headers['content-type'], 'application/x-www-form-urlencoded');
      assert.deepEqual(Object.fromEntries(new URLSearchParams(bytes.toString())), Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, String(value)])), row.name);
      calls++;
      if (row.denied) return { body: { status: 'error', errorMessage: 'Import denied by selected vendor permission or target type' } };
      world = structuredClone(expected);
      return { body: { status: 'ok', response: { result: reply, rawResponses: [], ...(row.warning ? { warningMessage: 'DNSSEC validation failed' } : {}) } } };
    });
    await verify(row.before);
    const before = vendors.traces.length;
    const preview = await success(command, input);
    assert.equal(preview.preview.operation, row.read ? 'OP-077.resolve' : 'OP-077.import');
    assert.equal(vendors.traces.length, before);
    if (row.denied) await failure('OUTCOME_UNKNOWN', command, input, ['--execute', '--confirm', preview.preview.digest]);
    else {
      const result = await success(command, input, ['--execute', '--confirm', preview.preview.digest]);
      assert.deepEqual(result.response, reply);
      if (row.warning) {
        assert.equal(result.warningMessage, 'DNSSEC validation failed');
        assert.equal(result.mutation, 'suppressed');
      }
    }
    assert.equal(calls, 1, row.name);
    await verify(expected);
  }
  const input = { parameters: base };
  await configure(['OP-077.import']);
  const preview = await success(command, input);
  const before = vendors.traces.length;
  await failure('WRITE_DENIED', command, input, ['--execute', '--confirm', preview.preview.digest], { TECHNITIUM_AXI_READ_ONLY: 'true' });
  await failure('USAGE', command, { parameters: { ...base, dnssecValidation: true } });
  assert.equal(vendors.traces.length, before);
}
