import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

export const dnssecTasks = [35, 36, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 140].map(id => `B3.OP-${String(id).padStart(3, '0')}`);

// Synthetic vendor worlds prove CLI transport and readback, not cryptographic correctness.
const key = (keyTag, keyType, state = 'Active', rolloverDays = 0) => ({ keyTag, keyType, state, rolloverDays,
  algorithm: 'ECDSAP256SHA256', isRetiring: false, stateChangedOn: '2026-01-01T00:00:00Z', stateReadyBy: '2026-01-01T00:00:00Z' });
const ksk = key(15048, 'KeySigningKey');
const zsk = key(25049, 'ZoneSigningKey', 'Active', 30);
const a = { name: 'www.example.test', type: 'A', ttl: 300, rData: { ipAddress: '192.0.2.10' } };
const record = (type, rData, ttl = 3600) => ({ name: 'example.test', type, ttl, rData });
const dnskey = k => record('DNSKEY', { keyTag: k.keyTag, publicKey: `synthetic-public-${k.keyTag}` });
const proof = (nsec3 = false, iterations = 0, saltLength = 0) => nsec3
  ? [record('NSEC3', { hash: 'synthetic-proof' }), record('NSEC3PARAM', { iterations, salt: 'ab'.repeat(saltLength) })]
  : [record('NSEC', { nextDomainName: 'www.example.test' })];
function world({ signed = true, nsec3 = false, iterations = 0, saltLength = 0, keys = [ksk, zsk], ttl = 3600 } = {}) {
  return {
    properties: { name: 'example.test', type: 'Primary', internal: false, disabled: false,
      dnssecStatus: signed ? `SignedWith${nsec3 ? 'NSEC3' : 'NSEC'}` : 'Unsigned',
      dnsKeyTtl: ttl, dnssecPrivateKeys: signed ? keys : [] },
    records: [a, ...(signed ? [...keys.filter(k => k.state !== 'Generated').map(k => ({ ...dnskey(k), ttl })),
      record('RRSIG', { typeCovered: 'A', keyTag: 25049 }), ...proof(nsec3, iterations, saltLength)] : [])],
  };
}

export async function dnssecJourney({ task, directory, env, run, executable, vendors, config, token, secret,
  configure, success, failure }) {
  const id = task.slice(3);
  const properties = 'zone dnssec properties ';
  const rows = {
    'OP-035': ['zone dnssec sign', '/api/zones/dnssec/sign', { algorithm: 'ECDSA', curve: 'P256' }, world({ signed: false }), world()],
    'OP-036': ['zone dnssec unsign', '/api/zones/dnssec/unsign', {}, world(), world({ signed: false })],
    'OP-039': [properties + 'convert-to-nsec', '/api/zones/dnssec/properties/convertToNSEC', {}, world({ nsec3: true, iterations: 2, saltLength: 8 }), world()],
    'OP-040': [properties + 'convert-to-nsec3', '/api/zones/dnssec/properties/convertToNSEC3', { iterations: 2, saltLength: 8 }, world(), world({ nsec3: true, iterations: 2, saltLength: 8 })],
    'OP-041': [properties + 'update-nsec3-params', '/api/zones/dnssec/properties/updateNSEC3Params', { iterations: 2, saltLength: 8 }, world({ nsec3: true, iterations: 1, saltLength: 4 }), world({ nsec3: true, iterations: 2, saltLength: 8 })],
    'OP-042': [properties + 'update-dns-key-ttl', '/api/zones/dnssec/properties/updateDnsKeyTtl', { ttl: 1800 }, world(), world({ ttl: 1800 })],
    'OP-043': [properties + 'add-private-key', '/api/zones/dnssec/properties/addPrivateKey', { keyType: 'ZoneSigningKey', algorithm: 'ECDSA', curve: 'P256', rolloverDays: 60 }, world({ keys: [ksk] }), world({ keys: [ksk, key(25049, 'ZoneSigningKey', 'Generated', 60)] })],
    'OP-044': [properties + 'update-private-key', '/api/zones/dnssec/properties/updatePrivateKey', { keyTag: 25049, rolloverDays: 60 }, world(), world({ keys: [ksk, { ...zsk, rolloverDays: 60 }] })],
    'OP-045': [properties + 'delete-private-key', '/api/zones/dnssec/properties/deletePrivateKey', { keyTag: 25049 }, world({ keys: [ksk, { ...zsk, state: 'Generated' }] }), world({ keys: [ksk] })],
    'OP-046': [properties + 'publish-all-private-keys', '/api/zones/dnssec/properties/publishAllPrivateKeys', {}, world({ keys: [{ ...ksk, state: 'Generated' }, { ...zsk, state: 'Generated' }] }), world({ keys: [{ ...ksk, state: 'Published' }, { ...zsk, state: 'Published' }] })],
    'OP-047': [properties + 'rollover-dns-key', '/api/zones/dnssec/properties/rolloverDnsKey', { keyTag: 25049 }, world(), world({ keys: [ksk, { ...zsk, isRetiring: true }, key(25050, 'ZoneSigningKey', 'Published', 30)] })],
    'OP-048': [properties + 'retire-dns-key', '/api/zones/dnssec/properties/retireDnsKey', { keyTag: 25049 }, world({ keys: [ksk, zsk, key(25050, 'ZoneSigningKey')] }), world({ keys: [ksk, { ...zsk, isRetiring: true }, key(25050, 'ZoneSigningKey')] })],
    'OP-140': [properties + 'activate-ksk-dns-key', '/api/zones/dnssec/properties/activateKskDnsKey', { keyTag: 15048 }, world({ keys: [key(15047, 'KeySigningKey'), { ...ksk, state: 'Ready' }, zsk] }), world({ keys: [key(15047, 'KeySigningKey'), ksk, zsk] })],
  };
  const [command, path, parameters, initial, final] = rows[id];
  const cases = [{ parameters, initial, final }];
  if (id === 'OP-035') {
    cases.push({ parameters: { algorithm: 'RSA', hashAlgorithm: 'SHA256', kskKeySize: 2048, zskKeySize: 1024, nxProof: 'NSEC3', iterations: 2, saltLength: 8 },
      initial, final: world({ nsec3: true, iterations: 2, saltLength: 8, keys: [ksk, zsk].map(k => ({ ...k, algorithm: 'RSASHA256' })) }) });
    cases.push({ parameters: { algorithm: 'ECDSA', curve: 'P256', pemKskPrivateKey: { env: 'OPERATION_SECRET' }, pemZskPrivateKey: { env: 'OPERATION_SECRET' } }, initial, final });
  }
  if (id === 'OP-043') {
    cases.push({ parameters: { keyType: 'KeySigningKey', algorithm: 'RSA', hashAlgorithm: 'SHA256', keySize: 2048, rolloverDays: 0 }, initial,
      final: world({ keys: [ksk, { ...key(15049, 'KeySigningKey', 'Generated'), algorithm: 'RSASHA256' }] }) });
    cases.push({ parameters: { ...parameters, pemPrivateKey: { env: 'OPERATION_SECRET' } }, initial, final });
  }
  if (id === 'OP-035' || id === 'OP-043') {
    const generated = id === 'OP-035' ? { algorithm: 'EDDSA', curve: 'ED25519' }
      : { keyType: 'ZoneSigningKey', algorithm: 'EDDSA', curve: 'ED25519', rolloverDays: 60 };
    const eddsa = world({ keys: (id === 'OP-035' ? [ksk, zsk] : [ksk, key(25049, 'ZoneSigningKey', 'Generated', 60)])
      .map(k => id === 'OP-035' || k.keyTag === 25049 ? { ...k, algorithm: 'ED25519' } : k) });
    const refs = id === 'OP-035' ? { pemKskPrivateKey: { env: 'OPERATION_SECRET' }, pemZskPrivateKey: { env: 'OPERATION_SECRET' } }
      : { pemPrivateKey: { env: 'OPERATION_SECRET' } };
    cases.push({ parameters: generated, initial, final: eddsa }, { parameters: { ...generated, ...refs }, initial, final: eddsa });
    cases.push({ parameters: { ...cases[1].parameters, ...refs }, initial, final: cases[1].final });
  }
  if (id === 'OP-040') for (const params of [{}, { iterations: 0, saltLength: 0 }, { iterations: 50, saltLength: 32 }]) {
    cases.push({ parameters: params, initial, final: world({ nsec3: true, ...params }) });
  }
  if (id === 'OP-042') cases.push({ parameters: { ttl: 0 }, initial, final: world({ ttl: 0 }) });
  if (id === 'OP-044') cases.push({ parameters: { keyTag: 25049, rolloverDays: 0 }, initial, final: world({ keys: [ksk, { ...zsk, rolloverDays: 0 }] }) });

  let current;
  let count = 0;
  const keep = world();
  const select = bytes => new URLSearchParams(bytes.toString()).get('zone') === 'keep.test' ? keep : current;
  vendors.responders.set('/api/zones/dnssec/properties/get', (_incoming, bytes) => ({ body: { status: 'ok', response: select(bytes).properties } }));
  vendors.responders.set('/api/zones/records/get', (_incoming, bytes) => ({ body: { status: 'ok', response: { zone: { name: 'example.test', type: 'Primary' }, records: select(bytes).records } } }));
  vendors.responders.set('/api/zones/dnssec/viewDS', () => ({ body: { status: 'ok', response: { ...current.properties,
    dsRecords: [{ keyTag: 15048, dnsKeyState: 'Active', dnsKeyStateReadyBy: '2026-01-01T00:00:00Z', algorithm: 'ECDSAP256SHA256', publicKey: 'synthetic-public-15048', digests: [{ digestType: 'SHA256', digest: 'ABCDEF' }] }] } } }));
  let reads = 0;
  const read = async (command, flags) => {
    const result = join(directory, `dnssec-result-${reads++}.json`);
    const response = await run(executable, [...command.split(' '), ...flags, '--config', config, '--result-file', result, '--json'], { env: { ...env, WRITE_TOKEN: token } });
    assert.equal(response.code, 0, response.stdout + response.stderr);
    return JSON.parse(await readFile(result, 'utf8')).response;
  };
  const verify = async expected => {
    assert.deepEqual(await read(properties + 'get', ['--zone', 'example.test']), expected.properties);
    assert.deepEqual((await read('zone record get', ['--zone', 'example.test', '--domain', 'example.test', '--list-zone', 'true'])).records, expected.records);
    assert.deepEqual(await read(properties + 'get', ['--zone', 'keep.test']), keep.properties);
    assert.deepEqual((await read('zone record get', ['--zone', 'keep.test', '--domain', 'keep.test', '--list-zone', 'true'])).records, keep.records);
  };

  await configure([id]);
  for (const [index, row] of cases.entries()) {
    current = structuredClone(row.initial);
    const input = { parameters: { zone: 'example.test', ...(id === 'OP-140' ? {} : { node: 'node.example.test' }), ...row.parameters } };
    vendors.responders.set(path, (incoming, bytes) => {
      assert.equal(incoming.method, 'POST');
      assert.deepEqual(Object.fromEntries(new URLSearchParams(bytes.toString())), Object.fromEntries(Object.entries(input.parameters).map(([key, value]) => [key, value?.env ? secret : String(value)])));
      count++;
      current = structuredClone(row.final);
      return { body: { status: 'ok', response: { pemPrivateKey: secret } } };
    });
    const before = vendors.traces.length;
    const preview = await success(command, input);
    assert.equal(vendors.traces.length, before, 'DNSSEC preview must not dispatch');
    await failure('CONFIRMATION_MISMATCH', command, { parameters: { ...input.parameters, zone: 'keep.test' } }, ['--execute', '--confirm', preview.preview.digest]);
    await success(command, input, ['--execute', '--confirm', preview.preview.digest]);
    assert.equal(count, index + 1);
    await verify(row.final);
    await failure('REPLAY_DENIED', command, input, ['--execute', '--confirm', preview.preview.digest]);
  }
  if (id === 'OP-047' || id === 'OP-048') {
    // Advance the fixture lifecycle without elapsed-time sleeps or extra mutations.
    current = world({ keys: [ksk, key(25050, 'ZoneSigningKey', 'Active', 30)] });
    await verify(current);
  }
  if (id === 'OP-140') {
    const ds = await read('zone dnssec view-ds', ['--zone', 'example.test']);
    assert.deepEqual(ds.dsRecords[0].digests, [{ digestType: 'SHA256', digest: 'ABCDEF' }]);
    assert.equal(ds.dsRecords[0].keyTag, 15048);
  }

  // A vendor prerequisite rejection leaves the selected and unrelated worlds intact.
  await configure([id], { username: 'prerequisite-check' });
  current = id === 'OP-045' ? world() : id === 'OP-048' ? world({ keys: [ksk, zsk] })
    : id === 'OP-140' ? world({ keys: [key(15047, 'KeySigningKey'), { ...ksk, state: 'Published' }, zsk] }) : initial;
  const unchanged = structuredClone(current);
  vendors.responders.set(path, () => ({ body: { status: 'error', errorMessage: 'DNSSEC key or zone is not ready' } }));
  const rejected = { parameters: { zone: 'example.test', ...parameters } };
  const preview = await success(command, rejected);
  await failure('OUTCOME_UNKNOWN', command, rejected, ['--execute', '--confirm', preview.preview.digest]);
  await verify(unchanged);
  await failure('REPLAY_DENIED', command, rejected, ['--execute', '--confirm', preview.preview.digest]);

  const invalid = [{ ...parameters, unexpected: true }];
  if (['OP-035', 'OP-040', 'OP-041'].includes(id)) for (const [field, values] of Object.entries({ iterations: [-1, 51, 65536, 1.5], saltLength: [-1, 33, 256, 1.5] })) {
    for (const value of values) invalid.push({ ...parameters, [field]: value });
  }
  if (Object.hasOwn(parameters, 'keyTag')) invalid.push({ ...parameters, keyTag: 65536 });
  if (Object.hasOwn(parameters, 'rolloverDays')) invalid.push({ ...parameters, rolloverDays: 366 });
  if (id === 'OP-042') invalid.push({ ttl: 4294967296 });
  const before = vendors.traces.length;
  for (const parameters of invalid) await failure('USAGE', command, { parameters: { zone: 'example.test', ...parameters } });
  assert.equal(vendors.traces.length, before, 'Invalid DNSSEC input must fail before vendor dispatch');
  await verify(unchanged);
  for (const file of await readdir(join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d'))) {
    const journal = await readFile(join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d', file), 'utf8');
    assert.ok(!journal.includes(secret));
    assert.ok(!journal.includes(token));
  }
}
