import assert from 'node:assert/strict';
import { chmod, mkdir, readFile, readdir, symlink, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import matrix from '../tests/fixtures/record-inputs.json' with { type: 'json' };

export const writeTasks = ['B3.01', 'B3.02', 'B3.03', 'B3.04', 'B3.05', 'B3.CR-013', 'B3.CR-014'];
const hash = value => createHash('sha256').update(value).digest('hex');

export async function writeJourney({ task, temporary, env, run, executable, vendors }) {
  const directory = join(temporary, 'writes');
  await mkdir(directory, { mode: 0o700 });
  const config = join(directory, 'config.json');
  const token = 'SYNTHETIC-write-token-alpha';
  const secret = 'SYNTHETIC-operation-"/+=secret';
  vendors.tokens.set('alpha', token);
  const profile = { origin: vendors.origins[0], auth: 'token', tokenKind: 'api', username: 'planner', token: { env: 'WRITE_TOKEN' }, caFile: vendors.caFile, tlsServerName: 'localhost' };
  let sequence = 0;
  const configure = async (operations = [], extra = {}) => writeFile(config, JSON.stringify({ version: 1,
    profiles: { alpha: { ...profile, writes: { allowWrites: operations.length > 0, operations }, ...extra } } }), { mode: 0o600 });
  await configure();
  const invoke = async (command, input, flags = [], extraEnv = {}) => {
    const file = join(directory, `input-${sequence++}.json`);
    await writeFile(file, JSON.stringify(input), { mode: 0o600 });
    const result = await run(executable, [...command.split(' '), '--input-file', file, '--config', config, '--json', ...flags],
      { env: { ...env, WRITE_TOKEN: token, OPERATION_SECRET: secret, ...extraEnv } });
    assert.equal(result.stderr, '', result.stderr);
    for (const canary of [token, secret]) for (const form of [canary, encodeURIComponent(canary), JSON.stringify(canary).slice(1, -1), Buffer.from(canary).toString('base64')]) assert.ok(!result.stdout.includes(form), result.stdout);
    return { ...result, value: JSON.parse(result.stdout) };
  };
  const success = async (...args) => {
    const result = await invoke(...args);
    assert.equal(result.code, 0, result.stdout);
    return result.value;
  };
  const failure = async (code, ...args) => {
    const result = await invoke(...args);
    assert.notEqual(result.code, 0, result.stdout);
    assert.equal(result.value.error.code, code, result.stdout);
    return result.value;
  };
  const execute = async (command, input, extraEnv = {}) => {
    const preview = await success(command, input, [], extraEnv);
    return await success(command, input, ['--execute', '--confirm', preview.preview.digest], extraEnv);
  };
  const add = { parameters: { zone: 'example.test', domain: 'www.example.test', type: 'A', ipAddress: '192.0.2.1', ttl: 0 } };
  const sent = [];
  let fault;
  vendors.responders.set('/api/zones/records/add', async (incoming, bytes) => {
    const data = Object.fromEntries(new URLSearchParams(bytes.toString()));
    sent.push(data);
    if (fault === 'drop') { incoming.socket.destroy(); return {}; }
    if (fault === 'handler') return { body: { status: 'error', errorMessage: secret } };
    return { body: { status: 'ok', response: { record: data, proxyPassword: secret } } };
  });
  if (task === 'B3.01' || task === 'B3.CR-013') {
    const before = vendors.traces.length;
    const preview = await success('zone record add', add);
    assert.equal(preview.preview.permitted, false);
    assert.equal(vendors.traces.length, before, 'Preview must not dispatch');
    await failure('WRITE_DENIED', 'zone record add', add, ['--execute', '--confirm', preview.preview.digest]);
    await configure(['OP-049']);
    const allowed = await success('zone record add', add);
    for (const input of [
      { parameters: { ...add.parameters, domain: 'other.example.test' } },
      { parameters: { ...add.parameters, zone: 'other.test' } },
      { parameters: { ...add.parameters, node: 'secondary.example.test' } },
      { parameters: { ...add.parameters, ttl: 1 } },
    ]) await failure('CONFIRMATION_MISMATCH', 'zone record add', input, ['--execute', '--confirm', allowed.preview.digest]);
    await configure(['OP-049'], { username: 'other' });
    await failure('CONFIRMATION_MISMATCH', 'zone record add', add, ['--execute', '--confirm', allowed.preview.digest]);
    await configure(['OP-049'], { origin: vendors.origins[1] });
    await failure('CONFIRMATION_MISMATCH', 'zone record add', add, ['--execute', '--confirm', allowed.preview.digest]);
    await configure(['OP-049']);
    await failure('WRITE_DENIED', 'zone record add', add, ['--execute', '--confirm', allowed.preview.digest], { TECHNITIUM_AXI_READ_ONLY: 'true' });
    await failure('WRITE_DENIED', 'zone record update', { parameters: { ...add.parameters, newIpAddress: '192.0.2.2' } }, ['--execute', '--confirm', allowed.preview.digest]);
    for (const operation of ['*', 'OP-999', 'OP-077.resolve']) {
      await configure([operation]);
      await failure('CONFIG_INVALID', 'zone record add', add);
    }
    await configure(['OP-049']);
    assert.equal(sent.length, 0);
    const blockedJournal = join(directory, 'journal-parent');
    await writeFile(blockedJournal, 'regular file', { mode: 0o600 });
    await failure('JOURNAL_FAILED', 'zone record add', add, ['--execute', '--confirm', allowed.preview.digest], { TECHNITIUM_AXI_WRITE_LOG: join(blockedJournal, 'writes.log') });
    assert.equal(sent.length, 0, 'No dispatch on durable journal failure');
    const result = await success('zone record add', add, ['--execute', '--confirm', allowed.preview.digest]);
    assert.equal(result.operation, 'OP-049');
    const receipt = JSON.parse(await readFile(join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d', `${allowed.preview.digest}.json`), 'utf8'));
    assert.equal(receipt.state, 'completed');
    assert.equal(receipt.auditId, result.auditId);
    await failure('REPLAY_DENIED', 'zone record add', add, ['--execute', '--confirm', allowed.preview.digest]);
    assert.equal(sent.length, 1);
    vendors.responders.set('/api/dnsClient/resolve', () => ({ body: { status: 'ok', response: { answer: [] } } }));
    await configure();
    const resolve = { parameters: { server: '192.0.2.53', domain: 'example.test', type: 'A' } };
    await execute('dns-client resolve', resolve);
    const importInput = { parameters: { ...resolve.parameters, import: true } };
    const importPreview = await success('dns-client resolve', importInput);
    await failure('WRITE_DENIED', 'dns-client resolve', importInput, ['--execute', '--confirm', importPreview.preview.digest]);
    const ldap = await success('admin ldap test', { parameters: {} });
    await failure('WRITE_DENIED', 'admin ldap test', { parameters: {} }, ['--execute', '--confirm', ldap.preview.digest]);
  }
  if (task === 'B3.CR-014') {
    await configure(['OP-049'], { tokenKind: 'single-use' });
    await failure('USAGE', 'zone record add', { parameters: { ...add.parameters, unsupported: true } });
    assert.equal(sent.length, 0);
    for (const mode of ['drop', 'handler', 'ok']) {
      fault = mode;
      const input = { parameters: { ...add.parameters, comments: mode } };
      const preview = await success('zone record add', input);
      assert.equal(sent.length, mode === 'drop' ? 0 : mode === 'handler' ? 1 : 2);
      if (mode === 'ok') {
        const output = await success('zone record add', input, ['--execute', '--confirm', preview.preview.digest]);
        assert.equal(output.credential, 'consumed');
      } else {
        const output = await failure('OUTCOME_UNKNOWN', 'zone record add', input, ['--execute', '--confirm', preview.preview.digest]);
        assert.match(output.error.message, /consumed-or-uncertain/);
      }
      await failure('REPLAY_DENIED', 'zone record add', input, ['--execute', '--confirm', preview.preview.digest]);
    }
    assert.equal(sent.length, 3, 'Each dispatched credential is used exactly once without retry');
  }
  if (task === 'B3.03') {
    const replacements = [
      { command: 'zone options set', grant: 'OP-032', target: { zone: 'example.test' }, field: 'notifyNameServers', get: '/api/zones/options/get', set: '/api/zones/options/set' },
      { command: 'settings set', grant: 'OP-080', target: {}, field: 'blockListUrls', get: '/api/settings/get', set: '/api/settings/set' },
      { command: 'admin group set', grant: 'OP-109', target: { group: 'Operators' }, field: 'members', get: '/api/admin/groups/get', set: '/api/admin/groups/set' },
    ];
    for (const row of replacements) {
      await configure([row.grant]);
      let state = ['a'];
      let setters = 0;
      let drop = false;
      vendors.responders.set(row.get, () => ({ body: { status: 'ok', response: { [row.field]: state, untouched: 'keep' } } }));
      vendors.responders.set(row.set, (incoming, bytes) => {
        setters++;
        const form = new URLSearchParams(bytes.toString());
        assert.deepEqual([...form.keys()].sort(), [...Object.keys(row.target), row.field].sort());
        state = form.get(row.field).split(',');
        if (drop) { incoming.socket.destroy(); return {}; }
        return { body: { status: 'ok' } };
      });
      const input = { parameters: { ...row.target, [row.field]: ['a', 'c'] }, baseline: { [row.field]: ['a'] } };
      const preview = await success(row.command, input);
      assert.match(preview.preview.concurrency, /single-writer/);
      state = ['a', 'b'];
      await failure('CONFLICT', row.command, input, ['--execute', '--confirm', preview.preview.digest]);
      assert.equal(setters, 0);
      assert.deepEqual(state, ['a', 'b']);
      state = ['a'];
      await success(row.command, input, ['--execute', '--confirm', preview.preview.digest]);
      assert.deepEqual(state, ['a', 'c']);
      const lost = { parameters: { ...row.target, [row.field]: ['a', 'c', 'd'] }, baseline: { [row.field]: ['a', 'c'] } };
      const lostPreview = await success(row.command, lost);
      drop = true;
      const unknown = await failure('OUTCOME_UNKNOWN', row.command, lost, ['--execute', '--confirm', lostPreview.preview.digest]);
      const auditId = unknown.error.message.match(/audit ID ([a-f0-9-]+)/)[1];
      const reconciled = await success(row.command, lost, ['--confirm', lostPreview.preview.digest, '--reconcile', auditId]);
      assert.equal(reconciled.auditId, auditId);
      assert.equal(reconciled.status, 'reconciled');
      assert.equal(setters, 2, 'Reconciliation never replays a setter');
      state = ['partial'];
      await failure('OUTCOME_UNKNOWN', row.command, lost, ['--confirm', lostPreview.preview.digest, '--reconcile', auditId]);
    }
  }
  if (task === 'B3.04') {
    const upload = join(directory, 'zone.txt');
    const bytes = Buffer.from('$ORIGIN example.test.\nwww 60 IN TXT "héllo"\n');
    await writeFile(upload, bytes, { mode: 0o600 });
    const requests = [];
    for (const [command, grant, path, parameters] of [
      ['zone create', 'OP-022', '/api/zones/create', { zone: 'example.test', type: 'Primary' }],
      ['zone import', 'OP-023', '/api/zones/import', { zone: 'example.test', overwrite: false }],
    ]) {
      await configure([grant]);
      vendors.responders.set(path, (incoming, body) => {
        const query = new URL(incoming.url, 'https://fixture.test').searchParams;
        assert.deepEqual(Object.fromEntries(query), Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, String(value)])));
        const boundary = incoming.headers['content-type'].split('boundary=')[1];
        const prefix = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="zone.txt"\r\nContent-Type: text/plain\r\n\r\n`);
        const suffix = Buffer.from(`\r\n--${boundary}--\r\n`);
        assert.deepEqual(body.subarray(0, prefix.length), prefix);
        assert.deepEqual(body.subarray(prefix.length, -suffix.length), bytes);
        assert.deepEqual(body.subarray(-suffix.length), suffix);
        requests.push(query.get('zone'));
        return { body: { status: 'ok' } };
      });
      const input = { parameters, upload: { file: upload } };
      const preview = await success(command, input);
      assert.equal(preview.preview.upload.sha256, hash(bytes));
      await writeFile(upload, 'changed');
      await failure('CONFIRMATION_MISMATCH', command, input, ['--execute', '--confirm', preview.preview.digest]);
      await writeFile(upload, bytes);
      await success(command, input, ['--execute', '--confirm', preview.preview.digest]);
      const link = join(directory, `upload-${grant}.link`);
      await symlink(upload, link);
      await failure('CONFIG_INSECURE', command, { parameters, upload: { file: link } });
    }
    assert.deepEqual(requests, ['example.test', 'example.test']);
    await writeFile(upload, Buffer.alloc(16 * 1024 * 1024 + 1));
    await failure('INPUT_LIMIT', 'zone import', { parameters: { zone: 'example.test' }, upload: { file: upload } });
  }
  if (task === 'B3.05') {
    await configure(['OP-035', 'OP-049']);
    const pem = join(directory, 'private-key.pem');
    const pemBytes = '-----BEGIN PRIVATE KEY-----\nSYNTHETIC-not-a-real-key\n-----END PRIVATE KEY-----\n';
    await writeFile(pem, pemBytes, { mode: 0o600 });
    let signCount = 0;
    vendors.responders.set('/api/zones/dnssec/sign', (_incoming, bytes) => {
      const form = new URLSearchParams(bytes.toString());
      assert.equal(form.get('pemKskPrivateKey'), pemBytes);
      assert.equal(form.get('pemZskPrivateKey'), pemBytes);
      signCount++;
      return { body: { status: 'ok' } };
    });
    const sign = { parameters: { zone: 'example.test', algorithm: 'RSA', pemKskPrivateKey: { file: pem }, pemZskPrivateKey: { file: pem } } };
    const preview = await success('zone dnssec sign', sign);
    await writeFile(pem, `${pemBytes}changed`);
    await failure('CONFIRMATION_MISMATCH', 'zone dnssec sign', sign, ['--execute', '--confirm', preview.preview.digest]);
    await writeFile(pem, pemBytes);
    await success('zone dnssec sign', sign, ['--execute', '--confirm', preview.preview.digest]);
    assert.equal(signCount, 1);
    const fwd = { parameters: { zone: 'example.test', domain: 'www.example.test', type: 'FWD', protocol: 'Udp', forwarder: '192.0.2.53', proxyPassword: { env: 'OPERATION_SECRET' } } };
    const result = join(directory, 'fwd-result.json');
    const fwdPreview = await success('zone record add', fwd);
    await failure('CONFIRMATION_MISMATCH', 'zone record add', fwd, ['--execute', '--confirm', fwdPreview.preview.digest], { OPERATION_SECRET: 'different-revision' });
    await success('zone record add', fwd, ['--execute', '--confirm', fwdPreview.preview.digest, '--result-file', result]);
    assert.equal(sent[0].proxyPassword, secret);
    assert.equal(JSON.parse(await readFile(result, 'utf8')).response.proxyPassword, secret);
    await failure('USAGE', 'zone record add', { parameters: { ...fwd.parameters, proxyPassword: secret } });
    await chmod(pem, 0o644);
    await failure('CONFIG_INSECURE', 'zone dnssec sign', sign);
    const journal = join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d');
    for (const file of await readdir(journal)) {
      const contents = await readFile(join(journal, file), 'utf8');
      for (const canary of [token, secret, pemBytes, encodeURIComponent(secret), Buffer.from(secret).toString('base64')]) assert.ok(!contents.includes(canary));
    }
  }
  if (task === 'B3.02') {
    await configure(['OP-049', 'OP-051', 'OP-052']);
    for (const row of matrix.rows) {
      let records = [];
      let related = [];
      const owner = row.updateOnly ? 'example.test' : 'www.example.test';
      const keep = { name: 'keep.example.test', type: 'TXT', ttl: 60, rData: { text: 'keep' } };
      const firstKey = Object.keys(row.data)[0];
      const siblingData = { ...row.data, [firstKey]: row.sibling ?? (typeof row.data[firstKey] === 'number' ? row.data[firstKey] + 1 : `sibling.${row.data[firstKey]}`) };
      const comparison = { name: row.updateOnly ? 'keep.test' : row.singleton ? 'other.example.test' : owner, type: row.type, ttl: 60, rData: siblingData };
      records = [keep, comparison];
      const params = { zone: 'example.test', domain: owner, type: row.type, ttl: 60, ...row.data, ...row.addOptions };
      const dataKeys = Object.keys(row.data);
      const select = p => records.findIndex(record => record.name === p.domain && record.type === p.type &&
        (row.singleton || dataKeys.every(key => String(record.rData[key]) === p[key])));
      vendors.responders.set('/api/zones/records/add', (_incoming, bytes) => {
        const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
        const expected = row.singleton && p.overwrite === 'true' ? { ...params, ...row.updated } : params;
        for (const [key, value] of Object.entries(expected)) assert.equal(p[key], String(value?.env ? secret : Array.isArray(value) ? value.join(',') : value), `${row.type} add ${key}`);
        if (row.singleton && select(p) >= 0 && p.overwrite !== 'true') return { body: { status: 'error' } };
        if (row.singleton && select(p) >= 0) records.splice(select(p), 1);
        records.push({ name: p.domain, type: p.type, ttl: Number(p.ttl), rData: { ...(row.singleton && p.overwrite === 'true' ? row.updated : row.data) } });
        if (row.related && p.ptr === 'true' && p.updateSvcbHints === 'true') related = row.related.add;
        return { body: { status: 'ok' } };
      });
      vendors.responders.set('/api/zones/records/update', (_incoming, bytes) => {
        const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
        for (const [key, value] of Object.entries(row.updateOptions ?? {})) assert.equal(p[key], String(value?.env ? secret : Array.isArray(value) ? value.join(',') : value), `${row.type} update ${key}`);
        assert.deepEqual(Object.fromEntries(Object.entries(row.replacement).map(([key]) => [key, p[key]])), Object.fromEntries(Object.entries(row.replacement).map(([key, value]) => [key, String(value)])));
        const index = select(p);
        assert.ok(index >= 0, 'Exact record selector must preserve siblings');
        records[index] = { name: p.newDomain ?? p.domain, type: row.type, ttl: Number(p.ttl), rData: row.updated };
        if (row.related && p.ptr === 'true' && p.updateSvcbHints === 'true') related = row.related.update;
        return { body: { status: 'ok' } };
      });
      vendors.responders.set('/api/zones/records/delete', (_incoming, bytes) => {
        const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
        const index = records.findIndex(record => record.name === p.domain && record.type === p.type &&
          (row.singleton || Object.entries(record.rData).every(([key, value]) => String(value) === p[key])));
        assert.ok(index >= 0);
        records.splice(index, 1);
        return { body: { status: 'ok' } };
      });
      const publicRecords = values => values.map(record => ({ ...record, rData: Object.fromEntries(Object.entries(record.rData).map(([key, value]) => {
        const names = { naptrOrder: 'order', naptrPreference: 'preference', naptrFlags: 'flags', naptrServices: 'services', naptrRegexp: 'regexp', naptrReplacement: 'replacement',
          sshfpAlgorithm: 'algorithm', sshfpFingerprintType: 'fingerprintType', sshfpFingerprint: 'fingerprint', tlsaCertificateUsage: 'certificateUsage',
          tlsaSelector: 'selector', tlsaMatchingType: 'matchingType', tlsaCertificateAssociationData: 'certificateAssociationData', uriPriority: 'priority', uriWeight: 'weight', recordData: 'data', rdata: 'value' };
        const enums = { algorithm: { 13: 'ECDSAP256SHA256' }, digestType: { 2: 'SHA256' }, sshfpAlgorithm: { 1: 'RSA', 2: 'DSA' },
          sshfpFingerprintType: { 2: 'SHA256' }, tlsaCertificateUsage: { 0: 'PKIX-TA', 2: 'DANE-TA', 3: 'DANE-EE' }, tlsaSelector: { 1: 'SPKI' }, tlsaMatchingType: { 1: 'SHA2-256' } };
        return [names[key] ?? key, key === 'characterStringsBase64' ? [value] : key === 'svcParams' ? Object.fromEntries([value.split('|')])
          : key === 'rdata' ? value.match(/../g).join(':').toUpperCase() : enums[key] ? enums[key][value] ?? String(value) : value];
      })) }));
      vendors.responders.set('/api/zones/records/get', () => ({ body: { status: 'ok', response: { zone: { name: 'example.test', type: 'Primary' }, records: publicRecords([...records, ...related]) } } }));
      const readback = async (expected, expectedRelated = []) => {
        const result = join(directory, `records-${sequence++}.json`);
        const read = await run(executable, ['zone', 'record', 'get', '--domain', 'example.test', '--zone', 'example.test', '--list-zone', 'true', '--config', config, '--result-file', result, '--json'], { env: { ...env, WRITE_TOKEN: token } });
        assert.equal(read.code, 0, read.stdout + read.stderr);
        assert.deepEqual(JSON.parse(await readFile(result, 'utf8')).response.records, publicRecords([...expected, ...expectedRelated]));
      };
      const first = { name: owner, type: row.type, ttl: 60, rData: row.data };
      if (row.updateOnly) {
        records.push(first);
        await failure('USAGE', 'zone record add', { parameters: params });
      } else await execute('zone record add', { parameters: params });
      await readback([keep, comparison, first], row.related?.add);
      if (row.singleton && !row.updateOnly) {
        const duplicate = { parameters: { ...params, overwrite: false } };
        await failure('OUTCOME_UNKNOWN', 'zone record add', duplicate, ['--execute', '--confirm', (await success('zone record add', duplicate)).preview.digest]);
        await readback([keep, comparison, first]);
        await execute('zone record add', { parameters: { ...params, ...row.updated, overwrite: true } });
        await readback([keep, comparison, { ...first, rData: row.updated }]);
      }
      const update = { ...params, ...row.replacement, ...row.updateOptions, ttl: 0 };
      delete update.overwrite;
      if (row.singleton) for (const key of dataKeys) if (!Object.hasOwn(row.replacement, key)) delete update[key];
      await execute('zone record update', { parameters: update });
      const rData = row.updated;
      const updated = { name: update.newDomain ?? owner, type: row.type, ttl: 0, rData };
      await readback([keep, comparison, updated], row.related?.update);
      const remove = { zone: 'example.test', domain: updated.name, type: row.type, ...(row.singleton ? {} : rData) };
      if (row.updateOnly) await failure('USAGE', 'zone record delete', { parameters: remove });
      else if (row.pendingDelete) await failure('PREREQUISITE_PENDING', 'zone record delete', { parameters: remove });
      else {
        await execute('zone record delete', { parameters: remove });
        await readback([keep, comparison], row.related?.update);
      }
      await failure('USAGE', 'zone record add', { parameters: { ...params, unexpected: true } });
    }
    await failure('USAGE', 'zone record add', { parameters: { ...add.parameters, ipAddress: null } });
    await failure('USAGE', 'zone record add', { parameters: { zone: 'example.test', domain: 'www.example.test', type: 'TXT', text: '', characterStringsBase64: '' } });
  }
  return [`native:${task}:write-behavior`];
}
