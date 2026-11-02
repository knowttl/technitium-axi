import assert from 'node:assert/strict';
import { chmod, mkdir, readFile, readdir, symlink, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import matrix from '../tests/fixtures/record-inputs.json' with { type: 'json' };
import { dnssecJourney, dnssecTasks } from './dnssec-journey.mjs';
import { zoneJourney, zoneTasks } from './zone-journey.mjs';

export const writeTasks = ['B3.01', 'B3.02', 'B3.03', 'B3.04', 'B3.05', 'B3.CR-013', 'B3.CR-014', 'B3.dnssec', ...dnssecTasks, ...zoneTasks, 'B3.OP-049', 'B3.OP-051', 'B3.OP-052'];
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
    assert.equal(result.code, 0, `${args[0]} ${args[1].parameters.type ?? ''}: ${result.stdout}`);
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
  if (task === 'B3.dnssec' || dnssecTasks.includes(task)) {
    for (const selected of task === 'B3.dnssec' ? dnssecTasks : [task]) {
      await dnssecJourney({ task: selected, directory, env, run, executable, vendors, config, token, secret, configure, success, failure });
    }
    return [`native:${task}:write-behavior`];
  }
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
    await configure(['OP-019', 'OP-049', 'OP-052', 'OP-022']);
    let statistics = 5;
    let clears = 0;
    vendors.responders.set('/api/dashboard/stats/deleteAll', () => {
      statistics = 0;
      clears++;
      return { body: { status: 'ok' } };
    });
    const firstClear = await success('dashboard stats delete-all', { parameters: {} });
    await success('dashboard stats delete-all', { parameters: {} }, ['--execute', '--confirm', firstClear.preview.digest]);
    assert.equal(statistics, 0);
    statistics = 7;
    await failure('REPLAY_DENIED', 'dashboard stats delete-all', { parameters: {} }, ['--execute', '--confirm', firstClear.preview.digest]);
    assert.equal(statistics, 7);
    const nextClear = await success('dashboard stats delete-all', { parameters: {} });
    assert.notEqual(nextClear.preview.digest, firstClear.preview.digest);
    await success('dashboard stats delete-all', { parameters: {} }, ['--execute', '--confirm', nextClear.preview.digest]);
    assert.equal(statistics, 0);
    assert.equal(clears, 2);
    let recordExists = true;
    vendors.responders.set('/api/zones/records/delete', () => {
      assert.equal(recordExists, true);
      recordExists = false;
      return { body: { status: 'ok' } };
    });
    vendors.responders.set('/api/zones/records/add', () => {
      assert.equal(recordExists, false);
      recordExists = true;
      return { body: { status: 'ok' } };
    });
    const remove = { parameters: { zone: add.parameters.zone, domain: add.parameters.domain, type: 'A', ipAddress: add.parameters.ipAddress } };
    await execute('zone record delete', remove);
    await execute('zone record add', add);
    await execute('zone record delete', remove);
    await execute('zone record add', add);
    assert.equal(recordExists, true);
    await failure('USAGE', 'zone create', { parameters: { zone: 'example.test', type: 'Primary', domain: 'other.test' } });
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
    const proxy = { type: 'Http', address: 'proxy.example.test', port: 8080, username: 'operator', password: secret, bypass: ['old.test'] };
    const mappings = [
      { command: 'admin group set', grant: 'OP-109', get: '/api/admin/groups/get', set: '/api/admin/groups/set', target: { group: 'Operators' },
        before: { name: 'Operators', members: ['old'] }, baseline: { members: ['OLD'] }, parameters: { members: ['BOB', 'alice', 'BOB'] },
        after: { name: 'Operators', members: ['alice', 'bob'] }, form: { members: 'BOB,alice,BOB' } },
      ...[
        { field: 'zoneTransferTsigKeyNames', before: [], input: ['KEY.', 'other', 'key'], after: ['key', 'other'] },
        { field: 'notifyNameServers', before: [], input: ['2001:0db8:0:0:0:0:0:1'], after: ['2001:db8::1'] },
        { field: 'updateNetworkACL', before: [], input: ['192.0.2.9/24', '!2001:db8::1234/64', '192.0.2.1/32'], after: ['192.0.2.0/24', '!2001:db8::/64', '192.0.2.1'] },
        { field: 'primaryZoneTransferProtocol', before: 'Tls', input: 'tcp', after: 'Tcp' },
        { field: 'catalog', before: null, input: 'CATALOG.Test.', after: 'catalog.test' },
        { field: 'updateSecurityPolicies', before: [], input: 'KEY.|Example.Test.|TXT|key|example.test|A',
          after: [{ tsigKeyName: 'key', domain: 'example.test', allowedTypes: ['TXT', 'A'] }] },
      ].map(row => ({ command: 'zone options set', grant: 'OP-032', get: '/api/zones/options/get', set: '/api/zones/options/set', target: { zone: 'example.test' },
        before: { [row.field]: row.before }, baseline: { [row.field]: row.before }, parameters: { [row.field]: row.input },
        after: { [row.field]: row.after }, form: { [row.field]: Array.isArray(row.input) ? row.input.join(',') : row.input } })),
      { command: 'settings set', grant: 'OP-080', get: '/api/settings/get', set: '/api/settings/set', target: {},
        before: { blockListUrls: null }, baseline: { blockListUrls: null }, parameters: { blockListUrls: ['https://block.example.test/list'] },
        after: { blockListUrls: ['https://block.example.test/list'] }, form: { blockListUrls: 'https://block.example.test/list' } },
      { command: 'settings set', grant: 'OP-080', get: '/api/settings/get', set: '/api/settings/set', target: {},
        before: { forwarders: null, forwarderProtocol: 'Udp' }, baseline: { forwarders: null }, parameters: { forwarders: ['192.0.2.53'] },
        after: { forwarders: ['192.0.2.53'], forwarderProtocol: 'Udp' }, form: { forwarders: '192.0.2.53', forwarderProtocol: 'Udp' } },
      { command: 'settings set', grant: 'OP-080', get: '/api/settings/get', set: '/api/settings/set', target: {},
        before: { forwarders: ['old.example.test'], forwarderProtocol: 'Tls' }, baseline: { forwarders: ['old.example.test'] }, parameters: { forwarders: ['new.example.test'] },
        after: { forwarders: ['new.example.test'], forwarderProtocol: 'Tls' }, form: { forwarders: 'new.example.test', forwarderProtocol: 'Tls' } },
      { command: 'settings set', grant: 'OP-080', get: '/api/settings/get', set: '/api/settings/set', target: {},
        before: { forwarders: ['old.example.test'], forwarderProtocol: 'Tls' }, baseline: { forwarders: ['old.example.test'] }, parameters: { forwarders: [] },
        after: { forwarders: null, forwarderProtocol: 'Udp' }, form: { forwarders: '', forwarderProtocol: 'Tls' } },
      { command: 'settings set', grant: 'OP-080', get: '/api/settings/get', set: '/api/settings/set', target: {},
        before: { proxy }, baseline: { proxyBypass: ['old.test'] }, parameters: { proxyBypass: ['new.test'] },
        after: { proxy: { ...proxy, bypass: ['new.test'] } },
        form: { proxyBypass: 'new.test', proxyType: 'Http', proxyAddress: 'proxy.example.test', proxyPort: '8080', proxyUsername: 'operator', proxyPassword: secret } },
      { command: 'zone options set', grant: 'OP-032', get: '/api/zones/options/get', set: '/api/zones/options/set', target: { zone: 'example.test' },
        before: { catalog: null }, baseline: { catalog: null }, parameters: { catalog: 'catalog.test' }, after: { catalog: 'catalog.test' }, form: { catalog: 'catalog.test' } },
      { command: 'zone options set', grant: 'OP-032', get: '/api/zones/options/get', set: '/api/zones/options/set', target: { zone: 'example.test' },
        before: { catalog: 'catalog.test' }, baseline: { catalog: 'catalog.test' }, parameters: { catalog: '' }, after: { catalog: null }, form: { catalog: '' } },
      { command: 'zone options set', grant: 'OP-032', get: '/api/zones/options/get', set: '/api/zones/options/set', target: { zone: 'example.test' },
        before: { primaryZoneTransferTsigKeyName: null }, baseline: { primaryZoneTransferTsigKeyName: null }, parameters: { primaryZoneTransferTsigKeyName: 'key' },
        after: { primaryZoneTransferTsigKeyName: 'key' }, form: { primaryZoneTransferTsigKeyName: 'key' } },
      { command: 'zone options set', grant: 'OP-032', get: '/api/zones/options/get', set: '/api/zones/options/set', target: { zone: 'example.test' },
        before: { primaryZoneTransferTsigKeyName: 'key' }, baseline: { primaryZoneTransferTsigKeyName: 'key' }, parameters: { primaryZoneTransferTsigKeyName: '' },
        after: { primaryZoneTransferTsigKeyName: null }, form: { primaryZoneTransferTsigKeyName: '' } },
      { command: 'zone options set', grant: 'OP-032', get: '/api/zones/options/get', set: '/api/zones/options/set', target: { zone: 'example.test' },
        before: { updateSecurityPolicies: [] }, baseline: { updateSecurityPolicies: [] }, parameters: { updateSecurityPolicies: 'KEY.|Example.Test.|TXT,A' },
        after: { updateSecurityPolicies: [{ tsigKeyName: 'key', domain: 'example.test', allowedTypes: ['A', 'TXT'] }] }, form: { updateSecurityPolicies: 'KEY.|Example.Test.|TXT,A' } },
      { command: 'zone options set', grant: 'OP-032', get: '/api/zones/options/get', set: '/api/zones/options/set', target: { zone: 'example.test' },
        before: { updateSecurityPolicies: [{ tsigKeyName: 'key', domain: 'example.test', allowedTypes: ['A', 'TXT'] }] },
        baseline: { updateSecurityPolicies: [{ tsigKeyName: 'key', domain: 'example.test', allowedTypes: ['A', 'TXT'] }] }, parameters: { updateSecurityPolicies: '' },
        after: { updateSecurityPolicies: [] }, form: { updateSecurityPolicies: '' } },
      { command: 'admin group set', grant: 'OP-109', get: '/api/admin/groups/get', set: '/api/admin/groups/set', target: { group: 'Operators' },
        before: { name: 'Operators', members: ['old'] }, baseline: { newGroup: 'Operators', members: ['old'] }, parameters: { newGroup: 'Renamed', members: ['new'] },
        after: { name: 'Renamed', members: ['new'] }, form: { newGroup: 'Renamed', members: 'new' } },
    ];
    for (const row of mappings) {
      await configure([row.grant]);
      let state = row.before;
      let setters = 0;
      let drop = false;
      vendors.responders.set(row.get, (_incoming, bytes) => {
        const target = Object.fromEntries(new URLSearchParams(bytes.toString()));
        assert.deepEqual(target, row.grant === 'OP-109' ? { group: state.name } : row.target);
        return { body: { status: 'ok', response: state } };
      });
      vendors.responders.set(row.set, (incoming, bytes) => {
        assert.deepEqual(Object.fromEntries(new URLSearchParams(bytes.toString())), { ...row.target, ...row.form });
        setters++;
        state = row.after;
        if (drop) { incoming.socket.destroy(); return {}; }
        return { body: { status: 'ok' } };
      });
      const input = { parameters: { ...row.target, ...row.parameters }, baseline: row.baseline };
      await execute(row.command, input);
      assert.deepEqual(state, row.after);
      state = row.before;
      drop = true;
      const preview = await success(row.command, input);
      const unknown = await failure('OUTCOME_UNKNOWN', row.command, input, ['--execute', '--confirm', preview.preview.digest]);
      const auditId = unknown.error.message.match(/audit ID ([a-f0-9-]+)/)[1];
      await success(row.command, input, ['--confirm', preview.preview.digest, '--reconcile', auditId]);
      assert.equal(setters, 2);
      if (row.after.forwarderProtocol === 'Tls') {
        state = { ...state, forwarderProtocol: 'Udp' };
        await failure('OUTCOME_UNKNOWN', row.command, input, ['--confirm', preview.preview.digest, '--reconcile', auditId]);
      }
      if (row.after.proxy) {
        state = { proxy: { ...state.proxy, address: 'changed.test' } };
        await failure('OUTCOME_UNKNOWN', row.command, input, ['--confirm', preview.preview.digest, '--reconcile', auditId]);
      }
    }
    const journal = join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d');
    for (const file of await readdir(journal)) assert.ok(!(await readFile(join(journal, file), 'utf8')).includes(secret));
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
  if (zoneTasks.includes(task)) await zoneJourney({ task, directory, env, run, executable, vendors, config, token, configure, success, failure, execute });
  if (['B3.02', 'B3.OP-049', 'B3.OP-051', 'B3.OP-052'].includes(task)) {
    await configure(['OP-049', 'OP-051', 'OP-052']);
    const numericTypes = { A: '1', SOA: '6', TXT: '16', DNAME: '39', ANAME: '65280', FWD: '65281', APP: '65282' };
    for (const row of matrix.rows.flatMap(row => numericTypes[row.type] ? [row, { ...row, inputType: numericTypes[row.type] }] : [row])) {
      let records = [];
      let related = [];
      const owner = row.updateOnly ? 'example.test' : 'www.example.test';
      const keep = { name: 'keep.example.test', type: 'TXT', ttl: 60, rData: { text: 'keep' } };
      const firstKey = Object.keys(row.data)[0];
      const siblingData = { ...row.data, [firstKey]: row.sibling ?? (typeof row.data[firstKey] === 'number' ? row.data[firstKey] + 1 : `sibling.${row.data[firstKey]}`) };
      const comparison = { name: row.updateOnly ? 'keep.test' : row.singleton ? 'other.example.test' : owner, type: row.type, ttl: 60, rData: siblingData };
      records = [keep, comparison];
      const params = { zone: 'example.test', domain: owner, type: row.type, ttl: 60, ...row.data, ...row.addOptions };
      const recordInput = parameters => ({ parameters: { ...parameters, type: row.inputType ?? row.type } });
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
        await failure('USAGE', 'zone record add', recordInput(params));
      } else await execute('zone record add', recordInput(params));
      await readback([keep, comparison, first], row.related?.add);
      if (row.singleton && !row.updateOnly) {
        const duplicate = recordInput({ ...params, overwrite: false });
        await failure('OUTCOME_UNKNOWN', 'zone record add', duplicate, ['--execute', '--confirm', (await success('zone record add', duplicate)).preview.digest]);
        await readback([keep, comparison, first]);
        await execute('zone record add', recordInput({ ...params, ...row.updated, overwrite: true }));
        await readback([keep, comparison, { ...first, rData: row.updated }]);
      }
      const update = { ...params, ...row.replacement, ...row.updateOptions, ttl: 0 };
      delete update.overwrite;
      if (row.singleton) for (const key of dataKeys) if (!Object.hasOwn(row.replacement, key)) delete update[key];
      await execute('zone record update', recordInput(update));
      const rData = row.updated;
      const updated = { name: update.newDomain ?? owner, type: row.type, ttl: 0, rData };
      await readback([keep, comparison, updated], row.related?.update);
      const remove = { zone: 'example.test', domain: updated.name, type: row.type, ...(row.singleton ? {} : rData) };
      if (row.updateOnly) await failure('USAGE', 'zone record delete', recordInput(remove));
      else if (row.pendingDelete) {
        const before = vendors.traces.length;
        await failure('PREREQUISITE_PENDING', 'zone record delete', recordInput(remove));
        await failure('PREREQUISITE_PENDING', 'zone record delete', { parameters: { ...remove, type: '39', rdata: '00' } }, ['--execute', '--confirm', 'unused']);
        await failure('PREREQUISITE_PENDING', 'zone record delete', { parameters: { ...remove, type: '039', rdata: '00' } });
        assert.equal(vendors.traces.length, before, 'Refused DNAME deletions must not dispatch');
        await readback([keep, comparison, updated]);
      } else {
        await execute('zone record delete', recordInput(remove));
        await readback([keep, comparison], row.related?.update);
      }
      await failure('USAGE', 'zone record add', { parameters: { ...params, unexpected: true } });
    }
    const before = vendors.traces.length;
    for (const action of ['add', 'update', 'delete']) {
      for (const type of ['HINFO', '13', 'RRSIG', '46', 'DNSKEY', '48']) {
        await failure('USAGE', `zone record ${action}`, { parameters: { zone: 'example.test', domain: 'www.example.test', type, rdata: '00' } });
      }
    }
    await failure('USAGE', 'zone record update', { parameters: { zone: 'example.test', domain: 'www.example.test', type: '6', rdata: '00' } });
    assert.equal(vendors.traces.length, before, 'Unsupported record paths must not dispatch');
    await failure('USAGE', 'zone record add', { parameters: { ...add.parameters, ipAddress: null } });
    await failure('USAGE', 'zone record add', { parameters: { zone: 'example.test', domain: 'www.example.test', type: 'TXT', text: '', characterStringsBase64: '' } });
  }
  return [`native:${task}:write-behavior`];
}
