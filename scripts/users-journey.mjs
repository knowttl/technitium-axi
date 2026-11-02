import assert from 'node:assert/strict';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { request } from 'node:https';

// Synthetic wire expectations from the pinned vendor User API contract.
const operations = [
  ['002', 'login', 'login', { user: 'planner', pass: { env: 'ACCOUNT_PASS' }, totp: { env: 'ACCOUNT_TOTP' } }],
  ['003', 'create-token', 'createToken', { tokenName: 'automation-1' }],
  ['004', 'create-single-use-token', 'createSingleUseToken', {}],
  ['005', 'logout', 'logout', {}],
  ['007', 'session delete', 'session/delete', { partialToken: '2222222222222222' }],
  ['008', 'change-password', 'changePassword', { pass: { env: 'ACCOUNT_PASS' }, newPass: { env: 'ACCOUNT_PASS' }, iterations: 100000 }],
  ['009', '2fa init', '2fa/init', {}],
  ['010', '2fa enable', '2fa/enable', { totp: { env: 'ACCOUNT_TOTP' } }],
  ['011', '2fa disable', '2fa/disable', {}],
  ['013', 'profile set', 'profile/set', { displayName: 'Planner Updated', sessionTimeoutSeconds: 600 }],
];
export const usersTasks = ['B5.01', 'B5.02', ...['006', '007', '009', '010'].map(id => `B5.CR-${id}`), ...operations.map(([id]) => `B5.OP-${id}`)];

export async function usersJourney({ task, temporary, env, run, executable, vendors }) {
  const directory = join(temporary, 'users');
  await mkdir(directory, { mode: 0o700 });
  const config = join(directory, 'config.json');
  const token = 'SYNTHETIC-standard-session';
  const issued = 'SYNTHETIC-issued-session';
  const password = 'SYNTHETIC-password-"/+=canary';
  const totp = '123456';
  const secret = 'SYNTHETIC-issued-secret';
  const profile = { origin: vendors.origins[0], auth: 'token', tokenKind: 'session', username: 'planner', token: { env: 'ACCOUNT_TOKEN' }, caFile: vendors.caFile, tlsServerName: 'localhost' };
  const grants = [...operations.map(([id]) => `OP-${id}`), 'OP-104', 'OP-116', 'OP-117'];
  const configure = async (changes = {}, name = 'alpha') => writeFile(config, JSON.stringify({ version: 1, profiles: { [name]: { ...profile, writes: { allowWrites: true, operations: grants }, ...changes } } }), { mode: 0o600 });
  await configure();
  vendors.tokens.set('alpha', token);
  vendors.tokens.set('beta', token);
  vendors.tokenKinds.set('alpha', 'session');
  let sequence = 0;
  const invoke = async (command, parameters, flags = [], extraEnv = {}) => {
    const file = join(directory, `input-${sequence++}.json`);
    await writeFile(file, JSON.stringify({ parameters }), { mode: 0o600 });
    const result = await run(executable, [...command.split(' '), '--config', config, '--json', ...(parameters === undefined ? [] : ['--input-file', file]), ...flags],
      { env: { ...env, ACCOUNT_TOKEN: token, ACCOUNT_PASS: password, ACCOUNT_TOTP: totp, ...extraEnv } });
    assert.equal(result.stderr, '', result.stderr);
    for (const value of [token, issued, password, secret, totp]) for (const form of [value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value), Buffer.from(value).toString('base64')]) assert.ok(!result.stdout.includes(form), result.stdout);
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
  };
  const execute = async (command, parameters, extraEnv = {}) => {
    const preview = await success(command, parameters, [], extraEnv);
    const resultFile = join(directory, `result-${sequence++}.json`);
    const result = await success(command, parameters, ['--execute', '--confirm', preview.preview.digest, '--result-file', resultFile], extraEnv);
    assert.equal((await stat(resultFile)).mode & 0o777, 0o600);
    return { result, bytes: await readFile(resultFile) };
  };
  let fault;
  let loginToken = issued;
  const changed = new Map();
  const sessions = new Map();
  const account = { displayName: 'Planner', password, totpEnabled: true, sessionTimeoutSeconds: 1800, enrollment: '' };
  for (const [id, , endpoint, parameters] of operations) vendors.responders.set(`/api/user/${endpoint}`, (incoming, bytes) => {
    const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
    const acquisition = id === '002' || id === '003' && p.pass !== undefined;
    assert.equal(incoming.headers.authorization, acquisition ? undefined : `Bearer ${token}`);
    const expected = Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, value?.env ? value.env === 'ACCOUNT_TOTP' ? totp : password : String(value)]));
    if (id === '002') expected.includeInfo = 'true';
    if (id === '003' && acquisition) Object.assign(expected, { user: 'planner', pass: password, totp });
    assert.deepEqual(p, expected);
    if (fault) return { body: { status: fault } };
    changed.set(id, p);
    if (id === '002') return { body: { status: 'ok', username: 'planner', token: loginToken, info: { permissions: { Administration: { canModify: true } } } } };
    if (id === '003') sessions.set(secret, { type: 'ApiToken', tokenName: p.tokenName });
    if (id === '003') return { body: { status: 'ok', username: 'planner', tokenName: p.tokenName, token: secret } };
    if (id === '004') return { body: { status: 'ok', response: { username: 'planner', token: secret } } };
    if (id === '005') { sessions.delete(token); vendors.tokens.delete('alpha'); }
    if (id === '007') {
      if (p.partialToken.length !== 16) return { body: { status: 'error', errorMessage: 'partialToken must be exactly 16 chars long.' } };
      const selected = [...sessions.keys()].find(value => value.startsWith(p.partialToken));
      if (!selected || selected === token) return { body: { status: 'error', errorMessage: 'No deletable session matches the prefix.' } };
      sessions.delete(selected);
    }
    if (id === '008') account.password = p.newPass;
    if (id === '009') { account.enrollment = secret; return { body: { status: 'ok', response: { secret, provisioningUri: `otpauth://totp/planner?secret=${secret}` } } }; }
    if (id === '010') account.totpEnabled = true;
    if (id === '011') account.totpEnabled = false;
    if (id === '013') Object.assign(account, { displayName: p.displayName, sessionTimeoutSeconds: Number(p.sessionTimeoutSeconds) });
    return { body: { status: 'ok', response: {} } };
  });
  if (task === 'B5.02') {
    let permission = true;
    let primary = false;
    const users = new Map();
    const keep = { username: 'keep-user', displayName: 'Keep', memberOfGroups: ['Users'], ssoIdentifier: 'keep-sub' };
    users.set('keep-user', keep);
    const clusterToken = 'SYNTHETIC-private-cluster-identity';
    vendors.clusterTokens.set('beta', clusterToken);
    const ca = await readFile(vendors.caFile);
    vendors.responders.set('/api/user/session/get', (_incoming, bytes) => {
      assert.equal(bytes.toString(), 'includeInfo=true');
      return { body: { status: 'ok', username: 'planner', token, info: { permissions: permission === undefined ? {} : { Administration: { canModify: permission } } } } };
    });
    vendors.responders.set('/api/admin/cluster/state', () => ({ body: { status: 'ok', response: { clusterInitialized: true, clusterNodes: [
      { name: 'primary.test', url: `${vendors.origins[1]}/`, type: 'Primary', state: primary ? 'Self' : 'Connected' },
      ...primary ? [] : [{ name: 'secondary.test', url: `${vendors.origins[0]}/`, type: 'Secondary', state: 'Self' }],
    ] } } }));
    for (const action of ['create', 'set']) vendors.responders.set(`/api/admin/sso/users/${action}`, async (incoming, bytes) => {
      if (incoming.socket.localPort !== Number(new URL(vendors.origins[1]).port)) {
        // Model the vendor secondary proxy, keeping its credential entirely outside the CLI.
        return await new Promise((resolve, reject) => {
          const call = request(new URL(`/api/admin/sso/users/${action}`, vendors.origins[1]), { method: 'POST', ca, headers: { authorization: `Bearer ${clusterToken}` } }, response => {
            const chunks = [];
            response.on('data', chunk => chunks.push(chunk));
            response.once('end', () => resolve({ body: JSON.parse(Buffer.concat(chunks).toString()) }));
          });
          call.once('error', reject);
          call.end(bytes);
        });
      }
      assert.equal(incoming.headers.authorization, `Bearer ${clusterToken}`);
      const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
      const previous = users.get(p.user);
      users.set(p.newUser ?? p.user, { username: p.newUser ?? p.user, displayName: p.displayName, memberOfGroups: p.memberOfGroups.split(','), ssoIdentifier: previous?.ssoIdentifier ?? p.ssoIdentifier });
      return { body: { status: 'ok' } };
    });
    vendors.responders.set('/api/admin/users/get', (incoming, bytes) => {
      assert.equal(incoming.socket.localPort, Number(new URL(vendors.origins[1]).port));
      return { body: { status: 'ok', response: users.get(new URLSearchParams(bytes.toString()).get('user')) } };
    });
    const readback = async expected => {
      await configure({ origin: vendors.origins[1] });
      const file = join(directory, 'sso-readback.json');
      await success('admin user get', undefined, ['--user', 'sso-user', '--result-file', file]);
      assert.deepEqual(JSON.parse(await readFile(file, 'utf8')).response, expected);
      assert.deepEqual(users.get('keep-user'), keep);
      await configure();
    };
    const create = { user: 'sso-user', displayName: 'SSO User', ssoIdentifier: 'sub-123', memberOfGroups: ['Users'] };
    const preview = await success('admin sso user create', create);
    assert.deepEqual(preview.preview.route, { requested: vendors.origins[0], effective: `${vendors.origins[1]}/`, caller: 'planner' });
    await execute('admin sso user create', create);
    await readback({ username: 'sso-user', displayName: 'SSO User', memberOfGroups: ['Users'], ssoIdentifier: 'sub-123' });
    await execute('admin sso user set', { user: 'sso-user', displayName: 'Updated', memberOfGroups: ['Operators'] });
    await readback({ username: 'sso-user', displayName: 'Updated', memberOfGroups: ['Operators'], ssoIdentifier: 'sub-123' });
    const mutations = () => vendors.traces.filter(trace => trace.path.startsWith('/api/admin/sso/')).length;
    const before = mutations();
    for (permission of [false, undefined, 'true']) await failure('PERMISSION_DENIED', 'admin sso user create', create);
    permission = true;
    primary = true;
    await configure({ origin: vendors.origins[1] });
    await failure('PREREQUISITE_REQUIRED', 'admin sso user create', create);
    assert.equal(mutations(), before);
    for (const file of await readdir(join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d'))) assert.ok(!(await readFile(join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d', file), 'utf8')).includes(clusterToken));
    return;
  }
  const selected = task.startsWith('B5.OP-') ? task.slice(6) : undefined;
  if (selected || task === 'B5.01' || task === 'B5.CR-010') {
    for (const [id, command, , parameters] of operations.filter(([id]) => selected ? id === selected : task === 'B5.CR-010' ? ['003', '009'].includes(id) : true)) {
      await configure();
      vendors.tokens.set('alpha', token);
      sessions.clear();
      sessions.set(token, { type: 'Standard' });
      sessions.set('2222222222222222-other-session', { type: 'Standard' });
      account.password = 'old-password';
      account.totpEnabled = id !== '010';
      fault = undefined;
      if (id === '002') {
        const before = vendors.traces.length;
        for (const login of ['user login', 'auth login']) await failure('USAGE', login, { ...parameters, includeInfo: false });
        assert.equal(vendors.traces.length, before, 'Unsupported login input must be rejected before dispatch');
      }
      const result = await execute(`user ${command}`, parameters);
      assert.deepEqual(changed.get(id), Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, value?.env ? value.env === 'ACCOUNT_TOTP' ? totp : password : String(value)]).concat(id === '002' ? [['includeInfo', 'true']] : [])));
      if (id === '003') assert.equal(JSON.parse(result.bytes).token, secret);
      if (id === '004') assert.equal(JSON.parse(result.bytes).response.token, secret);
      if (id === '009') assert.equal(JSON.parse(result.bytes).response.secret, secret);
      if (task === 'B5.CR-010') {
        const preview = await success(`user ${command}`, parameters);
        const destination = join(directory, 'insecure-result');
        await writeFile(destination, 'unchanged', { mode: 0o644 });
        const before = vendors.traces.length;
        await failure('CONFIG_INSECURE', `user ${command}`, parameters, ['--execute', '--confirm', preview.preview.digest, '--result-file', destination]);
        assert.equal(vendors.traces.length, before, 'Result custody must be established before issuance');
        assert.equal(await readFile(destination, 'utf8'), 'unchanged');
      }
      if (id === '003') assert.deepEqual([...sessions.values()].filter(row => row.type === 'ApiToken'), [{ type: 'ApiToken', tokenName: 'automation-1' }]);
      if (id === '007') {
        assert.equal(sessions.has('2222222222222222-other-session'), false);
        await success('user session get');
      }
      if (id === '008') assert.equal(account.password, password);
      if (id === '009') assert.equal(account.enrollment, secret);
      if (id === '010') assert.equal(account.totpEnabled, true);
      if (id === '011') assert.equal(account.totpEnabled, false);
      if (id === '013') assert.deepEqual({ displayName: account.displayName, sessionTimeoutSeconds: account.sessionTimeoutSeconds }, { displayName: 'Planner Updated', sessionTimeoutSeconds: 600 });
      if (id === '002') {
        const stored = await readFile(join(env.XDG_STATE_HOME, 'technitium-axi', 'credentials.json'), 'utf8');
        assert.equal(JSON.parse(stored).alpha.token, issued);
        assert.ok(!stored.includes(password) && !stored.includes(totp));
        fault = 'error';
        const rejected = await success('user login', parameters);
        await failure('OUTCOME_UNKNOWN', 'user login', parameters, ['--execute', '--confirm', rejected.preview.digest]);
        assert.equal(await readFile(join(env.XDG_STATE_HOME, 'technitium-axi', 'credentials.json'), 'utf8'), stored, 'A rejected password cannot replace stored credentials');
      }
      if (id === '005') {
        assert.equal(result.result.revoked, true);
        assert.deepEqual([...sessions.keys()], ['2222222222222222-other-session']);
        await failure('AUTH_REQUIRED', 'user session get');
        vendors.tokens.set('alpha', '2222222222222222-other-session');
        await success('user session get', undefined, [], { ACCOUNT_TOKEN: '2222222222222222-other-session' });
        vendors.tokens.set('alpha', token);
      }
      const before = vendors.traces.length;
      if (['003', '004', '008', '009', '010', '011', '013'].includes(id)) {
        await configure({ tokenKind: 'api' });
        await failure('TOKEN_KIND', `user ${command}`, parameters);
        assert.equal(vendors.traces.length, before);
        await configure();
      }
      fault = id === '002' ? '2fa-required' : 'invalid-token';
      if (id === '005') {
        const failed = await execute(`user ${command}`, parameters);
        assert.equal(failed.result.revoked, false);
        assert.equal(failed.result.status, 'revoke-failed');
      } else {
        const preview = await success(`user ${command}`, parameters);
        const before = vendors.traces.length;
        await failure(id === '002' ? 'TWO_FACTOR_REQUIRED' : 'AUTH_REQUIRED', `user ${command}`, parameters, ['--execute', '--confirm', preview.preview.digest, '--result-file', join(directory, 'failure-result')]);
        assert.equal(vendors.traces.length, before + 1, 'Authentication failure must not retry or acquire a wider identity');
      }
      fault = undefined;
      if (id === '003') {
        const minted = await execute('user create-token', { ...parameters, user: 'planner', pass: { env: 'ACCOUNT_PASS' }, totp: { env: 'ACCOUNT_TOTP' } });
        assert.equal(JSON.parse(minted.bytes).token, secret);
      }
      if (id === '004') {
        vendors.responders.set('/api/user/session/get', (incoming) => {
          const valid = incoming.headers.authorization === `Bearer ${secret}`;
          vendors.tokens.set('alpha', token);
          return { body: valid ? { status: 'ok', username: 'planner', token: secret, info: { version: '15.4', permissions: {} } } : { status: 'invalid-token' } };
        });
        vendors.tokens.set('alpha', secret);
        await configure({ tokenKind: 'single-use' });
        await success('user session get', undefined, [], { ACCOUNT_TOKEN: secret });
        await failure('AUTH_REQUIRED', 'user session get', undefined, [], { ACCOUNT_TOKEN: secret });
        vendors.responders.delete('/api/user/session/get');
      }
    }
  }
  if (['B5.01', 'B5.CR-006'].includes(task)) {
    fault = undefined;
    const login = operations[0][3];
    await configure({ token: { stored: true } });
    await execute('auth login', login);
    vendors.tokens.set('alpha', issued);
    for (const [field, value] of [['origin', vendors.origins[1]], ['username', 'other'], ['tokenKind', 'api'], ['tlsServerName', 'other.test'], ['caFile', join(directory, 'other.pem')]]) {
      await configure({ token: { stored: true }, [field]: value });
      const before = vendors.traces.length;
      await failure('AUTH_REQUIRED', 'user session get');
      assert.equal(vendors.traces.length, before);
    }
    await configure({ token: { stored: true } }, 'other-profile');
    await failure('AUTH_REQUIRED', 'user session get');
    loginToken = 'SYNTHETIC-other-session';
    await execute('user login', login);
    loginToken = issued;
    await configure({ token: { stored: true } });
    vendors.responders.set('/api/user/logout', () => ({ body: { status: 'ok' } }));
    const result = await execute('auth logout', {});
    assert.equal(result.result.localRemoved, true);
    assert.equal(JSON.parse(await readFile(join(env.XDG_STATE_HOME, 'technitium-axi', 'credentials.json'), 'utf8'))['other-profile'].token, 'SYNTHETIC-other-session');
    await failure('AUTH_REQUIRED', 'user session get');
    vendors.tokens.set('alpha', token);
  }
  if (['B5.01', 'B5.CR-007'].includes(task)) {
    for (const [, command, , parameters] of operations.filter(([id]) => ['003', '004', '008', '009', '010', '011', '013'].includes(id))) {
      await configure({ tokenKind: 'api' });
      const before = vendors.traces.length;
      await failure('TOKEN_KIND', `user ${command}`, parameters);
      assert.equal(vendors.traces.length, before);
    }
  }
  if (['B5.01', 'B5.CR-009'].includes(task)) {
    await configure();
    const before = vendors.traces.length;
    await failure('USAGE', 'user change-password', { pass: { env: 'ACCOUNT_PASS' }, newPass: password });
    await failure('USAGE', 'user change-password', { pass: { env: 'ACCOUNT_PASS' }, newPass: { env: 'ACCOUNT_PASS' } }, ['--new-pass', password]);
    assert.equal(vendors.traces.length, before);
    await execute('user change-password', operations.find(([id]) => id === '008')[3]);
    assert.equal(changed.get('008').newPass, password);
    vendors.responders.set('/api/admin/users/set', (_incoming, bytes) => {
      assert.deepEqual(Object.fromEntries(new URLSearchParams(bytes.toString())), { user: 'planner', newPass: password, totpEnabled: 'false' });
      return { body: { status: 'ok' } };
    });
    const admin = { user: 'planner', newPass: { env: 'ACCOUNT_PASS' }, totpEnabled: false };
    await failure('USAGE', 'admin user set', { ...admin, newPass: password });
    await execute('admin user set', admin);
  }
  if (task === 'B5.01') {
    await configure();
    const seeds = JSON.parse(await readFile(new URL('../tests/fixtures/read-seeds.json', import.meta.url), 'utf8')).responses;
    // Regression for issue #10: the vendor omits a User-Agent as null and permits reservation comments to be null.
    for (const [id, command, path, key, field, flags] of [
      ['OP-012', 'user profile get', '/api/user/profile/get', 'sessions', 'lastSeenUserAgent', []],
      ['OP-098', 'admin session list', '/api/admin/sessions/list', 'sessions', 'lastSeenUserAgent', []],
      ['OP-103', 'admin user get', '/api/admin/users/get', 'sessions', 'lastSeenUserAgent', ['--user', 'planner']],
      ['OP-091', 'dhcp scope get', '/api/dhcp/scopes/get', 'reservedLeases', 'comments', ['--name', 'scope']],
    ]) {
      const response = structuredClone(seeds[id]);
      response[key][0][field] = null;
      vendors.responders.set(path, () => ({ body: { status: 'ok', response } }));
      const result = await success(command, undefined, [...flags, '--full']);
      assert.equal(result.response[key][0][field], null);
      response[key][0][field] = false;
      await failure('UPSTREAM_INVALID', command, undefined, flags);
    }
  }
  if (task === 'B5.CR-007') return;
  const journal = join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d');
  for (const file of await readdir(journal)) {
    const bytes = await readFile(join(journal, file), 'utf8');
    for (const value of [token, issued, password, totp, secret]) for (const form of [value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value), Buffer.from(value).toString('base64')]) assert.ok(!bytes.includes(form));
  }
}
