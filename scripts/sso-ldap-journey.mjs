import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

// Synthetic inputs and wire expectations from the pinned WebServiceAuthApi handlers.
const cases = [
  ['115', 'sso', {
    ssoClientId: 'new', ssoAllowSignup: false, ssoScopes: ['openid', 'profile', 'email'], ssoClientSecret: { env: 'OPERATION_SECRET' },
  }, { ssoClientId: 'new', ssoAllowSignup: 'false', ssoScopes: 'openid|profile|email' }],
  ['142', 'ldap', {
    ldapEnabled: true, ldapServer: 'ldap2.example.test', ldapPort: 636, ldapSslOption: 'LDAPS', ldapIgnoreSslErrors: false,
    ldapBindUsername: 'bind-user', ldapBindPassword: { env: 'OPERATION_SECRET' }, ldapAllowSignup: false,
    ldapAllowSignupOnlyForMappedUsers: false, ldapGroupMap: [{ remoteGroup: 'group-b', localGroup: 'Keepers' }],
  }, { ldapEnabled: 'true', ldapServer: 'ldap2.example.test', ldapPort: '636', ldapSslOption: 'LDAPS', ldapIgnoreSslErrors: 'false',
    ldapBindUsername: 'bind-user', ldapAllowSignup: 'false', ldapAllowSignupOnlyForMappedUsers: 'false', ldapGroupMap: 'group-b|Keepers' }],
];
export const ssoLdapTasks = ['B5.sso-ldap', ...['115', '142', '143'].map(id => `B5.OP-${id}`)];

export async function ssoLdapJourney({ task, env, run, executable, vendors, config, token, secret, configure, success, failure, execute }) {
  const initial = {
    sso: { ssoEnabled: true, ssoAuthority: 'https://id.example.test', ssoClientId: 'old', ssoClientSecret: 'old-sso-secret',
      ssoMetadataAddress: null, ssoScopes: ['openid'], ssoAllowSignup: true, ssoAllowSignupOnlyForMappedUsers: true,
      ssoGroupMap: [{ remoteGroup: 'group-a', localGroup: 'Operators' }] },
    ldap: { ldapEnabled: false, ldapServer: 'ldap.example.test', ldapPort: 389, ldapSslOption: 'StartTLS', ldapIgnoreSslErrors: true,
      ldapBindUsername: 'old-bind', ldapBindPassword: secret, ldapSearchBase: 'dc=example,dc=test',
      ldapUserSearchFilter: '(uid={0})', ldapGroupAttribute: 'memberOf', ldapAllowSignup: true, ldapAllowSignupOnlyForMappedUsers: true,
      ldapGroupMap: [{ remoteGroup: 'group-a', localGroup: 'Operators' }] },
  };
  let state = structuredClone(initial);
  let drop = false;
  const ok = response => ({ body: { status: 'ok', ...(response ? { response } : {}) } });
  const masked = kind => ({ ...state[kind], [kind === 'sso' ? 'ssoClientSecret' : 'ldapBindPassword']: '************' });
  const read = async kind => {
    const result = await run(executable, ['admin', kind, 'get', '--config', config, '--json', '--full'], { env: { ...env, WRITE_TOKEN: token } });
    assert.equal(result.code, 0, result.stdout);
    assert.equal(result.stderr, '');
    assert.ok(!result.stdout.includes(secret), result.stdout);
    return JSON.parse(result.stdout).response;
  };
  for (const kind of ['sso', 'ldap']) vendors.responders.set(`/api/admin/${kind}/get`, () => ok(masked(kind)));
  for (const [id, kind, , wire] of cases) vendors.responders.set(`/api/admin/${kind}/set`, (incoming, bytes) => {
    assert.equal(incoming.headers.authorization, `Bearer ${token}`);
    assert.equal(incoming.headers['content-type'], 'application/x-www-form-urlencoded');
    const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
    const secretKey = kind === 'sso' ? 'ssoClientSecret' : 'ldapBindPassword';
    assert.deepEqual(p, { ...wire, [secretKey]: secret });
    for (const [key, value] of Object.entries(p)) {
      if (key === 'ssoScopes') state[kind][key] = value.split('|');
      else if (key.endsWith('GroupMap')) {
        const parts = value.split('|');
        state[kind][key] = Array.from({ length: parts.length / 2 }, (_, i) => ({ remoteGroup: parts[i * 2], localGroup: parts[i * 2 + 1] }));
      } else state[kind][key] = typeof initial[kind][key] === 'boolean' ? value === 'true' : key === 'ldapPort' ? Number(value) : value;
    }
    if (drop) { incoming.socket.destroy(); return {}; }
    return ok(masked(kind));
  });
  for (const [id, kind, parameters] of cases.filter(([id]) => task === 'B5.sso-ldap' || task === `B5.OP-${id}`)) {
    state = structuredClone(initial);
    await configure([`OP-${id}`]);
    const input = { parameters };
    await execute(`admin ${kind} set`, input);
    const { [kind === 'sso' ? 'ssoClientSecret' : 'ldapBindPassword']: ref, ...publicFields } = parameters;
    const expected = { ...initial[kind], ...publicFields };
    delete expected[kind === 'sso' ? 'ssoClientSecret' : 'ldapBindPassword'];
    assert.deepEqual(await read(kind), expected);
    assert.equal(state[kind][kind === 'sso' ? 'ssoClientSecret' : 'ldapBindPassword'], secret);
    assert.deepEqual(state[kind === 'sso' ? 'ldap' : 'sso'], initial[kind === 'sso' ? 'ldap' : 'sso']);
    const before = vendors.traces.length;
    const key = kind === 'sso' ? 'ssoClientSecret' : 'ldapBindPassword';
    await failure('USAGE', `admin ${kind} set`, { parameters: { ...parameters, [key]: secret } });
    await failure('USAGE', `admin ${kind} set`, input, [], { OPERATION_SECRET: '************' });
    assert.equal(vendors.traces.length, before, 'Inline secrets and masked sentinels must fail before dispatch');
    if (kind === 'sso') {
      state = structuredClone(initial);
      drop = true;
      const preview = await success('admin sso set', input);
      await failure('OUTCOME_UNKNOWN', 'admin sso set', input, ['--execute', '--confirm', preview.preview.digest]);
      drop = false;
      assert.deepEqual(await read('sso'), expected);
      await failure('REPLAY_DENIED', 'admin sso set', input, ['--execute', '--confirm', preview.preview.digest]);
    }
  }
  if (['B5.sso-ldap', 'B5.OP-143'].includes(task)) {
    state = structuredClone(initial);
    await configure(['OP-143']);
    const binds = [];
    let expectedWire = {};
    vendors.responders.set('/api/admin/ldap/test', (incoming, bytes) => {
      assert.equal(incoming.headers.authorization, `Bearer ${token}`);
      const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
      assert.deepEqual(p, expectedWire);
      const selected = { ...state.ldap, ...p };
      binds.push({ server: selected.ldapServer, username: selected.ldapBindUsername, password: selected.ldapBindPassword });
      return selected.ldapBindPassword === secret ? ok() : { body: { status: 'error', errorMessage: 'Invalid bind credentials.' } };
    });
    const override = { ldapServer: 'override.example.test', ldapPort: 636, ldapSslOption: 'LDAPS', ldapIgnoreSslErrors: false,
      ldapBindUsername: 'override-bind', ldapBindPassword: { env: 'OPERATION_SECRET' } };
    for (const parameters of [{}, override]) {
      expectedWire = parameters === override ? { ldapServer: 'override.example.test', ldapPort: '636', ldapSslOption: 'LDAPS',
        ldapIgnoreSslErrors: 'false', ldapBindUsername: 'override-bind', ldapBindPassword: secret } : {};
      const before = binds.length;
      await execute('admin ldap test', { parameters });
      assert.deepEqual(binds.slice(before), [{ server: parameters.ldapServer ?? initial.ldap.ldapServer,
        username: parameters.ldapBindUsername ?? initial.ldap.ldapBindUsername, password: secret }]);
    }
    expectedWire = { ...expectedWire, ldapBindPassword: 'wrong-bind' };
    const preview = await success('admin ldap test', { parameters: override }, [], { OPERATION_SECRET: 'wrong-bind' });
    const refused = await failure('UPSTREAM_ERROR', 'admin ldap test', { parameters: override }, ['--execute', '--confirm', preview.preview.digest], { OPERATION_SECRET: 'wrong-bind' });
    assert.match(refused.error.message, /audit ID [a-f0-9-]+/);
    const receipt = JSON.parse(await readFile(join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d', `${preview.preview.digest}.json`), 'utf8'));
    assert.equal(receipt.state, 'failed');
    assert.deepEqual(state, initial, 'Connection tests must not save configuration');
    for (const [grants, extraEnv] of [[[], {}], [['OP-142'], {}], [['OP-143'], { TECHNITIUM_AXI_READ_ONLY: '1' }]]) {
      await configure(grants);
      const input = { parameters: {} };
      const denied = await success('admin ldap test', input, [], extraEnv);
      const before = binds.length;
      await failure('WRITE_DENIED', 'admin ldap test', input, ['--execute', '--confirm', denied.preview.digest], extraEnv);
      assert.equal(binds.length, before, 'Denied outbound authentication must not bind');
    }
  }
  const journal = join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d');
  for (const file of await readdir(journal)) {
    const bytes = await readFile(join(journal, file), 'utf8');
    for (const value of [token, secret]) for (const form of [value, encodeURIComponent(value), JSON.stringify(value).slice(1, -1), Buffer.from(value).toString('base64')]) assert.ok(!bytes.includes(form));
  }
}
