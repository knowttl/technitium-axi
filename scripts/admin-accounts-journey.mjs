import assert from 'node:assert/strict';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

// Synthetic cases from the pinned vendor Administration API contract.
const reader = { username: 'reader', canView: true, canModify: false, canDelete: false };
const admin = { name: 'Administrators', canView: true, canModify: true, canDelete: true };
const cases = [
  ['099', 'session create-token', 'sessions/createToken', { user: 'service-user', tokenName: 'automation-2' }],
  ['100', 'session delete', 'sessions/delete', { node: 'selected-node', partialToken: '2222222222222222' }],
  ['102', 'user create', 'users/create', { user: 'new-user', displayName: 'New User', pass: { env: 'ADMIN_PASSWORD' } }],
  ['104', 'user set', 'users/set', { user: 'new-user', newUser: 'renamed-user', displayName: 'Renamed', totpEnabled: false, disabled: false, newPass: { env: 'ADMIN_PASSWORD' }, memberOfGroups: ['Operators'] }],
  ['105', 'user delete', 'users/delete', { user: 'delete-user' }],
  ['107', 'group create', 'groups/create', { group: 'NewGroup', description: 'New DNS group' }],
  ['109', 'group set', 'groups/set', { group: 'Operators', newGroup: 'Operators2', description: 'updated', members: ['planner', 'keep-user'] }, { newGroup: 'Operators', description: 'old', members: ['planner'] }],
  ['110', 'group delete', 'groups/delete', { group: 'DeleteGroup' }],
  ['113', 'permission set', 'permissions/set', { section: 'Dashboard', userPermissions: [{ ...reader, canModify: true }], groupPermissions: [admin] }, { userPermissions: [reader], groupPermissions: [admin] }],
];
export const adminAccountsTasks = ['B5.admin-accounts', ...cases.map(([id]) => `B5.OP-${id}`)];

export async function adminAccountsJourney({ task, temporary, env, run, executable, vendors }) {
  const directory = join(temporary, 'admin-accounts');
  await mkdir(directory, { mode: 0o700 });
  const config = join(directory, 'config.json');
  const token = 'SYNTHETIC-admin-bearer';
  const issued = 'SYNTHETIC-admin-issued';
  const password = 'SYNTHETIC-admin-password-"/+=';
  const seeds = JSON.parse(await readFile(new URL('../tests/fixtures/read-seeds.json', import.meta.url), 'utf8')).responses;
  const profile = { origin: vendors.origins[0], auth: 'token', tokenKind: 'api', username: 'planner', token: { env: 'ADMIN_TOKEN' }, caFile: vendors.caFile, tlsServerName: 'localhost',
    writes: { allowWrites: true, operations: [...cases.map(([id]) => `OP-${id}`), 'OP-002'] } };
  const configure = async (changes = {}) => writeFile(config, JSON.stringify({ version: 1, profiles: { alpha: { ...profile, ...changes } } }), { mode: 0o600 });
  await configure();
  vendors.tokens.set('alpha', token);
  vendors.tokens.set('beta', token);
  let sequence = 0;
  const invoke = async (command, input, flags = [], extraEnv = {}) => {
    const file = join(directory, `input-${sequence++}.json`);
    if (input) await writeFile(file, JSON.stringify(input), { mode: 0o600 });
    const result = await run(executable, [...command.split(' '), '--config', config, '--json', ...(input ? ['--input-file', file] : []), ...flags],
      { env: { ...env, ADMIN_TOKEN: token, ADMIN_PASSWORD: password, ...extraEnv } });
    assert.equal(result.stderr, '', result.stderr);
    for (const secret of [token, issued, password]) for (const form of [secret, JSON.stringify(secret).slice(1, -1), encodeURIComponent(secret), Buffer.from(secret).toString('base64')]) assert.ok(!result.stdout.includes(form), result.stdout);
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
  const execute = async (command, input, flags = []) => {
    const preview = await success(command, input);
    return success(command, input, ['--execute', '--confirm', preview.preview.digest, ...flags]);
  };
  const read = async (command, flags = []) => (await success(`admin ${command}`, undefined, [...flags, '--full'])).response;
  const authenticate = async (partialToken, allowed, origin = vendors.origins[0]) => {
    const credential = `${partialToken}-synthetic-session`;
    const identity = origin === vendors.origins[0] ? 'alpha' : 'beta';
    vendors.tokens.set(identity, credential);
    await configure({ origin, tokenKind: 'session' });
    if (allowed) await success('user session get', undefined, [], { ADMIN_TOKEN: credential });
    else await failure('AUTH_REQUIRED', 'user session get', undefined, [], { ADMIN_TOKEN: credential });
    vendors.tokens.set(identity, token);
    await configure();
  };
  const user = (username, displayName = username) => ({ ...structuredClone(seeds['OP-103']), username, displayName, isSsoUser: false, disabled: false, totpEnabled: true, memberOfGroups: [], sessions: [] });
  const session = (username, partialToken, tokenName = null) => ({ ...structuredClone(seeds['OP-098'].sessions[0]), username, partialToken, isCurrentSession: false, tokenName, type: tokenName ? 'ApiToken' : 'Standard' });
  let users, groups, permissions, sessions, passwords;
  let deny = false;
  const reset = () => {
    users = new Map(['planner', 'service-user', 'new-user', 'delete-user', 'keep-user', 'reader'].map(name => [name, user(name)]));
    users.get('planner').memberOfGroups = ['Operators'];
    users.get('keep-user').memberOfGroups = ['Keepers'];
    users.get('delete-user').memberOfGroups = ['DeleteGroup'];
    groups = new Map([
      ['Operators', { name: 'Operators', description: 'old', members: ['planner'] }],
      ['DeleteGroup', { name: 'DeleteGroup', description: 'delete', members: ['delete-user'] }],
      ['Keepers', { name: 'Keepers', description: 'keep', members: ['keep-user'] }],
    ]);
    permissions = new Map([
      ['Dashboard', { section: 'Dashboard', userPermissions: [reader], groupPermissions: [admin] }],
      ['Zones', { section: 'Zones', userPermissions: [], groupPermissions: [{ name: 'DeleteGroup', canView: true, canModify: false, canDelete: false }] }],
    ]);
    sessions = new Map([
      ['selected-node', [session('planner', '1111111111111111'), session('delete-user', '2222222222222222'), session('keep-user', '3333333333333333')]],
      ['other-node', [session('keep-user', '2222222222222222')]],
    ]);
    passwords = new Map();
    deny = false;
  };
  const ok = response => ({ body: { status: 'ok', response } });
  const rejected = () => ({ body: { status: 'error', errorMessage: 'Access denied or invalid target.' } });
  for (const [path, select] of [
    ['users/get', p => users.get(p.user)], ['users/list', () => ({ users: [...users.values()] })],
    ['groups/get', p => groups.get(p.group)], ['groups/list', () => ({ groups: [...groups.values()] })],
    ['sessions/list', p => ({ sessions: sessions.get(p.node ?? 'selected-node') })],
    ['permissions/get', p => permissions.get(p.section)],
  ]) vendors.responders.set(`/api/admin/${path}`, (_incoming, bytes) => {
    const response = select(Object.fromEntries(new URLSearchParams(bytes.toString())));
    return response ? ok(response) : rejected();
  });
  vendors.responders.set('/api/user/login', (_incoming, bytes) => {
    const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
    return passwords.get(p.user) === p.pass ? { body: { status: 'ok', username: p.user, token: issued, info: { permissions: {} } } } : rejected();
  });
  vendors.responders.set('/api/user/session/get', incoming => {
    const credential = incoming.headers.authorization.slice(7);
    const node = incoming.socket.localPort === Number(new URL(vendors.origins[0]).port) ? 'selected-node' : 'other-node';
    const selected = sessions.get(node).find(row => credential.startsWith(row.partialToken));
    return selected ? { body: { status: 'ok', username: selected.username, token: credential, ...(selected.tokenName ? { tokenName: selected.tokenName } : {}), info: { version: '15.4', permissions: {} } } } : { body: { status: 'invalid-token' } };
  });
  const parsePermissions = (text, name) => {
    if (!text) return [];
    const parts = text.split('|');
    return Array.from({ length: parts.length / 4 }, (_, i) => ({ [name]: parts[i * 4], canView: parts[i * 4 + 1] === 'true', canModify: parts[i * 4 + 2] === 'true', canDelete: parts[i * 4 + 3] === 'true' }));
  };
  for (const [id, , path] of cases) vendors.responders.set(`/api/admin/${path}`, (incoming, bytes) => {
    assert.equal(incoming.headers.authorization, `Bearer ${token}`);
    assert.equal(incoming.headers['content-type'], 'application/x-www-form-urlencoded');
    const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
    assert.ok(!Object.hasOwn(p, 'token'));
    if (deny || id === '113' && incoming.socket.localPort === Number(new URL(vendors.origins[1]).port)) return rejected();
    if (id === '099') {
      sessions.get('selected-node').push(session(p.user, issued.slice(0, 16), p.tokenName));
      return ok({ username: p.user, tokenName: p.tokenName, token: issued });
    }
    if (id === '100') {
      if (p.partialToken.length !== 16) return rejected();
      sessions.set(p.node, sessions.get(p.node).filter(row => row.partialToken !== p.partialToken));
    }
    if (id === '102') {
      if (users.has(p.user)) return rejected();
      users.set(p.user, { ...user(p.user, p.displayName), totpEnabled: false });
      passwords.set(p.user, p.pass);
    }
    if (id === '104') {
      const previous = users.get(p.user);
      users.delete(p.user);
      users.set(p.newUser, { ...previous, username: p.newUser, displayName: p.displayName, disabled: p.disabled === 'true', totpEnabled: p.totpEnabled === 'true', memberOfGroups: p.memberOfGroups.split(',') });
      for (const group of groups.values()) {
        group.members = group.members.filter(name => name !== p.user);
        if (p.memberOfGroups.split(',').includes(group.name)) group.members.push(p.newUser);
        group.members.sort();
      }
      passwords.set(p.newUser, p.newPass);
    }
    if (id === '105') {
      if (p.user === 'planner') return rejected();
      users.delete(p.user);
      for (const [node, rows] of sessions) sessions.set(node, rows.filter(row => row.username !== p.user));
      for (const group of groups.values()) group.members = group.members.filter(name => name !== p.user);
    }
    if (id === '107') {
      if (groups.has(p.group)) return rejected();
      groups.set(p.group, { name: p.group, description: p.description, members: [] });
    }
    if (id === '109') {
      const members = p.members.split(',').map(name => name.toLowerCase());
      // Vendor Dictionary.Add rejects repeated canonical usernames before synchronizing members.
      if (new Set(members).size !== members.length) return rejected();
      const previous = groups.get(p.group);
      groups.delete(p.group);
      groups.set(p.newGroup ?? p.group, { ...previous, name: p.newGroup ?? p.group, description: p.description ?? previous.description, members: members.sort() });
      for (const value of users.values()) {
        value.memberOfGroups = value.memberOfGroups.filter(name => name !== p.group);
        if (members.includes(value.username)) value.memberOfGroups.push(p.newGroup ?? p.group);
        value.memberOfGroups.sort();
      }
    }
    if (id === '110') {
      if (p.group === 'Administrators') return rejected();
      groups.delete(p.group);
      for (const value of users.values()) value.memberOfGroups = value.memberOfGroups.filter(name => name !== p.group);
      for (const value of permissions.values()) value.groupPermissions = value.groupPermissions.filter(row => row.name !== p.group);
    }
    if (id === '113') {
      const value = permissions.get(p.section);
      if (p.userPermissions !== undefined) value.userPermissions = parsePermissions(p.userPermissions, 'username');
      if (p.groupPermissions !== undefined) value.groupPermissions = [...parsePermissions(p.groupPermissions, 'name').filter(row => row.name !== 'Administrators'), admin];
    }
    return ok({});
  });
  for (const [id, command, , parameters, baseline] of cases.filter(([id]) => task === 'B5.admin-accounts' || task === `B5.OP-${id}`)) {
    reset();
    if (id === '102') users.delete('new-user');
    if (id === '104') {
      users.get('new-user').memberOfGroups = ['Operators'];
      groups.get('Operators').members.push('new-user');
    }
    const input = { parameters, ...(baseline ? { baseline } : {}) };
    const fullCommand = `admin ${command}`;
    const destination = join(directory, `result-${id}.json`);
    if (id === '099') {
      const preview = await success(fullCommand, input);
      const before = vendors.traces.length;
      await failure('USAGE', fullCommand, input, ['--execute', '--confirm', preview.preview.digest]);
      assert.equal(vendors.traces.length, before, 'Missing token custody must fail before dispatch');
    }
    await execute(fullCommand, input, id === '099' ? ['--result-file', destination] : []);
    assert.deepEqual(await read('user get', ['--user', 'keep-user']), { ...user('keep-user'), memberOfGroups: id === '109' ? ['Keepers', 'Operators2'] : ['Keepers'] });
    assert.deepEqual(await read('group get', ['--group', 'Keepers']), { name: 'Keepers', description: 'keep', members: ['keep-user'] });
    if (id === '099') {
      assert.equal((await stat(destination)).mode & 0o777, 0o600);
      assert.deepEqual(JSON.parse(await readFile(destination, 'utf8')).response, { username: 'service-user', tokenName: 'automation-2', token: issued });
      assert.deepEqual((await read('session list')).sessions.filter(row => row.tokenName === 'automation-2'), [session('service-user', issued.slice(0, 16), 'automation-2')]);
      vendors.tokens.set('alpha', issued);
      await success('user session get', undefined, [], { ADMIN_TOKEN: issued });
      vendors.tokens.set('alpha', token);
    }
    if (id === '100') {
      assert.deepEqual((await read('session list', ['--node', 'selected-node'])).sessions.map(row => row.partialToken), ['1111111111111111', '3333333333333333']);
      assert.deepEqual((await read('session list', ['--node', 'other-node'])).sessions.map(row => row.partialToken), ['2222222222222222']);
      await authenticate('2222222222222222', false);
      await authenticate('1111111111111111', true);
      await authenticate('3333333333333333', true);
      await authenticate('2222222222222222', true, vendors.origins[1]);
    }
    if (['102', '104'].includes(id)) {
      const name = id === '102' ? 'new-user' : 'renamed-user';
      const value = await read('user get', ['--user', name]);
      assert.deepEqual({ username: value.username, displayName: value.displayName, disabled: value.disabled, isSsoUser: value.isSsoUser, totpEnabled: value.totpEnabled, memberOfGroups: value.memberOfGroups },
        { username: name, displayName: id === '102' ? 'New User' : 'Renamed', disabled: false, isSsoUser: false, totpEnabled: false, memberOfGroups: id === '102' ? [] : ['Operators'] });
      if (id === '104') assert.ok(!(await read('user list')).users.some(row => row.username === 'new-user'));
      await configure({ username: name, tokenKind: 'session' });
      await execute('user login', { parameters: { user: name, pass: { env: 'ADMIN_PASSWORD' } } });
      await configure();
      const before = vendors.traces.length;
      const key = id === '102' ? 'pass' : 'newPass';
      await failure('USAGE', fullCommand, { parameters: { ...parameters, [key]: password } });
      await failure('USAGE', fullCommand, input, [`--${id === '102' ? 'pass' : 'new-pass'}`, password]);
      assert.equal(vendors.traces.length, before, 'Inline secrets must fail before dispatch');
    }
    if (id === '105') {
      assert.ok(!(await read('user list')).users.some(row => row.username === 'delete-user'));
      assert.deepEqual((await read('group get', ['--group', 'DeleteGroup'])).members, []);
      assert.deepEqual((await read('session list')).sessions.map(row => row.username), ['planner', 'keep-user']);
      await authenticate('2222222222222222', false);
      await authenticate('3333333333333333', true);
    }
    if (id === '107') {
      assert.deepEqual(await read('group get', ['--group', 'NewGroup']), { name: 'NewGroup', description: 'New DNS group', members: [] });
      const preview = await success(fullCommand, input);
      await failure('OUTCOME_UNKNOWN', fullCommand, input, ['--execute', '--confirm', preview.preview.digest]);
      assert.equal((await read('group list')).groups.filter(row => row.name === 'NewGroup').length, 1);
    }
    if (id === '109') {
      assert.deepEqual(await read('group get', ['--group', 'Operators2']), { name: 'Operators2', description: 'updated', members: ['keep-user', 'planner'] });
      assert.ok(!(await read('group list')).groups.some(row => row.name === 'Operators'));
      assert.deepEqual((await read('user get', ['--user', 'planner'])).memberOfGroups, ['Operators2']);
      reset();
      const preview = await success(fullCommand, input);
      groups.get('Operators').members.push('keep-user');
      const before = vendors.traces.filter(row => row.path === '/api/admin/groups/set').length;
      await failure('CONFLICT', fullCommand, input, ['--execute', '--confirm', preview.preview.digest]);
      assert.equal(vendors.traces.filter(row => row.path === '/api/admin/groups/set').length, before);
      reset();
      const duplicate = { parameters: { group: 'Operators', members: ['PLANNER', 'planner'] }, baseline: { members: ['planner'] } };
      const duplicated = await success(fullCommand, duplicate);
      await failure('OUTCOME_UNKNOWN', fullCommand, duplicate, ['--execute', '--confirm', duplicated.preview.digest]);
      assert.deepEqual((await read('group get', ['--group', 'Operators'])).members, ['planner']);
    }
    if (id === '110') {
      assert.ok(!(await read('group list')).groups.some(row => row.name === 'DeleteGroup'));
      assert.deepEqual((await read('user get', ['--user', 'delete-user'])).memberOfGroups, []);
      assert.deepEqual((await read('permission get', ['--section', 'Zones'])).groupPermissions, []);
    }
    if (id === '113') {
      assert.deepEqual(await read('permission get', ['--section', 'Dashboard']), { section: 'Dashboard', userPermissions: [{ ...reader, canModify: true }], groupPermissions: [admin] });
      assert.deepEqual(await read('permission get', ['--section', 'Zones']), { section: 'Zones', userPermissions: [], groupPermissions: [{ name: 'DeleteGroup', canView: true, canModify: false, canDelete: false }] });
      reset();
      await configure({ origin: vendors.origins[1] });
      const preview = await success(fullCommand, input);
      await failure('OUTCOME_UNKNOWN', fullCommand, input, ['--execute', '--confirm', preview.preview.digest]);
      assert.deepEqual((await read('permission get', ['--section', 'Dashboard'])).userPermissions, [reader]);
      await configure();
    }
    // The profile grant does not override the vendor's actual caller authorization.
    if (!['102', '104', '107', '109'].includes(id)) {
      reset();
      deny = true;
      const preview = await success(fullCommand, input);
      await failure('OUTCOME_UNKNOWN', fullCommand, input, ['--execute', '--confirm', preview.preview.digest, ...(id === '099' ? ['--result-file', destination] : [])]);
      assert.deepEqual((await read('session list')).sessions.map(row => row.partialToken), ['1111111111111111', '2222222222222222', '3333333333333333']);
      assert.ok((await read('user list')).users.some(row => row.username === 'delete-user'));
      assert.ok((await read('group list')).groups.some(row => row.name === 'DeleteGroup'));
      assert.deepEqual((await read('permission get', ['--section', 'Dashboard'])).userPermissions, [reader]);
    }
  }
  for (const file of await readdir(join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d'))) {
    const bytes = await readFile(join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d', file), 'utf8');
    for (const secret of [token, issued, password]) assert.ok(!bytes.includes(secret));
  }
}
