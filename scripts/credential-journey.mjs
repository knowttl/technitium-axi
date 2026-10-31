import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export const credentialTasks = {
  'B1.03': ['selection', 'invalid', 'refs', 'isolation', 'noninteractive'],
  'B1.04': ['insecure', 'atomic', 'tls', 'insecure-ca', 'relative-ca', 'result'],
  'B1.CR-001': ['selection'], 'B1.CR-002': ['invalid'], 'B1.CR-003': ['refs'],
  'B1.CR-004': ['insecure'], 'B1.CR-005': ['atomic'], 'B1.CR-008': ['isolation'],
  'B1.CR-011': ['tls', 'insecure-ca', 'relative-ca'], 'B1.CR-012': ['noninteractive'],
  'B1.OP-001': ['status'], 'B1.OP-006': ['session', 'login-session', 'single-use-session'],
};
const hash = value => createHash('sha256').update(value).digest('hex');

export async function credentialJourney({ task, temporary, env, run, executable, vendors }) {
  const directory = join(temporary, 'credentials');
  await mkdir(directory, { mode: 0o700 });
  const config = join(directory, 'config.json');
  const token = 'SYNTHETIC-alpha-"/+=canary';
  const other = 'SYNTHETIC-beta-canary';
  vendors.tokens.set('alpha', token);
  vendors.tokens.set('beta', other);
  const profile = (index = 0) => ({ origin: vendors.origins[index], auth: 'token', tokenKind: 'api',
    token: { env: index === 0 ? 'SYNTHETIC_ALPHA' : 'SYNTHETIC_BETA' }, caFile: vendors.caFile, tlsServerName: 'localhost' });
  const seeded = { version: 1, defaultProfile: 'alpha', profiles: { alpha: profile(), beta: profile(1) } };
  const base = { ...env, SYNTHETIC_ALPHA: token, SYNTHETIC_BETA: other };
  const writeConfig = async value => writeFile(config, JSON.stringify(value), { mode: 0o600 });
  await writeConfig(seeded);
  const invoke = async (args, extra = {}, selectedConfig = config) => {
    const result = await run(executable, [...args, '--json', ...(selectedConfig ? ['--config', selectedConfig] : [])],
      { cwd: directory, env: { ...base, ...extra } });
    for (const value of [token, JSON.stringify(token).slice(1, -1), encodeURIComponent(token), other]) {
      assert.ok(!`${result.stdout}${result.stderr}`.includes(value), 'Credential escaped into ordinary output');
    }
    assert.equal(result.stderr, '');
    return { ...result, value: JSON.parse(result.stdout) };
  };
  const ok = async (...args) => {
    const result = await invoke(...args);
    assert.equal(result.code, 0, result.stdout);
    return result.value;
  };
  const reject = async (args, code, extra) => {
    const count = vendors.traces.length;
    const result = await invoke(args, extra);
    assert.notEqual(result.code, 0, result.stdout);
    assert.equal(result.value.error.code, code);
    assert.equal(vendors.traces.length, count, 'Invalid input reached a vendor');
  };
  const environment = { TECHNITIUM_AXI_ORIGIN: vendors.origins[1], TECHNITIUM_AXI_AUTH: 'token',
    TECHNITIUM_AXI_TOKEN_KIND: 'api', TECHNITIUM_AXI_TOKEN: other, TECHNITIUM_AXI_CA_FILE: vendors.caFile };
  const session = ['user', 'session', 'get'];
  const tests = {
    async selection() {
      const selected = await ok(['auth', 'status', '--profile', 'alpha'], { ...environment, TECHNITIUM_AXI_PROFILE: 'beta' });
      assert.deepEqual(selected, { profile: 'alpha', source: 'flag', origin: vendors.origins[0], tokenKind: 'api', tokenSource: { env: 'SYNTHETIC_ALPHA' } });
      assert.equal((await ok(['auth', 'status'], { TECHNITIUM_AXI_PROFILE: 'beta' })).profile, 'beta');
      assert.equal((await ok(['auth', 'status'], environment)).source, 'environment');
      assert.equal((await ok(['auth', 'status'])).source, 'default');
      await writeConfig({ version: 1, profiles: { alpha: profile() } });
      assert.equal((await ok(['auth', 'status'])).source, 'sole');
      const alternate = join(directory, 'alternate.json');
      await writeFile(alternate, JSON.stringify({ version: 1, profiles: { beta: profile(1) } }), { mode: 0o600 });
      assert.equal((await ok(['auth', 'status'], { TECHNITIUM_AXI_CONFIG: alternate })).profile, 'alpha');
      assert.equal((await ok(['auth', 'status'], { TECHNITIUM_AXI_CONFIG: alternate }, null)).profile, 'beta');
      const defaultPath = join(env.XDG_CONFIG_HOME, 'technitium-axi');
      await mkdir(defaultPath, { recursive: true, mode: 0o700 });
      await writeFile(join(defaultPath, 'config.json'), JSON.stringify(seeded), { mode: 0o600 });
      assert.equal((await ok(['auth', 'status'], {}, null)).profile, 'alpha');
      await writeConfig(seeded);
    },
    async invalid() {
      for (const configValue of [
        { ...seeded, unknown: true },
        { ...seeded, profiles: { alpha: { ...profile(), token: token } } },
        { ...seeded, profiles: { alpha: { ...profile(), token: { env: 'BAD-NAME' } } } },
      ]) {
        await writeConfig(configValue);
        await reject(['status'], 'CONFIG_INVALID');
      }
      await writeConfig(seeded);
      await reject(['status'], 'CONFIG_INVALID', { TECHNITIUM_AXI_ORIGIN: vendors.origins[0] });
      await reject(['status', '--profile', 'missing'], 'PROFILE_NOT_FOUND');
      await reject([...session, '--token=inline-canary'], 'USAGE');
    },
    async refs() {
      await ok(session);
      assert.equal(vendors.traces.at(-1).bearerHash, hash(token));
      const secretFile = join(directory, 'token');
      await writeFile(secretFile, '\uFEFF' + token + '\r\n', { mode: 0o600 });
      await writeConfig({ ...seeded, profiles: { alpha: { ...profile(), token: { file: secretFile } } } });
      await ok(session);
      assert.equal(vendors.traces.at(-1).bearerHash, hash(token));
      await writeConfig(seeded);
    },
    async insecure() {
      const secretFile = join(directory, 'insecure-token');
      await writeFile(secretFile, token, { mode: 0o644 });
      await writeConfig({ ...seeded, profiles: { alpha: { ...profile(), token: { file: secretFile } } } });
      await reject(session, 'CONFIG_INSECURE');
      await chmod(secretFile, 0o600);
      const linked = join(directory, 'linked-token');
      await symlink(secretFile, linked);
      await writeConfig({ ...seeded, profiles: { alpha: { ...profile(), token: { file: linked } } } });
      await reject(session, 'CONFIG_INSECURE');
      await writeConfig(seeded);
      await chmod(config, 0o666);
      await reject(['status'], 'CONFIG_INSECURE');
      await chmod(config, 0o600);
      const storedDirectory = join(env.XDG_STATE_HOME, 'technitium-axi');
      await mkdir(storedDirectory, { recursive: true, mode: 0o700 });
      const storedFile = join(storedDirectory, 'credentials.json');
      await writeFile(storedFile, '{}', { mode: 0o644 });
      await writeConfig({ ...seeded, profiles: { alpha: { ...profile(), token: { stored: true } } } });
      await reject(session, 'CONFIG_INSECURE');
      await writeConfig(seeded);
    },
    async atomic() {
      const input = join(directory, 'import.json');
      await writeFile(input, JSON.stringify(seeded), { mode: 0o600 });
      const target = join(directory, 'protected', 'config.json');
      await ok(['config', 'import', '--input-file', input], {}, target);
      assert.equal((await stat(target)).mode & 0o777, 0o600);
      assert.equal((await stat(join(directory, 'protected'))).mode & 0o777, 0o700);
      const before = await readFile(target);
      // Inject process interruption at the real libc file boundary, outside the product.
      const source = join(directory, 'interrupt.c');
      const library = join(directory, 'interrupt.so');
      await writeFile(source, '#define _GNU_SOURCE\n#include <dlfcn.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n#include <fcntl.h>\n#include <stdarg.h>\nint fsync(int fd) { if (!strcmp(getenv("INTERRUPT_AT"),"fsync")) _exit(86); return ((int(*)(int))dlsym(RTLD_NEXT,"fsync"))(fd); }\nint rename(const char*a,const char*b) { if (!strcmp(getenv("INTERRUPT_AT"),"replace") && strstr(a,".tmp")) _exit(86); return ((int(*)(const char*,const char*))dlsym(RTLD_NEXT,"rename"))(a,b); }\nint open64(const char*p,int f,...) { mode_t m=0; if(f & O_CREAT) { va_list v; va_start(v,f); m=va_arg(v,int); va_end(v); } int fd=((int(*)(const char*,int,...))dlsym(RTLD_NEXT,"open64"))(p,f,m); if (strstr(p,".tmp") && !strcmp(getenv("INTERRUPT_AT"),"create")) _exit(86); return fd; }\n');
      const built = await run('cc', ['-shared', '-fPIC', '-o', library, source, '-ldl'], { env: base });
      assert.equal(built.code, 0, built.stderr);
      for (const boundary of ['create', 'fsync', 'replace']) {
        const result = await run(executable, ['config', 'import', '--input-file', input, '--config', target],
          { env: { ...base, LD_PRELOAD: library, INTERRUPT_AT: boundary } });
        assert.equal(result.code, 86, `Interruption did not reach ${boundary}: ${result.stdout}${result.stderr}`);
        assert.deepEqual(await readFile(target), before);
      }
      await ok(['config', 'import', '--input-file', input], {}, target);
      assert.deepEqual(await readFile(target), before);
    },
    async isolation() {
      await writeFile(join(directory, 'technitium-axi.json'), JSON.stringify({ ...seeded, defaultProfile: 'beta' }), { mode: 0o600 });
      await ok([...session, '--profile', 'alpha'], environment);
      assert.equal(vendors.traces.at(-1).identity, 'alpha');
      assert.equal(vendors.traces.at(-1).bearerHash, hash(token));
    },
    async noninteractive() {
      const count = vendors.traces.length;
      await ok(['--help']);
      assert.equal(vendors.traces.length, count);
      await writeConfig({ ...seeded, profiles: { alpha: { ...profile(), token: { env: 'MISSING_TOKEN' } } } });
      await reject(session, 'AUTH_REQUIRED');
      assert.equal((await ok(['status'])).server, 'dns-alpha.example.test');
      assert.equal(vendors.traces.at(-1).bearerHash, null);
      await writeConfig(seeded);
    },
    async tls() {
      await ok(session);
      const count = vendors.traces.length;
      for (const change of [{ tlsServerName: 'wrong.example.test' }, { caFile: undefined }]) {
        await writeConfig({ ...seeded, profiles: { alpha: { ...profile(), ...change } } });
        const result = await invoke(session);
        assert.equal(result.value.error.code, 'TRANSPORT_FAILED');
        assert.equal(vendors.traces.length, count, 'TLS failure sent a credential-bearing HTTP request');
      }
      await writeConfig(seeded);
      await reject(session, 'CONFIG_INVALID', { ...environment, TECHNITIUM_AXI_CA_FILE: 'ca.pem' });
    },
    async 'insecure-ca'() {
      const caFile = join(directory, 'untrusted-ca.pem');
      await writeFile(caFile, await readFile(vendors.caFile), { mode: 0o600 });
      await chmod(caFile, 0o666);
      await writeConfig({ ...seeded, profiles: { alpha: { ...profile(), caFile } } });
      for (const args of [session, ['doctor'], ['status'], []]) await reject(args, 'CONFIG_INSECURE');
      await reject(session, 'CONFIG_INSECURE', { ...environment, TECHNITIUM_AXI_CA_FILE: caFile });
      await writeConfig(seeded);
    },
    async 'relative-ca'() {
      const trusted = join(directory, 'trusted');
      await mkdir(trusted, { mode: 0o700 });
      await writeFile(join(trusted, 'ca.pem'), await readFile(vendors.caFile), { mode: 0o600 });
      const declared = join(trusted, 'config.json');
      await writeFile(declared, JSON.stringify({ ...seeded, profiles: { alpha: { ...profile(), caFile: 'ca.pem' } } }), { mode: 0o600 });
      for (const args of [session, ['doctor']]) assert.equal((await ok(args, {}, declared)).username, 'planner');
      assert.equal((await ok(['status'], {}, declared)).server, 'dns-alpha.example.test');
      const imported = join(directory, 'imported.json');
      await ok(['config', 'import', '--input-file', declared], {}, imported);
      assert.equal((await ok(session, {}, imported)).username, 'planner');
    },
    async result() {
      const destination = join(directory, 'results', 'session.json');
      const value = await ok([...session, '--result-file', destination]);
      assert.equal(value.info.permissions.Administration.canModify, false);
      const bytes = await readFile(destination);
      assert.equal(JSON.parse(bytes).token, token);
      assert.equal(value.result.sha256, hash(bytes));
      assert.equal((await stat(destination)).mode & 0o777, 0o600);
    },
    async status() {
      for (const [name, identity] of [['alpha', 'alpha'], ['beta', 'beta']]) {
        const result = await ok(['status', '--profile', name]);
        assert.deepEqual(result, { status: 'ok', server: `dns-${identity}.example.test`, hasDefaultCredentials: false, ssoEnabled: false });
        assert.equal(vendors.traces.at(-1).identity, identity);
        assert.equal(vendors.traces.at(-1).bearerHash, null);
      }
      assert.equal((await ok([])).server, 'dns-alpha.example.test');
    },
    async session() {
      assert.deepEqual(await ok(session), { status: 'ok', username: 'planner', tokenName: 'automation-1', hasDnssecPrivateKeys: false, info: { version: '15.4', permissions: { Administration: { canModify: false } } } });
      vendors.faults.set('alpha', 'true');
      assert.equal((await invoke(session)).value.error.code, 'UPSTREAM_INVALID');
      vendors.faults.delete('alpha');
      vendors.tokenKinds.set('alpha', 'session');
      assert.equal((await invoke(session)).value.error.code, 'UPSTREAM_INVALID');
      vendors.tokenKinds.delete('alpha');
    },
  };
  for (const [name, tokenKind] of [['login-session', 'session'], ['single-use-session', 'single-use']]) {
    tests[name] = async () => {
      vendors.tokenKinds.set('alpha', tokenKind);
      await writeConfig({ ...seeded, profiles: { alpha: { ...profile(), tokenKind } } });
      const destination = join(directory, 'results', `${tokenKind}.json`);
      const value = await ok([...session, '--result-file', destination]);
      assert.equal(value.username, 'planner');
      assert.equal(Object.hasOwn(value, 'tokenName'), false);
      assert.equal(JSON.parse(await readFile(destination, 'utf8')).token, token);
      assert.equal((await ok(['doctor'])).username, 'planner');
      vendors.tokenKinds.delete('alpha');
      await writeConfig(seeded);
    };
  }
  const checks = [];
  for (const test of credentialTasks[task]) { await tests[test](); checks.push(`native:${test}`); }
  return checks;
}
