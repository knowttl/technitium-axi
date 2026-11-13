import type { SecretWriteContext } from './journey-types.ts';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, readFile, readdir, stat, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import matrix from '../tests/fixtures/configuration-matrix.json' with { type: 'json' };
import { archive } from './read-journey.ts';

interface Settings extends Record<string, unknown> {
  proxy: Record<string, unknown> | null; tsigKeys: { keyName: string; sharedSecret: string; algorithmName: string }[];
  blockListUrls: string[]; forwarders: string[] | null;
}
interface Field { type: string; columns?: string[] }

export const settingsTasks = ['B4.01', 'B4.02', 'B4.03', 'B4.OP-080', 'B4.OP-082', 'B4.OP-083', 'B4.OP-136', 'B4.OP-137'];
const hash = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');

export async function settingsJourney({ task, directory, env, run, executable, vendors, token, secret, configure, success, failure, execute }: SecretWriteContext) {
  if (['B4.01', 'B4.OP-080', 'B4.03'].includes(task)) {
    await configure(['OP-080']);
    const inventory = JSON.parse((await run(executable, ['inventory', '--json'], { env })).stdout);
    const fields: Record<string, Field> = inventory.commands.find((row: { operation: string }) => row.operation === 'OP-080').input.configuration;
    assert.deepEqual(Object.keys(fields).sort(), matrix.settings.map(row => row.parameter).sort());
    assert.deepEqual(inventory.dhcpFields, matrix.dhcp);
    let state: Settings;
    let drop = false;
    let reject = false;
    let writes = 0;
    const initial = (): Settings => ({ defaultRecordTtl: 3600, defaultNsRecordTtl: 14400, enableBlocking: true,
      webServiceTlsCertificatePath: 'web.pfx', webServiceTlsCertificatePassword: '************', dnsTlsCertificatePath: 'dns.pfx', dnsTlsCertificatePassword: '************',
      blockListUrls: [], forwarders: ['192.0.2.1'], forwarderProtocol: 'Tls', proxy: { type: 'Http', address: 'proxy.example.test', port: 8080,
        username: 'operator', password: secret, bypass: ['old.test'] },
      tsigKeys: [{ keyName: 'existing', sharedSecret: secret, algorithmName: 'hmac-sha256' }] });
    const setField = (key: string, value: unknown) => {
      if (['webServiceTlsCertificatePassword', 'dnsTlsCertificatePassword'].includes(key)) value = '************';
      if (key.startsWith('proxy')) state.proxy![key === 'proxyBypass' ? 'bypass' : key.slice(5).toLowerCase()] = value;
      else if (key === 'reverseProxyNetworkACL') state.dnsReverseProxyNetworkACL = value;
      else state[key] = value;
    };
    const getField = (key: string) => key.startsWith('proxy') ? state.proxy![key === 'proxyBypass' ? 'bypass' : key.slice(5).toLowerCase()] : state[key === 'reverseProxyNetworkACL' ? 'dnsReverseProxyNetworkACL' : key];
    vendors.responders.set('/api/settings/get', () => ({ body: { status: 'ok', response: state } }));
    vendors.responders.set('/api/settings/set', (incoming, bytes) => {
      assert.equal(incoming.headers.authorization, `Bearer ${token}`);
      const json = incoming.headers['content-type'] === 'application/json';
      const data = json ? JSON.parse(bytes.toString()) : Object.fromEntries(new URLSearchParams(bytes.toString()));
      assert.ok(!Object.hasOwn(data, 'token'));
      writes++;
      for (const [key, raw] of Object.entries(data)) {
        const field = fields[key];
        let value = raw;
        if (!json) {
          if (field!.type === 'boolean') value = raw === 'true';
          else if (field!.type === 'integer') value = Number(raw);
          else if (field!.type === 'list' || field!.type === 'ports') value = raw === '' ? [] : (raw as string).split(',').map(item => field!.type === 'ports' ? Number(item) : item);
          else if (field!.type === 'rows') {
            const cells = raw === '' ? [] : (raw as string).split('|');
            value = [];
            for (let i = 0; i < cells.length; i += field!.columns!.length) (value as Record<string, unknown>[]).push(Object.fromEntries(field!.columns!.map((column, j) => [column, key.startsWith('qpm') ? Number(cells[i + j]) : cells[i + j]])));
          }
        }
        if (key === 'tsigKeys') value = (value as { keyName: string; sharedSecret: string }[]).map(row => ({ ...row, keyName: row.keyName.toLowerCase().replace(/\.$/, ''), sharedSecret: row.sharedSecret || secret }));
        setField(key, value);
        if (reject) return { body: { status: 'error', response: state } };
      }
      if (drop) { incoming.socket.destroy(); return {}; }
      return { body: { status: 'ok', response: state } };
    });
    const main = { parameters: { defaultRecordTtl: 300, forwarders: ['192.0.2.2'], enableBlocking: false },
      baseline: { defaultRecordTtl: 3600, forwarders: ['192.0.2.1'], enableBlocking: true } };
    for (const encoding of ['form', 'json']) {
      state = initial();
      const before = structuredClone(state);
      const resultFile = join(directory, `settings-${encoding}.json`);
      const preview = await success('settings set', { ...main, encoding });
      const result = await success('settings set', { ...main, encoding }, ['--execute', '--confirm', preview.preview.digest, '--result-file', resultFile]);
      assert.deepEqual(state, { ...before, ...main.parameters });
      const protectedBytes = await readFile(resultFile);
      assert.deepEqual(JSON.parse(protectedBytes.toString()).response, state);
      assert.equal(result.result.sha256, hash(protectedBytes));
      assert.equal((await stat(resultFile)).mode & 0o777, 0o600);
    }
    if (task !== 'B4.03') for (const row of matrix.settings) for (const encoding of row.encoding) {
      state = initial();
      const resolve = (value: unknown): unknown => (value as { env?: string })?.env ? (value as { env: string }).env === 'OLD_SECRET' ? 'SYNTHETIC-old-secret' : secret : Array.isArray(value) ? value.map(item => item?.sharedSecret?.env ? { ...item, sharedSecret: secret } : item) : value;
      setField(row.parameter, resolve(row.seed));
      const before = structuredClone(state);
      const input = { parameters: { [row.parameter]: row.changed }, baseline: { [row.parameter]: row.seed }, encoding };
      await execute('settings set', input, { OLD_SECRET: 'SYNTHETIC-old-secret' });
      const expected = resolve(row.changed);
      assert.deepEqual(getField(row.parameter), row.parameter === 'tsigKeys' ? (expected as { keyName: string }[]).map(item => ({ ...item, keyName: item.keyName.toLowerCase().replace(/\.$/, '') })) : row.parameter.endsWith('CertificatePassword') ? '************' : expected, row.parameter);
      const complement = structuredClone(state);
      if (row.parameter.startsWith('proxy')) {
        const property = row.parameter === 'proxyBypass' ? 'bypass' : row.parameter.slice(5).toLowerCase();
        complement.proxy![property] = before.proxy![property];
      }
      else delete complement[row.parameter === 'reverseProxyNetworkACL' ? 'dnsReverseProxyNetworkACL' : row.parameter];
      const preserved = structuredClone(before);
      if (!row.parameter.startsWith('proxy')) delete preserved[row.parameter === 'reverseProxyNetworkACL' ? 'dnsReverseProxyNetworkACL' : row.parameter];
      assert.deepEqual(complement, preserved, row.parameter);
    }
    state = initial();
    state.tsigKeys = [];
    const generatedInput = { parameters: { tsigKeys: [{ keyName: 'generated', sharedSecret: { env: 'EMPTY_SECRET' }, algorithmName: 'hmac-sha256' }] }, baseline: { tsigKeys: [] } };
    await execute('settings set', generatedInput, { EMPTY_SECRET: '' });
    assert.deepEqual(state.tsigKeys, [{ keyName: 'generated', sharedSecret: secret, algorithmName: 'hmac-sha256' }]);
    state = initial();
    state.blockListUrls = ['https://old.example.test/list'];
    const appended = ['https://old.example.test/list', 'https://new.example.test/list'];
    await execute('settings set', { parameters: { blockListUrls: appended }, baseline: { blockListUrls: state.blockListUrls } });
    assert.deepEqual(state.blockListUrls, appended);
    await execute('settings set', { parameters: { blockListUrls: [] }, baseline: { blockListUrls: appended } });
    assert.deepEqual(state.blockListUrls, []);
    state.maxLogFileDays = 365;
    state.webServiceHttpUnixSocket = 'dns.sock';
    await execute('settings set', { parameters: { maxLogFileDays: 0, webServiceHttpUnixSocket: '' }, baseline: { maxLogFileDays: 365, webServiceHttpUnixSocket: 'dns.sock' } });
    assert.equal(state.maxLogFileDays, 0);
    assert.equal(state.webServiceHttpUnixSocket, '');
    const normalizationCases: [string, string | string[], string | string[]][] = [
      ['dnsServerDomain', 'DNS.EXAMPLE.TEST', 'dns.example.test'],
      ['dnsOverHttpRealIpHeader', '', 'X-Real-IP'],
      ['eDnsClientSubnetIpv4Override', '192.0.2.129/24', '192.0.2.0/24'],
      ['eDnsClientSubnetIpv6Override', 'FE80:0:0:0:0:0:0:1%3/128', 'fe80::1%3'],
      ['dnsServerLocalEndPoints', ['2001:0DB8::1', '[0:0:0:0:0:0:0:1]:0053', '192.0.2.1:0', '[FE80:0:0:0:0:0:0:1%3]:53'], ['[2001:db8::1]:53', '[::1]:53', '192.0.2.1:53', '[fe80::1%3]:53']],
      ['webServiceLocalAddresses', ['0:0:0:0:0:0:0:1', 'FE80:0:0:0:0:0:0:1%3'], ['[::1]', '[fe80::1%3]']],
      ['dnsServerIPv4SourceAddresses', ['192.0.2.129/24'], ['192.0.2.0/24']],
      ['dnsServerIPv6SourceAddresses', ['2001:0DB8::1234/64', 'FE80:0:0:0:0:0:0:1%3'], ['2001:db8::/64', 'fe80::1%3']],
      ['zoneTransferAllowedNetworks', ['2001:0DB8::1234/64', 'FE80:0:0:0:0:0:0:1%3'], ['2001:db8::/64', 'fe80::1%3']],
      ['notifyAllowedNetworks', ['2001:0DB8::1234/64', 'FE80:0:0:0:0:0:0:1%3'], ['2001:db8::/64', 'fe80::1%3']],
      ['qpmLimitBypassList', ['2001:0DB8::1234/64', 'FE80:0:0:0:0:0:0:1%3'], ['2001:db8::/64', 'fe80::1%3']],
      ['webServiceReverseProxyAddresses', ['!2001:0DB8::1234/64', 'FE80:0:0:0:0:0:0:1%3'], ['!2001:db8::/64', 'fe80::1%3']],
      ['dnsReverseProxyNetworkACL', ['!2001:0DB8::1234/64', '!FE80:0:0:0:0:0:0:1%3'], ['!2001:db8::/64', '!fe80::1%3']],
      ['reverseProxyNetworkACL', ['!2001:0DB8::1234/64', '!FE80:0:0:0:0:0:0:1%3'], ['!2001:db8::/64', '!fe80::1%3']],
      ['recursionNetworkACL', ['!2001:0DB8::1234/64', '!FE80:0:0:0:0:0:0:1%3'], ['!2001:db8::/64', '!fe80::1%3']],
      ['blockingBypassList', ['2001:0DB8::1234/64', 'FE80:0:0:0:0:0:0:1%3'], ['2001:db8::/64', 'fe80::1%3']],
      ['customBlockingAddresses', ['0:0:0:0:0:0:0:1', '192.0.2.2', 'FE80:0:0:0:0:0:0:1%3', '192.0.2.3'], ['192.0.2.2', '192.0.2.3', '::1', 'fe80::1%3']],
    ];
    const settingsResponder = vendors.responders.get('/api/settings/set');
    vendors.responders.set('/api/settings/set', (incoming, bytes) => {
      const json = incoming.headers['content-type'] === 'application/json';
      const data = json ? JSON.parse(bytes.toString()) : Object.fromEntries(new URLSearchParams(bytes.toString()));
      writes++;
      for (const [key, raw] of Object.entries(data)) {
        let value = raw;
        if (fields[key]!.type === 'list') value = json ? raw : raw === '' ? [] : (raw as string).split(',');
        if (fields[key]!.type === 'integer' && !json) value = Number(raw);
        if (key === 'dnsServerDomain') value = (value as string).replace(/\.+$/, '').toLowerCase();
        if (key === 'dnsServerLocalEndPoints' && (value as unknown[]).length === 0) value = ['0.0.0.0:53', '[::]:53'];
        if (key === 'webServiceLocalAddresses' && (value as unknown[]).length === 0) value = ['0.0.0.0', '[::]'];
        if (key === 'webServiceRealIpHeader' && value === '') value = 'X-Real-IP';
        if (key === 'webServiceCspFrameAncestorsHeader' && value === '') value = "'none'";
        if (key === 'forwarderProtocol' && value === 'HttpsJson') value = 'Https';
        if (key === 'tsigKeys') {
          if (!json) {
            const cells = raw === '' ? [] : (raw as string).split('|');
            value = [];
            for (let i = 0; i < cells.length; i += 3) (value as Record<string, unknown>[]).push({ keyName: cells[i], sharedSecret: cells[i + 1], algorithmName: cells[i + 2] });
          }
          value = (value as { keyName: string; sharedSecret: string }[]).map(row => ({ ...row, keyName: row.keyName === 'BÜCHER.Example.' ? 'xn--bcher-kva.example' : row.keyName }));
        }
        const normalizationCase = normalizationCases.find(([field, requested]) => field === key && JSON.stringify(requested) === JSON.stringify(value));
        if (normalizationCase) value = structuredClone(normalizationCase[2]);
        if (key.startsWith('proxy')) {
          state.proxy ??= {};
          state.proxy[key.slice(5).toLowerCase()] = value;
        } else setField(key, value);
      }
      if (Array.isArray(state.forwarders) && state.forwarders.length === 0) state.forwarderProtocol = 'Udp';
      for (const prefix of ['webServiceTlsCertificate', 'dnsTlsCertificate']) {
        state[`${prefix}Password`] = state[`${prefix}Path`] ? '************' : null;
      }
      if (state.proxy && !state.proxy.username) {
        delete state.proxy.username;
        delete state.proxy.password;
      }
      if (drop) { incoming.socket.destroy(); return {}; }
      return { body: { status: 'ok', response: state } };
    });
    const normalizedInput = {
      parameters: { dnsServerDomain: 'new.example.test.', dnsServerLocalEndPoints: [], webServiceLocalAddresses: [],
        webServiceRealIpHeader: '', webServiceCspFrameAncestorsHeader: '', forwarderProtocol: 'HttpsJson' },
      baseline: { dnsServerDomain: 'old.example.test', dnsServerLocalEndPoints: ['192.0.2.1:53'], webServiceLocalAddresses: ['192.0.2.1'],
        webServiceRealIpHeader: 'Custom-IP', webServiceCspFrameAncestorsHeader: "'self'", forwarderProtocol: 'Tls' },
    };
    const normalizedExpected = { dnsServerDomain: 'new.example.test', dnsServerLocalEndPoints: ['0.0.0.0:53', '[::]:53'],
      webServiceLocalAddresses: ['0.0.0.0', '[::]'], webServiceRealIpHeader: 'X-Real-IP', webServiceCspFrameAncestorsHeader: "'none'", forwarderProtocol: 'Https' };
    for (const encoding of ['form', 'json']) {
      state = { ...initial(), defaultResponsiblePerson: 'old@example.test' };
      const plainAddressInput = { parameters: { defaultResponsiblePerson: 'Admin@Example.TEST' }, baseline: { defaultResponsiblePerson: 'old@example.test' }, encoding };
      const plainAddressPreview = await success('settings set', plainAddressInput);
      for (const value of ['DNS Admin <admin@example.test>', 'admin@example.test (DNS Admin)']) {
        for (const field of ['parameters', 'baseline']) {
          const input = { ...plainAddressInput, [field]: { defaultResponsiblePerson: value } };
          const before = vendors.traces.length;
          const refused = await failure('USAGE', 'settings set', input);
          assert.match(refused.error.message, /defaultResponsiblePerson requires a plain local@domain address/);
          await failure('USAGE', 'settings set', input, ['--execute', '--confirm', plainAddressPreview.preview.digest]);
          assert.equal(vendors.traces.length, before, 'Unsupported mailbox forms fail before vendor requests');
        }
      }
      await success('settings set', plainAddressInput, ['--execute', '--confirm', plainAddressPreview.preview.digest]);
      assert.equal(state.defaultResponsiblePerson, 'Admin@Example.TEST');
      for (const prefix of ['webServiceTlsCertificate', 'dnsTlsCertificate']) {
        for (const password of ['OPERATION_SECRET', 'EMPTY_SECRET']) {
          state = { ...initial(), [`${prefix}Path`]: null, [`${prefix}Password`]: null };
          await execute('settings set', { parameters: { [`${prefix}Path`]: 'first.pfx', [`${prefix}Password`]: { env: password } },
            baseline: { [`${prefix}Path`]: '', [`${prefix}Password`]: { env: 'EMPTY_SECRET' } }, encoding }, { EMPTY_SECRET: '' });
          assert.equal(state[`${prefix}Path`], 'first.pfx');
          assert.equal(state[`${prefix}Password`], '************');
        }
        state = initial();
        await execute('settings set', { parameters: { [`${prefix}Password`]: { env: 'EMPTY_SECRET' } },
          baseline: { [`${prefix}Password`]: { env: 'OPERATION_SECRET' } }, encoding }, { EMPTY_SECRET: '' });
        assert.equal(state[`${prefix}Path`], prefix === 'webServiceTlsCertificate' ? 'web.pfx' : 'dns.pfx');
        assert.equal(state[`${prefix}Password`], '************');
        await execute('settings set', { parameters: { [`${prefix}Path`]: '', [`${prefix}Password`]: { env: 'EMPTY_SECRET' } },
          baseline: { [`${prefix}Path`]: state[`${prefix}Path`], [`${prefix}Password`]: { env: 'OPERATION_SECRET' } }, encoding }, { EMPTY_SECRET: '' });
        assert.equal(state[`${prefix}Password`], null);
      }
      state = { ...initial(), proxy: null };
      await execute('settings set', { parameters: { proxyType: 'Http', proxyAddress: 'new.proxy.test', proxyPort: 8080 },
        baseline: { proxyType: 'None', proxyAddress: '', proxyPort: 0 }, encoding });
      assert.deepEqual(state.proxy, { type: 'Http', address: 'new.proxy.test', port: 8080, bypass: [] });
      await execute('settings set', { parameters: { proxyUsername: 'operator' }, baseline: { proxyUsername: '' }, encoding });
      assert.deepEqual(state.proxy, { type: 'Http', address: 'new.proxy.test', port: 8080, bypass: [], username: 'operator', password: '' });
      await execute('settings set', { parameters: { proxyPassword: { env: 'OPERATION_SECRET' } },
        baseline: { proxyPassword: { env: 'EMPTY_SECRET' } }, encoding }, { EMPTY_SECRET: '' });
      assert.deepEqual(state.proxy, { type: 'Http', address: 'new.proxy.test', port: 8080, bypass: [], username: 'operator', password: secret });
      state = { ...initial(), ...normalizedInput.baseline };
      await execute('settings set', { ...normalizedInput, encoding });
      assert.deepEqual(state, { ...initial(), ...normalizedExpected });
      state = { ...initial(), ...normalizedInput.baseline };
      drop = true;
      const preview = await success('settings set', { ...normalizedInput, encoding });
      const lost = await failure('OUTCOME_UNKNOWN', 'settings set', { ...normalizedInput, encoding }, ['--execute', '--confirm', preview.preview.digest]);
      const afterLost = writes;
      await failure('CONFLICT', 'settings set', { ...normalizedInput, encoding }, ['--execute', '--confirm', preview.preview.digest]);
      assert.equal(writes, afterLost, 'Normalized uncertain writes are never replayed');
      drop = false;
      const auditId = lost.error.message.match(/audit ID ([a-f0-9-]+)/)![1];
      await success('settings set', { ...normalizedInput, encoding }, ['--confirm', preview.preview.digest, '--reconcile', auditId!]);
      assert.equal(writes, afterLost, 'Reconciliation only reads vendor state');
      assert.deepEqual(state, { ...initial(), ...normalizedExpected });
      for (const alias of ['dnsReverseProxyNetworkACL', 'reverseProxyNetworkACL']) {
        const cases = normalizationCases.filter(([key]) => !['dnsReverseProxyNetworkACL', 'reverseProxyNetworkACL'].includes(key!) || key === alias);
        const parameters = Object.fromEntries(cases.map(([key, requested]) => [key, requested]));
        const baseline = Object.fromEntries(cases.map(([key, requested]) => [key, Array.isArray(requested) ? [] : '']));
        state = { ...initial(), ...baseline };
        if (alias === 'reverseProxyNetworkACL') { delete state.reverseProxyNetworkACL; state.dnsReverseProxyNetworkACL = []; }
        const before = structuredClone(state);
        const expected = { ...before, ...Object.fromEntries(cases.map(([key, , returned]) => [key === 'reverseProxyNetworkACL' ? 'dnsReverseProxyNetworkACL' : key, returned])) };
        const input = { parameters, baseline, encoding };
        await execute('settings set', input);
        assert.deepEqual(state, expected);
        const sameBaseline = await success('settings set', { parameters, baseline: parameters, encoding });
        await success('settings set', { parameters, baseline: parameters, encoding }, ['--execute', '--confirm', sameBaseline.preview.digest]);
        state = structuredClone(before);
        drop = true;
        const preview = await success('settings set', input);
        const lost = await failure('OUTCOME_UNKNOWN', 'settings set', input, ['--execute', '--confirm', preview.preview.digest]);
        const afterLost = writes;
        drop = false;
        await failure('CONFLICT', 'settings set', input, ['--execute', '--confirm', preview.preview.digest]);
        const auditId = lost.error.message.match(/audit ID ([a-f0-9-]+)/)![1];
        await success('settings set', input, ['--confirm', preview.preview.digest, '--reconcile', auditId!]);
        assert.equal(writes, afterLost);
        assert.deepEqual(state, expected);
        const unchanged = structuredClone(state);
        await execute('settings set', { parameters: { defaultRecordTtl: 600 }, baseline: { defaultRecordTtl: 3600 }, encoding });
        assert.deepEqual(state, { ...unchanged, defaultRecordTtl: 600 });
      }
      const tsigInput = { parameters: { tsigKeys: [{ keyName: 'BÜCHER.Example.', sharedSecret: { env: 'OPERATION_SECRET' }, algorithmName: 'hmac-sha256' }] }, baseline: { tsigKeys: [] }, encoding };
      state = { ...initial(), tsigKeys: [] };
      await execute('settings set', tsigInput);
      assert.deepEqual(state.tsigKeys, [{ keyName: 'xn--bcher-kva.example', sharedSecret: secret, algorithmName: 'hmac-sha256' }]);
      state.tsigKeys = [];
      drop = true;
      const tsigPreview = await success('settings set', tsigInput);
      const tsigLost = await failure('OUTCOME_UNKNOWN', 'settings set', tsigInput, ['--execute', '--confirm', tsigPreview.preview.digest]);
      const afterTsigLost = writes;
      drop = false;
      await failure('CONFLICT', 'settings set', tsigInput, ['--execute', '--confirm', tsigPreview.preview.digest]);
      const tsigAuditId = tsigLost.error.message.match(/audit ID ([a-f0-9-]+)/)![1];
      await success('settings set', tsigInput, ['--confirm', tsigPreview.preview.digest, '--reconcile', tsigAuditId!]);
      assert.equal(writes, afterTsigLost);
      for (const parameters of [{ forwarderProtocol: 'Tls' }, { forwarders: [] }, { forwarders: [], forwarderProtocol: 'Tls' }]) {
        state = { ...initial(), forwarders: null, forwarderProtocol: 'Udp' };
        const baseline = Object.fromEntries(Object.keys(parameters).map(key => [key, key === 'forwarders' ? [] : 'Udp']));
        const input = { parameters, baseline, encoding };
        await execute('settings set', input);
        assert.deepEqual(state.forwarders, []);
        assert.equal(state.forwarderProtocol, 'Udp');
        state.forwarders = null;
        drop = true;
        const preview = await success('settings set', input);
        const lost = await failure('OUTCOME_UNKNOWN', 'settings set', input, ['--execute', '--confirm', preview.preview.digest]);
        const afterLost = writes;
        drop = false;
        await failure('REPLAY_DENIED', 'settings set', input, ['--execute', '--confirm', preview.preview.digest]);
        const auditId = lost.error.message.match(/audit ID ([a-f0-9-]+)/)![1];
        await success('settings set', input, ['--confirm', preview.preview.digest, '--reconcile', auditId!]);
        assert.equal(writes, afterLost);
      }
    }
    vendors.responders.set('/api/settings/set', settingsResponder!);
    await failure('USAGE', 'settings set', { parameters: { enableBlocking: null }, baseline: { enableBlocking: true } });
    await failure('USAGE', 'settings set', { parameters: { proxyPassword: '[REDACTED]' }, baseline: { proxyPassword: { env: 'OPERATION_SECRET' } } });
    state = initial();
    const preview = await success('settings set', main);
    state.defaultRecordTtl = 999;
    const count = writes;
    await failure('CONFLICT', 'settings set', main, ['--execute', '--confirm', preview.preview.digest]);
    assert.equal(writes, count);
    state = initial();
    drop = true;
    const lost = await success('settings set', main);
    const unknown = await failure('OUTCOME_UNKNOWN', 'settings set', main, ['--execute', '--confirm', lost.preview.digest]);
    const afterLost = writes;
    await failure('CONFLICT', 'settings set', main, ['--execute', '--confirm', lost.preview.digest]);
    assert.equal(writes, afterLost, 'An uncertain mutation is never replayed');
    const auditId = unknown.error.message.match(/audit ID ([a-f0-9-]+)/)![1];
    drop = false;
    await success('settings set', main, ['--confirm', lost.preview.digest, '--reconcile', auditId!]);
    state = initial();
    reject = true;
    const partial = await success('settings set', main);
    await failure('OUTCOME_UNKNOWN', 'settings set', main, ['--execute', '--confirm', partial.preview.digest]);
    assert.equal(state.defaultRecordTtl, 300);
    assert.equal(state.proxy!.password, secret);
    const secretInput = { parameters: { proxyPassword: { env: 'OPERATION_SECRET' } }, baseline: { proxyPassword: { env: 'OPERATION_SECRET' } } };
    const secretPreview = await success('settings set', secretInput);
    await failure('CONFIRMATION_MISMATCH', 'settings set', secretInput, ['--execute', '--confirm', secretPreview.preview.digest], { OPERATION_SECRET: 'SYNTHETIC-revision-2' });
  }
  if (task === 'B4.02' || task === 'B4.03') {
    const bytes = archive(['logs/2024-01-01.log', 'dns.config', 'dnsApp.config']);
    const upload = join(directory, 'package.zip');
    await writeFile(upload, bytes, { mode: 0o600 });
    let caseIndex = 0;
    for (const [command, operation, path, parameters] of [
      ['app install', 'OP-072', '/api/apps/install', { name: 'Example' }],
      ['app update', 'OP-073', '/api/apps/update', { name: 'Example' }],
      ['settings restore', 'OP-085', '/api/settings/restore', { logs: true, dnsSettings: false, deleteExistingFiles: false }],
      ['settings restore', 'OP-085', '/api/settings/restore', { logs: false, dnsSettings: true, deleteExistingFiles: false }],
    ] satisfies [string, string, string, Record<string, unknown>][]) {
      await configure([operation!]);
      let count = 0;
      let restoredLog = 'old-log';
      let configuration = { proxy: { password: secret }, tsigKeys: [{ sharedSecret: secret }] };
      vendors.responders.set(path!, (incoming, received) => {
        assert.equal(incoming.headers.authorization, `Bearer ${token}`);
        assert.deepEqual(Object.fromEntries(new URL(incoming.url!, vendors.origins[0]).searchParams), Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, String(value)])));
        const boundary = incoming.headers['content-type']!.split('boundary=')[1];
        assert.equal(received.toString().split('Content-Disposition:').length, 2, 'File-only multipart prevents vendor proxy field loss');
        const start = received.indexOf('\r\n\r\n') + 4;
        const packageBytes = received.subarray(start, received.length - Buffer.byteLength(`\r\n--${boundary}--\r\n`));
        assert.deepEqual(packageBytes, bytes);
        const entries: Record<string, string> = {};
        let offset = 0;
        while (packageBytes.readUInt32LE(offset) === 0x04034b50) {
          const size = packageBytes.readUInt32LE(offset + 18);
          const nameLength = packageBytes.readUInt16LE(offset + 26);
          const name = packageBytes.subarray(offset + 30, offset + 30 + nameLength).toString();
          const end = offset + 30 + nameLength + size;
          entries[name] = packageBytes.subarray(offset + 30 + nameLength, end).toString();
          offset = end;
        }
        assert.deepEqual(entries, { 'logs/2024-01-01.log': 'SYNTHETIC-logs/2024-01-01.log', 'dns.config': 'SYNTHETIC-dns.config', 'dnsApp.config': 'SYNTHETIC-dnsApp.config' });
        if (operation === 'OP-085' && parameters!.logs) restoredLog = entries['logs/2024-01-01.log'];
        if (operation === 'OP-085' && parameters!.dnsSettings) configuration = { proxy: { password: 'SYNTHETIC-restored-proxy' }, tsigKeys: [{ sharedSecret: 'SYNTHETIC-restored-tsig' }] };
        count++;
        return { body: { status: 'ok', response: configuration } };
      });
      const input = { parameters, upload: { file: upload } };
      const preview = await success(command!, input);
      assert.equal(preview.preview.upload.sha256, hash(bytes));
      await writeFile(upload, archive(['logs/changed.log']));
      await failure('CONFIRMATION_MISMATCH', command!, input, ['--execute', '--confirm', preview.preview.digest]);
      assert.equal(count, 0);
      await writeFile(upload, bytes);
      const caseId = `${operation}-${caseIndex++}`;
      const resultFile = join(directory, `${caseId}.json`);
      const result = await success(command!, input, ['--execute', '--confirm', preview.preview.digest, '--result-file', resultFile]);
      assert.equal(result.result.sha256, hash(await readFile(resultFile)));
      assert.deepEqual(JSON.parse((await readFile(resultFile)).toString()).response, configuration);
      for (const value of [configuration.proxy.password, configuration.tsigKeys[0]!.sharedSecret]) assert.ok(!JSON.stringify(result).includes(value!));
      if (operation === 'OP-085') assert.equal(restoredLog, parameters!.logs ? 'SYNTHETIC-logs/2024-01-01.log' : 'old-log');
      const unsafe = join(directory, `${caseId}.link`);
      await symlink(resultFile, unsafe);
      const denied = await success(command!, input);
      await failure('CONFIG_INSECURE', command!, input, ['--execute', '--confirm', denied.preview.digest, '--result-file', unsafe]);
      assert.equal(count, 1, 'Custody denial happens before mutation');
      await chmod(directory, 0o755);
      const next = await success(command!, input);
      await success(command!, input, ['--execute', '--confirm', next.preview.digest, '--result-file', resultFile]);
      assert.equal((await stat(directory)).mode & 0o777, 0o755, 'Existing destination access is preserved');
      await chmod(directory, 0o700);
    }
    await writeFile(upload, archive(['../escape']));
    await failure('UPLOAD_INVALID', 'settings restore', { parameters: { logs: true }, upload: { file: upload } });
    await writeFile(upload, Buffer.alloc(16 * 1024 * 1024 + 1));
    await failure('INPUT_LIMIT', 'settings restore', { parameters: { logs: true }, upload: { file: upload } });
  }
  for (const [id, command, path, parameters] of [
    ['B4.OP-082', 'settings force-update-block-lists', '/api/settings/forceUpdateBlockLists', {}],
    ['B4.OP-083', 'settings temporary-disable-blocking', '/api/settings/temporaryDisableBlocking', { minutes: 5 }],
    ['B4.OP-136', 'log delete', '/api/logs/delete', { log: '2024-01-01' }],
    ['B4.OP-137', 'log delete-all', '/api/logs/deleteAll', {}],
  ] satisfies [string, string, string, { minutes?: number; log?: string }][]) if (task === id) {
    await configure([id.slice(3)]);
    let logs = ['2024-01-01', '2024-01-02'];
    let revision = 1;
    let now = Date.parse('2024-01-01T00:00:00Z');
    let until: number | undefined;
    let calls = 0;
    let fault = false;
    vendors.responders.set(path!, (incoming, bytes) => {
      assert.equal(incoming.headers.authorization, `Bearer ${token}`);
      assert.deepEqual(Object.fromEntries(new URLSearchParams(bytes.toString())), Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, String(value)])));
      calls++;
      if (fault) return { body: { status: 'error' } };
      if (id === 'B4.OP-082') revision = 2;
      if (id === 'B4.OP-083') until = now + parameters!.minutes! * 60000;
      if (id === 'B4.OP-136') logs = logs.filter(log => log !== parameters!.log);
      if (id === 'B4.OP-137') logs = [];
      return { body: { status: 'ok', response: until ? { temporaryDisableBlockingTill: new Date(until).toISOString() } : {} } };
    });
    const input = { parameters };
    const result = await execute(command!, input);
    assert.equal(calls, 1);
    if (id === 'B4.OP-082') assert.equal(revision, 2);
    if (id === 'B4.OP-083') {
      assert.equal((result.response as { temporaryDisableBlockingTill: string }).temporaryDisableBlockingTill, '2024-01-01T00:05:00.000Z');
      assert.equal(now < until!, true);
      now = until!;
      assert.equal(now < until!, false);
      await failure('USAGE', command!, { parameters: { minutes: 0 } });
    }
    if (id === 'B4.OP-136') assert.deepEqual(logs, ['2024-01-02']);
    if (id === 'B4.OP-137') assert.deepEqual(logs, []);
    fault = true;
    const preview = await success(command!, input);
    await failure('UPSTREAM_ERROR', command!, input, ['--execute', '--confirm', preview.preview.digest]);
    await failure('REPLAY_DENIED', command!, input, ['--execute', '--confirm', preview.preview.digest]);
    assert.equal(calls, 2);
  }
  const journal = join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d');
  for (const name of await readdir(journal)) {
    const text = await readFile(join(journal, name), 'utf8');
    for (const value of [token, secret, encodeURIComponent(secret!), Buffer.from(secret).toString('base64')]) assert.ok(!text.includes(value!));
  }
}
