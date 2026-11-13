import type { SecretWriteContext } from './journey-types.ts';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { request } from 'node:https';
import { join } from 'node:path';
import type { IncomingMessage } from 'node:http';

interface ClusterNode { id: number; name: string; url: string; ipAddresses: string[]; type: string; configLastSynced?: string }

const ids = ['119', '120', '121', '122', '123', '124', '126', '127', '128', '129', '130', '131', '132', '133'];
export const clusterTasks = ['B5.03', ...ids.map(id => `B5.OP-${id}`)];

// Synthetic worlds grounded in WebServiceClusterApi and ClusterManager at vendor revision 0dd592aad21eced4221a9a46204cb1a299972ca0.
export async function clusterJourney({ task, env, run, executable, vendors, config, token, secret, configure, success, failure, execute }: SecretWriteContext) {
  const certificate = new X509Certificate(await readFile(vendors.caFile)).raw.toString('base64url');
  const pUrl = 'https://dns-p.cluster.example.test';
  const sUrl = 'https://dns-s.cluster.example.test';
  const nextUrl = 'https://dns-new.cluster.example.test';
  const timers = { heartbeatRefreshIntervalSeconds: 30, heartbeatRetryIntervalSeconds: 10, configRefreshIntervalSeconds: 900, configRetryIntervalSeconds: 60 };
  const cases: [string, string, string, Record<string, unknown>][] = [
    ['119', 'init', 'init', { clusterDomain: 'cluster.example.test', primaryNodeIpAddresses: ['192.0.2.10'] }],
    ['120', 'primary delete', 'primary/delete', { forceDelete: true }],
    ['121', 'primary join', 'primary/join', { secondaryNodeId: 200, secondaryNodeUrl: sUrl, secondaryNodeIpAddresses: ['192.0.2.20'], secondaryNodeCertificate: certificate }],
    ['122', 'primary remove-secondary', 'primary/removeSecondary', { secondaryNodeId: 200 }],
    ['123', 'primary delete-secondary', 'primary/deleteSecondary', { secondaryNodeId: 200 }],
    ['124', 'primary update-secondary', 'primary/updateSecondary', { secondaryNodeId: 200, secondaryNodeUrl: nextUrl, secondaryNodeIpAddresses: ['192.0.2.21'], secondaryNodeCertificate: certificate }],
    ['126', 'primary set-options', 'primary/setOptions', { heartbeatRefreshIntervalSeconds: 45, heartbeatRetryIntervalSeconds: 15, configRefreshIntervalSeconds: 600, configRetryIntervalSeconds: 30 }],
    ['127', 'init-join', 'initJoin', { secondaryNodeIpAddresses: ['192.0.2.20'], primaryNodeUrl: pUrl, primaryNodeUsername: 'planner', primaryNodePassword: { env: 'OPERATION_SECRET' }, primaryNodeTotp: { env: 'OPERATION_SECRET' }, ignoreCertificateErrors: false }],
    ['128', 'secondary leave', 'secondary/leave', { forceLeave: false }],
    ['129', 'secondary notify', 'secondary/notify', { primaryNodeId: 100, primaryNodeUrl: nextUrl, primaryNodeIpAddresses: ['192.0.2.11'] }],
    ['130', 'secondary resync', 'secondary/resync', {}],
    ['131', 'secondary update-primary', 'secondary/updatePrimary', { primaryNodeUrl: nextUrl, primaryNodeIpAddresses: ['192.0.2.11'] }],
    ['132', 'secondary promote', 'secondary/promote', { forceDeletePrimary: false }],
    ['133', 'update-ip-address', 'updateIpAddress', { node: 'S', ipAddresses: ['192.0.2.21', '2001:db8::21'] }],
  ];
  vendors.tokens.set('beta', token);
  let nodes!: ClusterNode[], initialized!: Record<string, boolean>, options!: typeof timers, zones!: { replicated: number; local: string }, deny!: boolean, drop!: boolean, pulls!: number, replacementNode: string | undefined, unreachablePrimary: boolean;
  const reset = (id: string) => {
    nodes = [
      { id: 100, name: 'dns-p.cluster.example.test', url: pUrl, ipAddresses: ['192.0.2.10'], type: 'Primary' },
      { id: 200, name: 'dns-s.cluster.example.test', url: sUrl, ipAddresses: ['192.0.2.20'], type: 'Secondary' },
      { id: 300, name: 'keep.cluster.example.test', url: 'https://keep.cluster.example.test', ipAddresses: ['192.0.2.30'], type: 'Secondary' },
    ];
    if (id === '121' || id === '127') nodes = nodes.filter(row => row.id !== 200);
    if (id === '119') nodes = nodes.filter(row => row.id === 100);
    initialized = { P: id !== '119', S: id !== '127', keep: true };
    options = { ...timers };
    zones = { replicated: 7, local: 'preserved local zone' };
    deny = false; drop = false; pulls = 0; replacementNode = undefined; unreachablePrimary = false;
  };
  const selected = (incoming: IncomingMessage, p: Record<string, string>) => p.node ?? (incoming.socket.localPort === Number(new URL(vendors.origins[1]!).port) ? 'S' : 'P');
  const state = (node: string): Record<string, unknown> & { clusterInitialized: boolean | undefined; clusterNodes?: (ClusterNode & { state: string })[] } => ({ version: '15.4', dnsServerDomain: `dns-${node.toLowerCase()}.cluster.example.test`, clusterInitialized: initialized[node],
    ...(initialized[node] ? { clusterDomain: 'cluster.example.test', ...options,
      clusterNodes: nodes.map(row => ({ ...row, state: row.id === ({ P: 100, S: 200, keep: 300 } as Record<string, number>)[node] ? 'Self' : 'Connected', ...(row.id === 200 && pulls ? { configLastSynced: '2024-01-01T00:00:01Z' } : {}) })) } : {}) });
  const ok = (response?: unknown) => ({ body: { status: 'ok', ...(response ? { response } : {}) } });
  const rejected = () => ({ body: { status: 'error', errorMessage: 'Access denied or cluster prerequisite failed.' } });
  vendors.responders.set('/api/admin/cluster/state', (incoming, bytes) => {
    if (replacementNode && incoming.socket.localPort === Number(new URL(vendors.origins[0]!).port)) { incoming.socket.destroy(); return {}; }
    return ok(state(replacementNode ?? selected(incoming, Object.fromEntries(new URLSearchParams(bytes.toString())))));
  });
  vendors.responders.set('/api/zones/records/get', (_incoming, bytes) => {
    const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
    return ok({ zone: { name: p.zone, type: p.zone === 'keep.test' ? 'Primary' : 'Secondary' }, records: p.zone === 'keep.test'
      ? [{ name: 'keep.test', type: 'TXT', ttl: 60, rData: { text: zones.local } }]
      : [{ name: 'example.test', type: 'SOA', ttl: 60, rData: { primaryNameServer: 'dns-p.cluster.example.test', responsiblePerson: 'hostmaster.example.test', serial: zones.replicated, refresh: 900, retry: 300, expire: 86400, minimum: 60 } }] });
  });
  const leave = async () => new Promise<void>((resolve, reject) => {
    const call = request(`${vendors.origins[1]}/api/admin/cluster/secondary/leave`, { method: 'POST',
      // Explicit loopback trust, identical to the public caller's configured CA.
      ca: caBytes, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/x-www-form-urlencoded' } }, response => {
      response.resume(); response.once('end', resolve);
    });
    call.once('error', reject); call.end('forceLeave=false');
  });
  const caBytes = await readFile(vendors.caFile);
  for (const [id, , path, parameters] of cases) vendors.responders.set(`/api/admin/cluster/${path}`, async (incoming, bytes) => {
    const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
    assert.equal(incoming.headers.authorization, `Bearer ${token}`);
    assert.equal(incoming.headers['content-type'], 'application/x-www-form-urlencoded');
    if (deny || id === '129' && Number(p.primaryNodeId) >= 0 && !nodes.some(row => row.id === Number(p.primaryNodeId) && row.id !== 200) || id === '120' && p.forceDelete !== 'true' && nodes.length > 1) return rejected();
    if (id !== '128' || !incoming.url!.includes('leave')) assert.deepEqual(p, Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, (value as { env?: string })?.env ? secret : Array.isArray(value) ? value.join(',') : String(value)])));
    const node = selected(incoming, p);
    if (id === '119') initialized.P = true;
    if (id === '120') initialized.P = false;
    if (id === '121' || id === '127') {
      nodes.push({ id: 200, name: 'dns-s.cluster.example.test', url: sUrl, ipAddresses: ['192.0.2.20'], type: 'Secondary' });
      initialized.S = true; zones.replicated = 42;
    }
    if (id === '122') await leave();
    if (id === '123' || id === '128' && !unreachablePrimary) nodes = nodes.filter(row => row.id !== 200);
    if (id === '128') initialized.S = false;
    if (id === '124') Object.assign(nodes.find(row => row.id === 200)!,  { name: new URL(p.secondaryNodeUrl!).hostname, url: p.secondaryNodeUrl, ipAddresses: p.secondaryNodeIpAddresses!.split(',') });
    if (id === '126') for (const [key, value] of Object.entries(p)) options[key as keyof typeof options] = Number(value);
    if (id === '129' || id === '131') {
      const primary = nodes.find(row => id === '129' && Number(p.primaryNodeId) >= 0 ? row.id === Number(p.primaryNodeId) : row.type === 'Primary');
      if (primary!.type === 'Secondary') nodes = nodes.filter(row => row.type !== 'Primary');
      Object.assign(primary!, { name: new URL(p.primaryNodeUrl!).hostname, type: 'Primary', url: p.primaryNodeUrl, ipAddresses: p.primaryNodeIpAddresses?.split(',') ?? ['192.0.2.11'] });
    }
    if (id === '129' || id === '130') { pulls++; zones.replicated = 42; }
    if (id === '132') { nodes = nodes.filter(row => row.id !== 100); nodes.find(row => row.id === 200)!.type = 'Primary'; if (p.forceDeletePrimary !== 'true') initialized.P = false; zones.replicated = 42; }
    if (id === '133') nodes.find(row => row.id === ({ P: 100, S: 200, keep: 300 } as Record<string, number>)[node])!.ipAddresses = p.ipAddresses!.split(',');
    if (drop) { incoming.socket.destroy(); return {}; }
    return ok(['129', '130'].includes(id) ? undefined : state(node));
  });
  const read = async (node: string): Promise<ReturnType<typeof state>> => {
    const result = await run(executable, ['admin', 'cluster', 'state', '--config', config, '--node', node, '--full', '--json'], { env: { ...env, WRITE_TOKEN: token } });
    assert.equal(result.code, 0, result.stdout + result.stderr);
    return JSON.parse(result.stdout).response;
  };
  for (const [id, command, path, parameters] of cases.filter(([id]) => task === 'B5.03' || task === `B5.OP-${id}`)) {
    reset(id);
    await configure([`OP-${id}`], { origin: vendors.origins[['127', '128', '129', '130', '131', '132'].includes(id) ? 1 : 0] });
    const full = `admin cluster ${command}`;
    const input = { parameters };
    const traceStart = vendors.traces.length;
    const preview = await success(full, input);
    const result = await success(full, input, ['--execute', '--confirm', preview.preview.digest]);
    assert.equal(result.operation, `OP-${id}`);
    const primary = await read('P');
    const secondary = await read('S');
    if (id === '119') assert.deepEqual(primary.clusterNodes!.find(row => row.id === 100)!.ipAddresses, ['192.0.2.10']);
    if (id === '120') assert.equal(primary.clusterInitialized, false);
    if (id === '121' || id === '127') assert.equal(secondary.clusterNodes!.find(row => row.id === 200)!.type, 'Secondary');
    if (id === '122' || id === '123') {
      assert.deepEqual(primary.clusterNodes!.map(row => row.id), [100, 300]);
      assert.equal(secondary.clusterInitialized, id === '123');
      assert.equal(vendors.traces.slice(traceStart).some(row => row.path === '/api/admin/cluster/secondary/leave' && row.identity === 'beta'), id === '122');
    }
    if (id === '124') assert.equal(primary.clusterNodes!.find(row => row.id === 200)!.url, nextUrl);
    if (id === '126') assert.deepEqual(Object.fromEntries(Object.keys(timers).map(key => [key, primary[key]])), parameters);
    if (id === '128') { assert.equal(secondary.clusterInitialized, false); assert.deepEqual(primary.clusterNodes!.map(row => row.id), [100, 300]); }
    if (id === '129' || id === '131') {
      const primary = secondary.clusterNodes!.find(row => row.id === 100);
      assert.equal(primary!.name, 'dns-new.cluster.example.test');
      assert.equal(primary!.url, nextUrl);
      assert.deepEqual(primary!.ipAddresses, ['192.0.2.11']);
    }
    if (id === '129' || id === '130') {
      assert.equal(pulls, 1);
      assert.equal(secondary.clusterNodes!.find(row => row.id === 200)!.configLastSynced, '2024-01-01T00:00:01Z');
    }
    if (['121', '127', '129', '130', '132'].includes(id)) {
      for (const zone of ['example.test', 'keep.test']) {
        const response = await run(executable, ['zone', 'record', 'get', '--zone', zone, '--domain', zone, '--list-zone', 'true', '--config', config, '--full', '--json'], { env: { ...env, WRITE_TOKEN: token } });
        assert.equal(response.code, 0, response.stdout);
        const records = JSON.parse(response.stdout).response.records;
        assert.deepEqual(records, zone === 'keep.test'
          ? [{ name: 'keep.test', type: 'TXT', ttl: 60, rData: { text: 'preserved local zone' } }]
          : [{ name: 'example.test', type: 'SOA', ttl: 60, rData: { primaryNameServer: 'dns-p.cluster.example.test', responsiblePerson: 'hostmaster.example.test', serial: 42, refresh: 900, retry: 300, expire: 86400, minimum: 60 } }]);
      }
    }
    if (id === '132') assert.deepEqual(secondary.clusterNodes!.map(row => [row.id, row.type]), [[200, 'Primary'], [300, 'Secondary']]);
    if (id === '133') { assert.deepEqual(secondary.clusterNodes!.find(row => row.id === 200)!.ipAddresses, ['192.0.2.21', '2001:db8::21']); assert.deepEqual(primary.clusterNodes!.find(row => row.id === 100)!.ipAddresses, ['192.0.2.10']); }
    reset(id);
    deny = true;
    const before = await read('P');
    const denied = await success(full, input);
    await failure('OUTCOME_UNKNOWN', full, input, ['--execute', '--confirm', denied.preview.digest]);
    assert.deepEqual(await read('P'), before);
    if (Object.hasOwn(parameters, 'node') || ['120', '126', '128', '130', '131', '132'].includes(id)) await failure('USAGE', full, { parameters: { ...parameters, node: 'cluster' } });
    if (id === '127') {
      await failure('USAGE', full, { parameters: { ...parameters, primaryNodePassword: secret } });
      await failure('USAGE', full, input, ['--primary-node-password', secret!]);
    }
    if (id === '120') {
      reset(id);
      parameters.forceDelete = false;
      const refused = await success(full, input);
      await failure('OUTCOME_UNKNOWN', full, input, ['--execute', '--confirm', refused.preview.digest]);
      assert.deepEqual((await read('P')).clusterNodes!.map(row => row.id), [100, 200, 300]);
      nodes = nodes.filter(row => row.id === 100);
      await execute(full, input);
      assert.equal((await read('P')).clusterInitialized, false);
      parameters.forceDelete = true;
    }
    if (id === '126') {
      reset(id);
      const partial = { parameters: { configRetryIntervalSeconds: 90 } };
      const original = vendors.responders.get(`/api/admin/cluster/${path}`);
      vendors.responders.set(`/api/admin/cluster/${path}`, (_incoming, bytes) => {
        assert.deepEqual(Object.fromEntries(new URLSearchParams(bytes.toString())), { configRetryIntervalSeconds: '90' });
        options.configRetryIntervalSeconds = 90;
        return ok(state('P'));
      });
      await execute(full, partial);
      const actual = await read('P');
      assert.deepEqual(Object.fromEntries(Object.keys(timers).map(key => [key, actual[key]])), { ...timers, configRetryIntervalSeconds: 90 });
      const beforeRequests = vendors.traces.length;
      await failure('USAGE', full, { parameters: { heartbeatRefreshIntervalSeconds: 9 } });
      assert.equal(vendors.traces.length, beforeRequests);
      await failure('USAGE', full, { parameters: { configRefreshIntervalSeconds: 30, heartbeatRefreshIntervalSeconds: 45 } });
      vendors.responders.set(`/api/admin/cluster/${path}`, original!);
    }
    if (id === '128' || id === '132') {
      reset(id); unreachablePrimary = true;
      const key = id === '128' ? 'forceLeave' : 'forceDeletePrimary';
      parameters[key] = true;
      const forced = await execute(full, input);
      assert.equal(forced.cluster.uncertainty, 'Remote nodes may retain cluster configuration; verify them with explicit trusted profiles');
      assert.equal((await read('P')).clusterInitialized, true);
      if (id === '128') { assert.equal((await read('S')).clusterInitialized, false); assert.deepEqual((await read('P')).clusterNodes!.map(row => row.id), [100, 200, 300]); }
      else assert.equal((await read('S')).clusterNodes!.find(row => row.id === 200)!.type, 'Primary');
      parameters[key] = false;
    }
    if (id === '129') {
      for (const primaryNodeId of [-1, 300]) {
        reset(id);
        parameters.primaryNodeId = primaryNodeId;
        await execute(full, input);
        assert.deepEqual((await read('S')).clusterNodes!.map(({ id, name, type, state, ipAddresses }) => [id, name, type, state, ipAddresses]), primaryNodeId === -1
          ? [[100, 'dns-new.cluster.example.test', 'Primary', 'Connected', ['192.0.2.11']], [200, 'dns-s.cluster.example.test', 'Secondary', 'Self', ['192.0.2.20']], [300, 'keep.cluster.example.test', 'Secondary', 'Connected', ['192.0.2.30']]]
          : [[200, 'dns-s.cluster.example.test', 'Secondary', 'Self', ['192.0.2.20']], [300, 'dns-new.cluster.example.test', 'Primary', 'Connected', ['192.0.2.11']]]);
      }
      parameters.primaryNodeId = 100;
      reset(id);
      const invalid = { parameters: { ...parameters, primaryNodeId: 999 } };
      const wrong = await success(full, invalid);
      await failure('OUTCOME_UNKNOWN', full, invalid, ['--execute', '--confirm', wrong.preview.digest]);
      assert.equal(pulls, 0);
      assert.equal((await read('S')).clusterNodes!.find(row => row.id === 100)!.url, pUrl);
    }
    if (id === '130') {
      reset(id); drop = true;
      const pending = await success(full, input);
      const dispatched = vendors.traces.filter(row => row.path === `/api/admin/cluster/${path}`).length;
      const unknown = await failure('OUTCOME_UNKNOWN', full, input, ['--execute', '--confirm', pending.preview.digest]);
      const auditId = unknown.error.message.match(/audit ID ([a-f0-9-]+)/)![1];
      await failure('OUTCOME_UNKNOWN', full, input, ['--confirm', pending.preview.digest, '--reconcile', auditId!]);
      await failure('CONFIRMATION_MISMATCH', full, input, ['--confirm', `${pending.preview.digest.split('.')[0]}.${'0'.repeat(64)}`, '--reconcile', auditId!]);
      await failure('REPLAY_DENIED', full, input, ['--execute', '--confirm', pending.preview.digest]);
      assert.equal(vendors.traces.filter(row => row.path === `/api/admin/cluster/${path}`).length, dispatched + 1);
    }
    if (id === '119' || id === '127') {
      const beforeInvalid = vendors.traces.length;
      await failure('USAGE', full, input, ['--confirm', '../../config', '--reconcile', 'invalid']);
      assert.equal(vendors.traces.length, beforeInvalid, 'Malformed confirmations must fail before journal lookup or dispatch');
      reset(id); drop = true;
      const pending = await success(full, input);
      const unknown = await failure('OUTCOME_UNKNOWN', full, input, ['--execute', '--confirm', pending.preview.digest]);
      const auditId = unknown.error.message.match(/audit ID ([a-f0-9-]+)/)![1];
      replacementNode = id === '119' ? 'P' : 'S';
      const settings = JSON.parse(await readFile(config, 'utf8'));
      settings.defaultProfile = 'alpha';
      settings.profiles.replacement = { ...settings.profiles.alpha, origin: vendors.origins[1] };
      await writeFile(config, JSON.stringify(settings));
      // Only the explicitly selected trusted binding may receive a reconciliation read.
      const readsBefore = vendors.traces.filter(row => row.identity === 'beta').length;
      if (id === '119') await failure('OUTCOME_UNKNOWN', full, input, ['--confirm', pending.preview.digest, '--reconcile', auditId!]);
      assert.equal(vendors.traces.filter(row => row.identity === 'beta').length, readsBefore);
      const reconciled = await success(full, input, ['--confirm', pending.preview.digest, '--reconcile', auditId!, '--reconcile-profile', 'replacement']);
      assert.equal(reconciled.verifiedProfile, 'replacement');
      replacementNode = undefined;
      assert.equal((await read(id === '119' ? 'P' : 'S')).clusterInitialized, true);
    }
  }
  if (task === 'B5.03') {
    const settings: Record<string, { version: string; dnsServerDomain: string; defaultRecordTtl: number; webServiceHttpPort: number }> = { P: { version: '15.4', dnsServerDomain: 'dns-p.cluster.example.test', defaultRecordTtl: 300, webServiceHttpPort: 5380 }, S: { version: '15.4', dnsServerDomain: 'dns-s.cluster.example.test', defaultRecordTtl: 300, webServiceHttpPort: 5381 } };
    vendors.responders.set('/api/settings/get', incoming => ok(settings[selected(incoming, {})]));
    vendors.responders.set('/api/settings/set', (incoming, bytes) => {
      assert.equal(selected(incoming, {}), 'S');
      assert.deepEqual(Object.fromEntries(new URLSearchParams(bytes.toString())), { defaultRecordTtl: '600', webServiceHttpPort: '8080' });
      settings.S = { ...settings.S!, defaultRecordTtl: 600, webServiceHttpPort: 8080 };
      settings.P!.defaultRecordTtl = 600;
      return ok(settings.S);
    });
    await configure(['OP-080'], { origin: vendors.origins[1] });
    const input = { parameters: { defaultRecordTtl: 600, webServiceHttpPort: 8080 }, baseline: { defaultRecordTtl: 300, webServiceHttpPort: 5381 } };
    const preview = await success('settings set', input);
    assert.equal(preview.preview.routing.replication, 'Listeners and local settings stay local; cluster parameters propagate through the primary');
    await success('settings set', input, ['--execute', '--confirm', preview.preview.digest]);
    for (const [index, expected] of [[0, { version: '15.4', dnsServerDomain: 'dns-p.cluster.example.test', defaultRecordTtl: 600, webServiceHttpPort: 5380 }], [1, { version: '15.4', dnsServerDomain: 'dns-s.cluster.example.test', defaultRecordTtl: 600, webServiceHttpPort: 8080 }]] satisfies [number, Record<string, unknown>][]) {
      await configure([], { origin: vendors.origins[index!] });
      const result = await run(executable, ['settings', 'get', '--config', config, '--json'], { env: { ...env, WRITE_TOKEN: token } });
      assert.equal(result.code, 0, result.stdout);
      assert.deepEqual(JSON.parse(result.stdout).response, expected);
    }
  }
  for (const file of await readdir(join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d'))) {
    const bytes = await readFile(join(env.XDG_STATE_HOME, 'technitium-axi', 'writes.log.d', file), 'utf8');
    for (const canary of [token, secret]) assert.ok(!bytes.includes(canary!));
  }
}
