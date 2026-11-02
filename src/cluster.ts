import { X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import type { Profile } from './credentials.js';
import { ToolError } from './errors.js';
import { vendorRequest, checkStatus } from './vendor.js';

type Node = { id: number; name: string; url: string; ipAddresses: string[]; type: string; state: string; configLastSynced?: string };
export type ClusterState = { clusterInitialized: boolean; clusterDomain?: string; clusterNodes: Node[]; [key: string]: unknown };
export const clusterTimers = ['heartbeatRefreshIntervalSeconds', 'heartbeatRetryIntervalSeconds', 'configRefreshIntervalSeconds', 'configRetryIntervalSeconds'];
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const fail = (message: string): never => { throw new ToolError('USAGE', message, 'Use the cluster input contract shown in inventory'); };

export function validateCluster(parameters: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(parameters)) {
    if (key.endsWith('IpAddresses') || key === 'ipAddresses') {
      if (!Array.isArray(value) || value.length === 0 || value.some(ip => typeof ip !== 'string' || !isIP(ip))) fail(`${key} requires a nonempty array of IP addresses`);
    } else if (key.endsWith('NodeId')) {
      if (!Number.isInteger(value) || Number(value) < -2147483648 || Number(value) > 2147483647) fail(`${key} requires a signed 32-bit integer`);
    } else if (key.endsWith('NodeUrl')) {
      let url: URL;
      try { url = new URL(String(value)); } catch { fail(`${key} requires an HTTPS URL`); }
      if (url!.protocol !== 'https:' || url!.username || url!.password || url!.search || url!.hash || url!.pathname !== '/') fail(`${key} requires an HTTPS origin without credentials`);
    } else if (key === 'primaryNodeIpAddress' && (typeof value !== 'string' || !isIP(value))) fail('primaryNodeIpAddress requires an IP address');
    else if (key === 'secondaryNodeCertificate') {
      if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+={0,2}$/.test(value)) fail('secondaryNodeCertificate requires a base64url DER certificate');
      try { new X509Certificate(Buffer.from(value as string, 'base64url')); } catch { fail('secondaryNodeCertificate requires a base64url DER certificate'); }
    } else if (clusterTimers.includes(key)) {
      const min = key.startsWith('heartbeat') ? 10 : 30;
      const max = key.startsWith('heartbeat') ? 300 : 3600;
      if (!Number.isInteger(value) || Number(value) < min || Number(value) > max) fail(`${key} must be between ${min} and ${max}`);
    }
  }
}

export async function clusterState(profile: Profile, token: string, node: unknown): Promise<ClusterState> {
  const body = node === undefined ? '' : new URLSearchParams({ node: String(node) }).toString();
  const result = await vendorRequest(profile, '/api/admin/cluster/state', body, token, {}, { bytes: 1024 * 1024, elapsedMs: 10000 });
  if (result.status !== 200 || result.contentType !== 'application/json') throw new ToolError('UPSTREAM_INVALID', 'Cluster state read failed', 'Read cluster state using an explicitly trusted profile', 1);
  const value: unknown = JSON.parse(result.bytes.toString());
  checkStatus(value);
  const state = value.response;
  if (!object(state) || typeof state.clusterInitialized !== 'boolean' || state.clusterInitialized && (!Array.isArray(state.clusterNodes) || state.clusterNodes.some(row => !object(row) || !Number.isInteger(row.id) || typeof row.name !== 'string' || typeof row.url !== 'string' || !['Primary', 'Secondary'].includes(String(row.type)) || typeof row.state !== 'string' || !Array.isArray(row.ipAddresses) || row.ipAddresses.some(ip => typeof ip !== 'string' || !isIP(ip))))) {
    throw new ToolError('UPSTREAM_INVALID', 'Invalid cluster state', 'Check the selected server API version', 1);
  }
  // Heartbeats and synchronization timestamps change independently of the topology being approved.
  return { clusterInitialized: state.clusterInitialized,
    ...(state.clusterInitialized ? { clusterDomain: String(state.clusterDomain), ...Object.fromEntries(clusterTimers.map(key => [key, state[key]])) } : {}),
    clusterNodes: state.clusterInitialized ? (state.clusterNodes as Node[]).map(row => ({ id: row.id, name: row.name, url: row.url, ipAddresses: row.ipAddresses, type: row.type, state: row.state === 'Self' ? 'Self' : 'Remote' })).sort((a, b) => a.id - b.id) : [] };
}

export function clusterPreview(id: string, p: Record<string, unknown>, before: ClusterState) {
  const effects: Record<string, string> = {
    'OP-119': 'Initialize the selected node as primary; TLS listeners and identity may change',
    'OP-120': 'Delete selected primary cluster configuration; remote nodes are not reset',
    'OP-121': 'Add secondary membership and notify replicated configuration',
    'OP-122': 'Ask the selected secondary to leave; remote completion requires a separate trusted read',
    'OP-123': 'Delete primary membership only; the removed secondary is not reset',
    'OP-124': 'Replace selected secondary address and certificate; notify replicated configuration',
    'OP-126': 'Change cluster timers; omitted timers remain unchanged',
    'OP-127': 'Join selected node as secondary and replace replicated configuration; TLS identity may change',
    'OP-128': 'Leave selected secondary; force can leave stale primary membership',
    'OP-129': 'Update primary identity and schedule configuration synchronization',
    'OP-130': 'Trigger asynchronous configuration and cluster secondary zone resync',
    'OP-131': 'Update primary address on selected secondary; replacement origin is not automatically trusted',
    'OP-132': 'Promote selected secondary and remove old primary membership; force skips old primary synchronization and deletion',
    'OP-133': 'Update selected node addresses; TLS trust remains unchanged',
  };
  return { scope: p.node === undefined ? 'selected node' : 'named node via vendor proxy', effects: effects[id],
    affectedNodes: before.clusterNodes.map(({ id, name, type }) => ({ id, name, type })),
    completion: ['OP-129', 'OP-130'].includes(id) ? 'scheduled, not synchronized' : 'selected-node state only',
    ...(id === 'OP-127' ? { primaryNodeUrl: p.primaryNodeUrl, ignoreCertificateErrors: p.ignoreCertificateErrors ?? false } : {}),
    ...(p.forceLeave || p.forceDeletePrimary || p.forceDelete ? { uncertainty: 'Remote nodes may retain cluster configuration; verify them with explicit trusted profiles' } : {}) };
}

export function clusterMatches(id: string, p: Record<string, unknown>, before: ClusterState, after: ClusterState): boolean {
  const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
  const self = after.clusterNodes.find(row => row.state === 'Self');
  const oldSelf = before.clusterNodes.find(row => row.state === 'Self');
  const primary = after.clusterNodes.find(row => row.type === 'Primary');
  const oldPrimary = before.clusterNodes.find(row => row.type === 'Primary');
  if (['OP-120', 'OP-128'].includes(id)) return !after.clusterInitialized;
  if (!after.clusterInitialized) return false;
  if (id === 'OP-119') return after.clusterDomain === String(p.clusterDomain).replace(/\.+$/, '') && self?.type === 'Primary' && same(self.ipAddresses, p.primaryNodeIpAddresses);
  if (id === 'OP-127') return self?.type === 'Secondary' && same(self.ipAddresses, p.secondaryNodeIpAddresses) && primary?.url === p.primaryNodeUrl;
  if (after.clusterDomain !== before.clusterDomain) return false;
  let expected = structuredClone(before.clusterNodes);
  if (['OP-122', 'OP-123'].includes(id)) expected = expected.filter(row => row.id !== p.secondaryNodeId);
  else if (['OP-121', 'OP-124'].includes(id)) {
    const selected = after.clusterNodes.find(row => row.id === p.secondaryNodeId);
    if (!selected || selected.type !== 'Secondary' || selected.url !== p.secondaryNodeUrl || !same(selected.ipAddresses, p.secondaryNodeIpAddresses)) return false;
    expected = [...expected.filter(row => row.id !== p.secondaryNodeId), selected].sort((a, b) => a.id - b.id);
  } else if (['OP-129', 'OP-131'].includes(id)) {
    const selected = id === 'OP-129' && Number(p.primaryNodeId) >= 0 ? expected.find(row => row.id === p.primaryNodeId) : oldPrimary;
    if (!oldPrimary || !selected || selected.state === 'Self') return false;
    if (selected.id !== oldPrimary.id) expected = expected.filter(row => row.id !== oldPrimary.id);
    expected = expected.map(row => row.id === selected.id ? { ...row, name: new URL(String(p.primaryNodeUrl)).hostname.toLowerCase(), type: 'Primary', url: String(p.primaryNodeUrl), ipAddresses: p.primaryNodeIpAddresses as string[] ?? primary?.ipAddresses } : row);
  } else if (id === 'OP-132') {
    if (!oldSelf || !oldPrimary || oldSelf.type !== 'Secondary') return false;
    expected = expected.filter(row => row.id !== oldPrimary.id).map(row => row.id === oldSelf.id ? { ...row, type: 'Primary' } : row);
  } else if (id === 'OP-133') expected = expected.map(row => row.state === 'Self' ? { ...row, ipAddresses: p.ipAddresses as string[] } : row);
  return same(after.clusterNodes, expected) && clusterTimers.every(key => after[key] === (id === 'OP-126' ? p[key] ?? before[key] : before[key]));
}
