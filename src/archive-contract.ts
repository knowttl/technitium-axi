import { ToolError } from './errors.js';

// Entry names and selection rules reviewed against the pinned vendor handlers.
export const archiveContract = {
  sourceRevision: '0dd592aad21eced4221a9a46204cb1a299972ca0',
  sources: {
    'DnsWebService.cs': '1e2f492baa3113d09704589bf0109fd4c9bbc05f65204918d0d485ba8ae5753e',
    'WebServiceClusterApi.cs': '2bb0efaa14335f9bfa74844db917021a2d2869604d1531b2e85e3105cad1e6d5',
    'Cluster/ClusterManager.cs': '787086de7f3a2b625e788042d4f8ef2aa8d6ef27c9d235be2ffc94922d4ff496',
  },
  backup: {
    authConfig: ['auth.config'], clusterConfig: ['cluster.config'],
    webServiceSettings: ['webservice.config', '<certificate-relative-path-within-config>'],
    dnsSettings: ['dns.config', '<certificate-relative-path-within-config>'],
    logSettings: ['log.config'], zones: ['zones/*.zone'], allowedZones: ['allowed.config'],
    blockedZones: ['blocked.config'], blockLists: ['blocklist.config', 'blocklists/*'],
    apps: ['apps/**/*'], scopes: ['scopes/*.scope'], stats: ['stats/*.stat', 'stats/*.dstat'], logs: ['logs/*.log'],
  },
  transfer: {
    changedFiles: ['auth.config', 'dns.config', 'allowed.config', 'blocked.config', 'blocklist.config'],
    excludedComponents: ['clusterConfig', 'webServiceSettings', 'logSettings', 'scopes', 'stats', 'logs'],
    excludedEntries: ['zones/*.zone', 'blocklists/*', '<certificate-relative-path-within-config>'],
    comparison: 'file mtime > If-Modified-Since; DNSSEC key StateChangedOn > If-Modified-Since',
    keys: 'zones/<zone-name>.keys: signed Primary members of the cluster catalog; includeZones forces eligible selected names, changed unselected keys remain eligible',
    appEntries: { unchanged: 'apps/<name>/.exists', package: 'apps/<name>/<name>.zip', config: 'apps/<name>/dnsApp.config' },
    appMarker: 'Emit zero-byte .exists only when neither package nor config is newer; empty and key-only worlds have no app directories',
    response: { status: 200, contentType: 'application/zip', lastModified: 'RFC 1123 GMT response time', emptyZip: 'valid protected result' },
  },
};

export function validateUploadArchive(bytes: Buffer): void {
  const invalid = (): never => { throw new ToolError('UPLOAD_INVALID', 'Upload must be a bounded ZIP with safe relative entry names and no links', 'Select a valid app package or settings backup'); };
  let end = bytes.length - 22;
  const minimum = Math.max(0, end - 65535);
  while (end >= minimum && bytes.readUInt32LE(end) !== 0x06054b50) end--;
  if (end < minimum || end + 22 + bytes.readUInt16LE(end + 20) !== bytes.length || bytes.readUInt16LE(end + 4) !== 0 || bytes.readUInt16LE(end + 6) !== 0) invalid();
  const count = bytes.readUInt16LE(end + 10);
  let offset = bytes.readUInt32LE(end + 16);
  const centralEnd = offset + bytes.readUInt32LE(end + 12);
  if (count !== bytes.readUInt16LE(end + 8) || centralEnd !== end) invalid();
  for (let i = 0; i < count; i++) {
    if (offset + 46 > centralEnd || bytes.readUInt32LE(offset) !== 0x02014b50) invalid();
    const length = bytes.readUInt16LE(offset + 28);
    const next = offset + 46 + length + bytes.readUInt16LE(offset + 30) + bytes.readUInt16LE(offset + 32);
    if (next > centralEnd) invalid();
    const name = bytes.subarray(offset + 46, offset + 46 + length).toString('utf8');
    if (!name || /[\\\x00-\x1f]/.test(name) || name.startsWith('/') || /^[A-Za-z]:/.test(name) || name.split('/').includes('..') || (bytes.readUInt32LE(offset + 38) >>> 16 & 0xf000) === 0xa000) invalid();
    offset = next;
  }
  if (offset !== centralEnd) invalid();
}
