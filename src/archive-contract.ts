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
