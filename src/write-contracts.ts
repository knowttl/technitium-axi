export interface WriteContract {
  id: string; command: string; path: string;
  fields: string[]; required: string[]; secrets?: string[];
  baselinePath?: string; baselineTarget?: string[];
}

// Reviewed against DNS Server 0dd592aad21eced4221a9a46204cb1a299972ca0.
// Selectors describe vendor matching, including composite keys and owner/type singletons.
export const recordFamilies: Record<string, { selector: string[]; replacement: string[]; optional?: string[] }> = {
  A: { selector: ['ipAddress'], replacement: ['newIpAddress'], optional: ['ptr', 'createPtrZone', 'updateSvcbHints'] },
  AAAA: { selector: ['ipAddress'], replacement: ['newIpAddress'], optional: ['ptr', 'createPtrZone', 'updateSvcbHints'] },
  NS: { selector: ['nameServer'], replacement: ['newNameServer'], optional: ['glue'] },
  CNAME: { selector: [], replacement: ['cname'] },
  DNAME: { selector: [], replacement: ['dname'] },
  PTR: { selector: ['ptrName'], replacement: ['newPtrName'] },
  MX: { selector: ['preference', 'exchange'], replacement: ['newPreference', 'newExchange'] },
  TXT: { selector: ['text'], replacement: ['newText'], optional: ['splitText', 'newSplitText', 'characterStringsBase64', 'newCharacterStringsBase64'] },
  RP: { selector: ['mailbox', 'txtDomain'], replacement: ['newMailbox', 'newTxtDomain'] },
  SRV: { selector: ['priority', 'weight', 'port', 'target'], replacement: ['newPriority', 'newWeight', 'newPort', 'newTarget'] },
  NAPTR: { selector: ['naptrOrder', 'naptrPreference', 'naptrFlags', 'naptrServices', 'naptrRegexp', 'naptrReplacement'],
    replacement: ['naptrNewOrder', 'naptrNewPreference', 'naptrNewFlags', 'naptrNewServices', 'naptrNewRegexp', 'naptrNewReplacement'] },
  DS: { selector: ['keyTag', 'algorithm', 'digestType', 'digest'], replacement: ['newKeyTag', 'newAlgorithm', 'newDigestType', 'newDigest'] },
  SSHFP: { selector: ['sshfpAlgorithm', 'sshfpFingerprintType', 'sshfpFingerprint'], replacement: ['newSshfpAlgorithm', 'newSshfpFingerprintType', 'newSshfpFingerprint'] },
  TLSA: { selector: ['tlsaCertificateUsage', 'tlsaSelector', 'tlsaMatchingType', 'tlsaCertificateAssociationData'],
    replacement: ['newTlsaCertificateUsage', 'newTlsaSelector', 'newTlsaMatchingType', 'newTlsaCertificateAssociationData'] },
  SVCB: { selector: ['svcPriority', 'svcTargetName', 'svcParams'], replacement: ['newSvcPriority', 'newSvcTargetName', 'newSvcParams'], optional: ['autoIpv4Hint', 'autoIpv6Hint'] },
  HTTPS: { selector: ['svcPriority', 'svcTargetName', 'svcParams'], replacement: ['newSvcPriority', 'newSvcTargetName', 'newSvcParams'], optional: ['autoIpv4Hint', 'autoIpv6Hint'] },
  URI: { selector: ['uriPriority', 'uriWeight', 'uri'], replacement: ['newUriPriority', 'newUriWeight', 'newUri'] },
  CAA: { selector: ['flags', 'tag', 'value'], replacement: ['newFlags', 'newTag', 'newValue'] },
  ANAME: { selector: ['aname'], replacement: ['newAName'] },
  FWD: { selector: ['protocol', 'forwarder'], replacement: ['newProtocol', 'newForwarder'],
    optional: ['dnssecValidation', 'proxyType', 'proxyAddress', 'proxyPort', 'proxyUsername', 'proxyPassword', 'forwarderPriority'] },
  APP: { selector: [], replacement: ['appName', 'classPath', 'recordData'] },
  SOA: { selector: [], replacement: ['primaryNameServer', 'responsiblePerson', 'serial', 'refresh', 'retry', 'expire', 'minimum'], optional: ['useSerialDateScheme'] },
  raw: { selector: ['rdata'], replacement: ['newRData'] },
};
const words = (value: string) => value.split(' ');
const recordFields = [...new Set(Object.values(recordFamilies).flatMap(row => [...row.selector, ...row.replacement, ...row.optional ?? []]))];
export const writeContracts: WriteContract[] = [
  { id: 'OP-019', command: 'dashboard stats delete-all', path: '/api/dashboard/stats/deleteAll', fields: ['node'], required: [] },
  { id: 'OP-022', command: 'zone create', path: '/api/zones/create', fields: words('node zone type catalog useSoaSerialDateScheme primaryNameServerAddresses zoneTransferProtocol tsigKeyName validateZone initializeForwarder protocol forwarder dnssecValidation proxyType proxyAddress proxyPort proxyUsername proxyPassword domain'), required: ['zone', 'type'], secrets: ['proxyPassword'] },
  { id: 'OP-023', command: 'zone import', path: '/api/zones/import', fields: words('node zone overwrite overwriteZone overwriteSoaSerial records'), required: ['zone'] },
  { id: 'OP-032', command: 'zone options set', path: '/api/zones/options/set', fields: words('node zone disabled catalog overrideCatalogQueryAccess overrideCatalogZoneTransfer overrideCatalogNotify primaryNameServerAddresses primaryZoneTransferProtocol primaryZoneTransferTsigKeyName validateZone queryAccess queryAccessNetworkACL zoneTransfer zoneTransferNetworkACL zoneTransferTsigKeyNames notify notifyNameServers notifySecondaryCatalogsNameServers update updateNetworkACL updateSecurityPolicies'), required: ['zone'], baselinePath: '/api/zones/options/get', baselineTarget: ['zone', 'node'] },
  { id: 'OP-035', command: 'zone dnssec sign', path: '/api/zones/dnssec/sign', fields: words('node zone algorithm pemKskPrivateKey pemZskPrivateKey hashAlgorithm kskKeySize zskKeySize curve dnsKeyTtl zskRolloverDays nxProof iterations saltLength'), required: ['zone', 'algorithm'], secrets: ['pemKskPrivateKey', 'pemZskPrivateKey'] },
  { id: 'OP-043', command: 'zone dnssec properties add-private-key', path: '/api/zones/dnssec/properties/addPrivateKey', fields: words('node zone keyType rolloverDays algorithm pemPrivateKey hashAlgorithm keySize curve'), required: ['zone', 'keyType', 'algorithm'], secrets: ['pemPrivateKey'] },
  ...[['OP-049', 'add'], ['OP-051', 'update'], ['OP-052', 'delete']].map(([id, action]) => ({ id: id!, command: `zone record ${action}`, path: `/api/zones/records/${action}`,
    fields: [...words('node zone domain type ttl overwrite comments expiryTtl newDomain disable'), ...recordFields], required: ['zone', 'domain', 'type'], secrets: ['proxyPassword'] })),
  { id: 'OP-077', command: 'dns-client resolve', path: '/api/dnsClient/resolve', fields: words('node server domain type protocol dnssec eDnsClientSubnet import'), required: ['server', 'domain', 'type'] },
  // Other settings fields are introduced with their domain operation journeys.
  { id: 'OP-080', command: 'settings set', path: '/api/settings/set', fields: words('blockListUrls forwarders proxyBypass'), required: [], baselinePath: '/api/settings/get', baselineTarget: [] },
  { id: 'OP-109', command: 'admin group set', path: '/api/admin/groups/set', fields: words('group newGroup description members'), required: ['group'], baselinePath: '/api/admin/groups/get', baselineTarget: ['group'] },
  { id: 'OP-143', command: 'admin ldap test', path: '/api/admin/ldap/test', fields: words('ldapServer ldapPort ldapSslOption ldapIgnoreSslErrors ldapBindUsername ldapBindPassword ldapSearchBase ldapUserSearchFilter ldapGroupAttribute'), required: [], secrets: ['ldapBindPassword'] },
];

export const writeFlags = ['--json', '--help', '--config', '--profile', '--input-file', '--execute', '--confirm', '--result-file', '--reconcile'];
export const writeCapabilities = writeContracts.flatMap(row => row.id === 'OP-077' ? ['OP-077.import'] : [row.id]);
