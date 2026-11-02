export interface WriteContract {
  id: string; command: string; path: string;
  fields: string[]; required: string[]; secrets?: string[];
  baselinePath?: string; baselineTarget?: string[];
}

export const recordTypeNames: Record<number, string> = {
  0: 'Unknown', 1: 'A', 2: 'NS', 3: 'MD', 4: 'MF', 5: 'CNAME', 6: 'SOA', 7: 'MB', 8: 'MG', 9: 'MR',
  10: 'NULL', 11: 'WKS', 12: 'PTR', 13: 'HINFO', 14: 'MINFO', 15: 'MX', 16: 'TXT', 17: 'RP', 18: 'AFSDB',
  19: 'X25', 20: 'ISDN', 21: 'RT', 22: 'NSAP', 23: 'NSAP_PTR', 24: 'SIG', 25: 'KEY', 26: 'PX', 27: 'GPOS',
  28: 'AAAA', 29: 'LOC', 30: 'NXT', 31: 'EID', 32: 'NIMLOC', 33: 'SRV', 34: 'ATMA', 35: 'NAPTR', 36: 'KX',
  37: 'CERT', 38: 'A6', 39: 'DNAME', 40: 'SINK', 41: 'OPT', 42: 'APL', 43: 'DS', 44: 'SSHFP', 45: 'IPSECKEY',
  46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 49: 'DHCID', 50: 'NSEC3', 51: 'NSEC3PARAM', 52: 'TLSA', 53: 'SMIMEA',
  55: 'HIP', 56: 'NINFO', 57: 'RKEY', 58: 'TALINK', 59: 'CDS', 60: 'CDNSKEY', 61: 'OPENPGPKEY', 62: 'CSYNC',
  63: 'ZONEMD', 64: 'SVCB', 65: 'HTTPS', 99: 'SPF', 100: 'UINFO', 101: 'UID', 102: 'GID', 103: 'UNSPEC',
  104: 'NID', 105: 'L32', 106: 'L64', 107: 'LP', 108: 'EUI48', 109: 'EUI64', 128: 'NXNAME', 249: 'TKEY',
  250: 'TSIG', 251: 'IXFR', 252: 'AXFR', 253: 'MAILB', 254: 'MAILA', 255: 'ANY', 256: 'URI', 257: 'CAA',
  258: 'AVC', 259: 'DOA', 260: 'AMTRELAY', 261: 'RESINFO', 262: 'WALLET', 263: 'CLA', 264: 'IPN',
  32768: 'TA', 32769: 'DLV', 65280: 'ANAME', 65281: 'FWD', 65282: 'APP', 65283: 'CHILD_NS', 65284: 'PARENT_NS', 65357: 'ALIAS',
};

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
  { id: 'OP-022', command: 'zone create', path: '/api/zones/create', fields: words('node zone type catalog useSoaSerialDateScheme primaryNameServerAddresses zoneTransferProtocol tsigKeyName validateZone initializeForwarder protocol forwarder dnssecValidation proxyType proxyAddress proxyPort proxyUsername proxyPassword'), required: ['zone', 'type'], secrets: ['proxyPassword'] },
  { id: 'OP-023', command: 'zone import', path: '/api/zones/import', fields: words('node zone overwrite overwriteZone overwriteSoaSerial records'), required: ['zone'] },
  { id: 'OP-032', command: 'zone options set', path: '/api/zones/options/set', fields: words('node zone disabled catalog overrideCatalogQueryAccess overrideCatalogZoneTransfer overrideCatalogNotify primaryNameServerAddresses primaryZoneTransferProtocol primaryZoneTransferTsigKeyName validateZone queryAccess queryAccessNetworkACL zoneTransfer zoneTransferNetworkACL zoneTransferTsigKeyNames notify notifyNameServers notifySecondaryCatalogsNameServers update updateNetworkACL updateSecurityPolicies'), required: ['zone'], baselinePath: '/api/zones/options/get', baselineTarget: ['zone', 'node'] },
  { id: 'OP-035', command: 'zone dnssec sign', path: '/api/zones/dnssec/sign', fields: words('node zone algorithm pemKskPrivateKey pemZskPrivateKey hashAlgorithm kskKeySize zskKeySize curve dnsKeyTtl zskRolloverDays nxProof iterations saltLength'), required: ['zone', 'algorithm'], secrets: ['pemKskPrivateKey', 'pemZskPrivateKey'] },
  { id: 'OP-036', command: 'zone dnssec unsign', path: '/api/zones/dnssec/unsign', fields: words('node zone'), required: ['zone'] },
  ...[
    ['OP-039', 'convert-to-nsec', 'convertToNSEC', '', ''],
    ['OP-040', 'convert-to-nsec3', 'convertToNSEC3', 'iterations saltLength', ''],
    ['OP-041', 'update-nsec3-params', 'updateNSEC3Params', 'iterations saltLength', ''],
    ['OP-042', 'update-dns-key-ttl', 'updateDnsKeyTtl', 'ttl', 'ttl'],
    ['OP-044', 'update-private-key', 'updatePrivateKey', 'keyTag rolloverDays', 'keyTag rolloverDays'],
    ['OP-045', 'delete-private-key', 'deletePrivateKey', 'keyTag', 'keyTag'],
    ['OP-046', 'publish-all-private-keys', 'publishAllPrivateKeys', '', ''],
    ['OP-047', 'rollover-dns-key', 'rolloverDnsKey', 'keyTag', 'keyTag'],
    ['OP-048', 'retire-dns-key', 'retireDnsKey', 'keyTag', 'keyTag'],
  ].map(([id, command, path, fields, required]) => ({ id: id!, command: `zone dnssec properties ${command}`, path: `/api/zones/dnssec/properties/${path}`,
    fields: words(`node zone ${fields}`.trim()), required: words(`zone ${required}`.trim()) })),
  { id: 'OP-140', command: 'zone dnssec properties activate-ksk-dns-key', path: '/api/zones/dnssec/properties/activateKskDnsKey', fields: words('zone keyTag'), required: words('zone keyTag') },
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
