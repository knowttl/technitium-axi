import { ToolError } from './errors.js';
import { isAbsolute } from 'node:path';

type Field = { type: 'string' | 'boolean' | 'integer' | 'list' | 'ports' | 'rows'; columns?: string[]; secret?: boolean; read?: string };
const words = (text: string) => text.split(' ');
const group = (type: Field['type'], text: string): Record<string, Field> => Object.fromEntries(words(text).map(key => [key, { type }]));

// Reviewed against DNS Server 0dd592aad21eced4221a9a46204cb1a299972ca0.
export const settingsFields: Record<string, Field> = {
  ...group('string', 'dnsServerDomain defaultResponsiblePerson ipv6Mode eDnsClientSubnetIpv4Override eDnsClientSubnetIpv6Override webServiceHttpUnixSocket webServiceTlsUnixSocket webServiceTlsCertificatePath webServiceRealIpHeader webServiceCspFrameAncestorsHeader dnsOverHttpUnixSocket dnsOverHttpsUnixSocket dnsTlsCertificatePath dnsOverHttpRealIpHeader recursion blockingType proxyType proxyAddress proxyUsername forwarderProtocol loggingType logFolder'),
  ...group('boolean', 'useSoaSerialDateScheme dnsServerEnableCheckForUpdate dnsAppsEnableAutomaticUpdate enableUdpSocketPool dnssecValidation eDnsClientSubnet webServiceEnableHttpUnixSocket webServiceEnableTlsUnixSocket webServiceEnableTls webServiceEnableHttp3 webServiceHttpToTlsRedirect webServiceUseSelfSignedTlsCertificate enableEDnsClientSubnetSourceAddress enableDnsOverUdpProxy enableDnsOverTcpProxy enableDnsOverHttp enableDnsOverHttpUnixSocket enableDnsOverHttpsUnixSocket enableDnsOverTls enableDnsOverHttps enableDnsOverHttp3 enableDnsOverQuic enableDnsOverHttpHelpRedirect randomizeName qnameMinimization locallyServedDnsZones saveCache serveStale enableCachePrefetch enableBlocking allowTxtBlockingReport concurrentForwarding enableLogging ignoreResolverLogs logQueries noStackTrace useLocalTime enableInMemoryStats preferIPv6'),
  ...group('integer', 'defaultRecordTtl defaultNsRecordTtl defaultSoaRecordTtl minSoaRefresh minSoaRetry udpPayloadSize eDnsClientSubnetIPv4PrefixLength eDnsClientSubnetIPv6PrefixLength qpmLimitSampleMinutes qpmLimitUdpTruncationPercentage clientTimeout tcpSendTimeout tcpReceiveTimeout quicIdleTimeout quicMaxInboundStreams listenBacklog udpSendBufferSizeKB udpReceiveBufferSizeKB maxConcurrentResolutionsPerCore webServiceHttpPort webServiceTlsPort dnsOverUdpProxyPort dnsOverTcpProxyPort dnsOverHttpPort dnsOverTlsPort dnsOverHttpsPort dnsOverQuicPort resolverRetries resolverTimeout resolverConcurrency resolverMaxStackCount serveStaleTtl serveStaleAnswerTtl serveStaleResetTtl serveStaleMaxWaitTime cacheMaximumEntries cacheMinimumRecordTtl cacheMaximumRecordTtl cacheNegativeRecordTtl cacheFailureRecordTtl cachePrefetchEligibility cachePrefetchTrigger blockingAnswerTtl blockListUpdateIntervalHours proxyPort forwarderRetries forwarderTimeout forwarderConcurrency maxLogFileDays maxStatFileDays'),
  ...group('list', 'dnsServerLocalEndPoints dnsServerIPv4SourceAddresses dnsServerIPv6SourceAddresses zoneTransferAllowedNetworks notifyAllowedNetworks qpmLimitBypassList webServiceLocalAddresses webServiceReverseProxyAddresses dnsReverseProxyNetworkACL reverseProxyNetworkACL recursionNetworkACL blockingBypassList customBlockingAddresses blockListUrls proxyBypass forwarders'),
  socketPoolExcludedPorts: { type: 'ports' },
  qpmPrefixLimitsIPv4: { type: 'rows', columns: ['prefix', 'udpLimit', 'tcpLimit'] },
  qpmPrefixLimitsIPv6: { type: 'rows', columns: ['prefix', 'udpLimit', 'tcpLimit'] },
  tsigKeys: { type: 'rows', columns: ['keyName', 'sharedSecret', 'algorithmName'] },
  webServiceTlsCertificatePassword: { type: 'string', secret: true },
  dnsTlsCertificatePassword: { type: 'string', secret: true },
  proxyPassword: { type: 'string', secret: true },
};
for (const key of ['Type', 'Address', 'Port', 'Username', 'Password', 'Bypass']) settingsFields[`proxy${key}`]!.read = `proxy.${key === 'Bypass' ? 'bypass' : key.toLowerCase()}`;
settingsFields.reverseProxyNetworkACL!.read = 'dnsReverseProxyNetworkACL';

export const dhcpFields: Record<string, Field> = {
  ...group('string', 'name newName startingAddress endingAddress subnetMask domainName serverAddress serverHostName bootFileName routerAddress'),
  ...group('integer', 'leaseTimeDays leaseTimeHours leaseTimeMinutes offerDelayTime pingCheckTimeout pingCheckRetries dnsTtl'),
  ...group('boolean', 'pingCheckEnabled dnsUpdates dnsOverwriteForDynamicLease useThisDnsServer allowOnlyReservedLeases blockLocallyAdministeredMacAddresses ignoreClientIdentifierOption'),
  ...group('list', 'domainSearchList dnsServers winsServers ntpServers ntpServerDomainNames capwapAcIpAddresses tftpServerAddresses'),
  staticRoutes: { type: 'rows', columns: ['destination', 'subnetMask', 'router'] },
  vendorInfo: { type: 'rows', columns: ['identifier', 'information'] },
  genericOptions: { type: 'rows', columns: ['code', 'value'] },
  exclusions: { type: 'rows', columns: ['startingAddress', 'endingAddress'] },
  reservedLeases: { type: 'rows', columns: ['hostName', 'hardwareAddress', 'address', 'comments'] },
};

const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
function invalid(): never { throw new ToolError('USAGE', 'Invalid configuration field value', 'Use the configuration field types and row columns shown in inventory'); }
export function validateConfiguration(field: Field, value: unknown, resolved = false): void {
  if (field.secret && !resolved) {
    if (!object(value) || Object.keys(value).length !== 1 || !(typeof value.env === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(value.env) || typeof value.file === 'string' && isAbsolute(value.file))) invalid();
    return;
  }
  if (field.type === 'boolean') { if (typeof value !== 'boolean') invalid(); }
  else if (field.type === 'integer') { if (!Number.isSafeInteger(value) || Number(value) < 0) invalid(); }
  else if (field.type === 'string') { if (typeof value !== 'string' || /[\x00\r]/.test(value) || value === '[REDACTED]') invalid(); }
  else {
    if (!Array.isArray(value)) invalid();
    for (const item of value) {
      if (field.type === 'ports') { if (!Number.isInteger(item) || item < 0 || item > 65535) invalid(); }
      else if (field.type === 'list') { if (typeof item !== 'string' || /[\x00-\x1f\x7f,]/.test(item) || item === '[REDACTED]') invalid(); }
      else {
        if (!object(item) || Object.keys(item).length !== field.columns!.length) invalid();
        for (const column of field.columns!) {
          if (column === 'sharedSecret' && !resolved) { validateConfiguration({ type: 'string', secret: true }, item[column]); continue; }
          if (['prefix', 'udpLimit', 'tcpLimit', 'code'].includes(column)) {
            if (!Number.isSafeInteger(item[column]) || Number(item[column]) < 0) invalid();
          } else if (typeof item[column] !== 'string' || /[|\x00-\x1f\x7f]/.test(item[column]) || item[column] === '[REDACTED]') invalid();
        }
      }
    }
  }
}

export function configurationForm(field: Field | undefined, value: unknown): string {
  if (field?.type === 'rows') return (value as Record<string, unknown>[]).flatMap(row => field.columns!.map(column => String(row[column]))).join('|');
  return Array.isArray(value) ? value.join(',') : String(value);
}

export function settingValue(response: Record<string, unknown>, key: string): unknown {
  if (key.startsWith('proxy') && response.proxy === null) return key === 'proxyType' ? 'None' : key === 'proxyPort' ? 0 : key === 'proxyBypass' ? [] : '';
  if (key === 'enableLogging' && response.enableLogging === undefined) return response.loggingType !== 'None';
  const path = (settingsFields[key]?.read ?? key).split('.');
  let value: unknown = response;
  for (const part of path) value = object(value) ? value[part] : undefined;
  if (['proxyUsername', 'proxyPassword'].includes(key) && value == null) return '';
  if (key === 'proxyBypass' && value == null) return [];
  if (value === null && ['list', 'ports', 'rows'].includes(settingsFields[key]?.type ?? '')) return [];
  return value;
}
