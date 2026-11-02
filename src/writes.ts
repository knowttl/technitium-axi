import { createHash, createHmac, randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { isIP } from 'node:net';
import { toASCII } from 'tr46';
import { readOnly, storeSession, removeSession } from './credentials.js';
import type { Profile } from './credentials.js';
import { ToolError } from './errors.js';
import { PrivateFiles } from './private-file.js';
import { checkStatus, Redactor, vendorRead, vendorRequest } from './vendor.js';
import { recordFamilies, recordTypeNames } from './write-contracts.js';
import type { WriteContract } from './write-contracts.js';
import { settingsFields, dhcpFields, validateConfiguration, configurationForm, settingValue, dhcpValue, validateDhcp } from './configuration.js';
import { validateUploadArchive } from './archive-contract.js';

const files = new PrivateFiles();
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
function usage(message: string): never { throw new ToolError('USAGE', message, 'Use --input-file with the typed input contract shown in inventory'); }
const hash = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
const booleans = new Set('overwrite overwriteZone overwriteSoaSerial disabled disable ptr createPtrZone updateSvcbHints autoIpv4Hint autoIpv6Hint dnssecValidation useSerialDateScheme useSoaSerialDateScheme validateZone initializeForwarder overrideCatalogQueryAccess overrideCatalogZoneTransfer overrideCatalogNotify import dnssec ldapIgnoreSslErrors splitText newSplitText'.split(' '));
const integers = new Set('ttl expiryTtl preference newPreference priority newPriority weight newWeight port newPort naptrOrder naptrPreference naptrNewOrder naptrNewPreference keyTag newKeyTag digestType newDigestType sshfpAlgorithm newSshfpAlgorithm sshfpFingerprintType newSshfpFingerprintType tlsaCertificateUsage newTlsaCertificateUsage tlsaSelector newTlsaSelector tlsaMatchingType newTlsaMatchingType svcPriority newSvcPriority uriPriority newUriPriority uriWeight newUriWeight flags newFlags serial refresh retry expire minimum proxyPort forwarderPriority ldapPort kskKeySize zskKeySize keySize dnsKeyTtl zskRolloverDays rolloverDays iterations saltLength'.split(' '));
const lists = new Set('zones primaryNameServerAddresses queryAccessNetworkACL zoneTransferNetworkACL zoneTransferTsigKeyNames notifyNameServers notifySecondaryCatalogsNameServers updateNetworkACL blockListUrls forwarders proxyBypass members glue'.split(' '));
const literalName = (value: string) => value.replace(/^\.+|\.+$/g, '').toLowerCase();

function domainName(value: string): string {
  const name = literalName(value);
  if (!/[^\x00-\x7f]/.test(name)) return name;
  const ascii = toASCII(name, { checkBidi: true, checkJoiners: true });
  if (!ascii) usage('Invalid internationalized zone name');
  return ascii;
}

function permissionRows(key: string, value: unknown): Record<string, unknown>[] {
  const name = key === 'userPermissions' ? 'username' : 'name';
  if (!Array.isArray(value)) usage('Permissions require an array of named permission rows');
  const names = new Set<string>();
  for (const row of value) {
    if (!object(row) || Object.keys(row).sort().join(',') !== ['canDelete', 'canModify', 'canView', name].sort().join(',') ||
      typeof row[name] !== 'string' || !row[name] || /[|\x00-\x1f\x7f]/.test(row[name]) ||
      ['canView', 'canModify', 'canDelete'].some(flag => typeof row[flag] !== 'boolean')) usage('Invalid permission row');
    const normalized = (row[name] as string).toLowerCase();
    if (names.has(normalized)) usage('Duplicate permission principal');
    names.add(normalized);
  }
  return value as Record<string, unknown>[];
}

function address(value: string): string {
  if (isIP(value) === 6) return new URL(`http://[${value}]/`).hostname.slice(1, -1);
  return value;
}

function network(value: string): string {
  const denied = value.startsWith('!');
  const [ip, suffix] = (denied ? value.slice(1) : value).split('/');
  const version = isIP(ip!);
  if (!version) return value;
  const bits = version === 4 ? 32 : 128;
  const prefix = suffix === undefined ? bits : Number(suffix);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return value;
  let words: string[];
  if (version === 4) words = ip!.split('.');
  else {
    const [left, right] = address(ip!).split('::');
    const start = left ? left.split(':') : [];
    const end = right ? right.split(':') : [];
    words = right === undefined ? start : [...start, ...Array(8 - start.length - end.length).fill('0'), ...end];
  }
  const width = version === 4 ? 8n : 16n;
  const numeric = words.reduce((result, word) => (result << width) + BigInt(parseInt(word, version === 4 ? 10 : 16)), 0n);
  const shift = BigInt(bits - prefix);
  const masked = (numeric >> shift) << shift;
  const result = Array.from({ length: version === 4 ? 4 : 8 }, (_, index) => Number((masked >> (BigInt((version === 4 ? 3 : 7) - index) * width)) & ((1n << width) - 1n)).toString(version === 4 ? 10 : 16)).join(version === 4 ? '.' : ':');
  return `${denied ? '!' : ''}${address(result)}/${prefix}`;
}

function settingsAddress(value: string): string {
  const denied = value.startsWith('!');
  const [literal, suffix] = (denied ? value.slice(1) : value).split('/');
  const [ip, scope] = literal!.replace(/^\[|\]$/g, '').split('%');
  const version = isIP(ip!);
  if (!version) return value;
  const bits = version === 4 ? 32 : 128;
  const prefix = suffix === undefined ? bits : Number(suffix);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return value;
  let words: string[];
  if (version === 4) words = ip!.split('.');
  else {
    const hex = ip!.replace(/\d+\.\d+\.\d+\.\d+$/, tail => {
      const octets = tail.split('.').map(Number);
      return `${(octets[0]! * 256 + octets[1]!).toString(16)}:${(octets[2]! * 256 + octets[3]!).toString(16)}`;
    });
    const [left, right] = hex.split('::');
    const start = left ? left.split(':') : [];
    const end = right ? right.split(':') : [];
    words = right === undefined ? start : [...start, ...Array(8 - start.length - end.length).fill('0'), ...end];
  }
  const width = version === 4 ? 8n : 16n;
  const numeric = words.reduce((result, word) => (result << width) + BigInt(parseInt(word, version === 4 ? 10 : 16)), 0n);
  const shift = BigInt(bits - prefix);
  const masked = (numeric >> shift) << shift;
  const result = Array.from({ length: version === 4 ? 4 : 8 }, (_, index) => Number((masked >> (BigInt((version === 4 ? 3 : 7) - index) * width)) & ((1n << width) - 1n)).toString(version === 4 ? 10 : 16)).join(version === 4 ? '.' : ':');
  return `${denied ? '!' : ''}${result}${scope === undefined ? '' : `%${scope}`}${prefix === bits ? '' : `/${prefix}`}`;
}

function baselineValue(key: string, value: unknown): unknown {
  if (['userPermissions', 'groupPermissions'].includes(key)) {
    const name = key === 'userPermissions' ? 'username' : 'name';
    return permissionRows(key, value).map(row => ({ ...row, [name]: (row[name] as string).toLowerCase() }))
      .sort((a, b) => String(a[name]).localeCompare(String(b[name])));
  }
  if (['members', 'zoneTransferTsigKeyNames'].includes(key) && Array.isArray(value)) {
    return [...new Set(value.map(item => key === 'members' ? String(item).toLowerCase() : literalName(String(item))))].sort();
  }
  if (['notifyNameServers', 'notifySecondaryCatalogsNameServers', 'queryAccessNetworkACL', 'zoneTransferNetworkACL', 'updateNetworkACL'].includes(key) && Array.isArray(value)) {
    return value.map(item => key.endsWith('NetworkACL') ? network(String(item)) : address(String(item)));
  }
  if (['blockListUrls', 'forwarders'].includes(key) && value === null) return [];
  if (key === 'dnsServerDomain' && typeof value === 'string') return value.replace(/\.+$/, '').toLowerCase();
  if (Array.isArray(value) && value.length === 0) {
    if (key === 'dnsServerLocalEndPoints') value = ['0.0.0.0:53', '[::]:53'];
    if (key === 'webServiceLocalAddresses') value = ['0.0.0.0', '[::]'];
  }
  if (['webServiceRealIpHeader', 'dnsOverHttpRealIpHeader'].includes(key) && value === '') return 'X-Real-IP';
  if (['eDnsClientSubnetIpv4Override', 'eDnsClientSubnetIpv6Override'].includes(key) && typeof value === 'string' && value !== '') return settingsAddress(value);
  if (['dnsServerIPv4SourceAddresses', 'dnsServerIPv6SourceAddresses', 'zoneTransferAllowedNetworks', 'notifyAllowedNetworks', 'qpmLimitBypassList', 'webServiceReverseProxyAddresses', 'dnsReverseProxyNetworkACL', 'reverseProxyNetworkACL', 'recursionNetworkACL', 'blockingBypassList'].includes(key) && Array.isArray(value)) return value.map(item => settingsAddress(String(item)));
  if (key === 'customBlockingAddresses' && Array.isArray(value)) {
    const addresses = value.map(item => settingsAddress(String(item)));
    return [...addresses.filter(item => isIP(item) === 4), ...addresses.filter(item => isIP(item) === 6)];
  }
  if (key === 'webServiceLocalAddresses' && Array.isArray(value)) return value.map(item => {
    const ip = settingsAddress(String(item));
    return isIP(ip) === 6 ? `[${ip}]` : ip;
  });
  if (key === 'dnsServerLocalEndPoints' && Array.isArray(value)) return value.map(item => {
    const endpoint = String(item);
    const parts = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(endpoint);
    const ip = settingsAddress(parts?.[1] ?? endpoint);
    return `${isIP(ip) === 6 ? `[${ip}]` : ip}:${Number(parts?.[2]) || 53}`;
  });
  if (key === 'webServiceCspFrameAncestorsHeader' && value === '') return "'none'";
  if (key === 'forwarderProtocol' && value === 'HttpsJson') return 'Https';
  if (settingsFields[key]?.type === 'string' && value === null) return '';
  if (['webServiceTlsCertificatePassword', 'dnsTlsCertificatePassword'].includes(key) && typeof value === 'string') return value === '' ? '' : '************';
  if (settingsFields[key] && ['list', 'ports', 'rows'].includes(settingsFields[key]!.type) && value === null) return [];
  if (key === 'tsigKeys' && Array.isArray(value)) return value.map(row => ({ ...row, keyName: domainName(row.keyName), algorithmName: row.algorithmName.toLowerCase().replace(/\.$/, '') })).sort((a, b) => a.keyName.localeCompare(b.keyName));
  if (['catalog', 'primaryZoneTransferTsigKeyName'].includes(key) && value === null) return '';
  if (['catalog', 'primaryZoneTransferTsigKeyName'].includes(key) && typeof value === 'string') return literalName(value);
  if (['primaryZoneTransferProtocol', 'queryAccess', 'zoneTransfer', 'notify', 'update'].includes(key) && typeof value === 'string') return value.toLowerCase();
  if (key === 'updateSecurityPolicies') {
    let policies: string[] | undefined;
    if (Array.isArray(value)) {
      policies = value.flatMap(row => {
        if (!object(row) || typeof row.tsigKeyName !== 'string' || typeof row.domain !== 'string' || !Array.isArray(row.allowedTypes) || row.allowedTypes.some(type => typeof type !== 'string')) usage('Invalid update security policy baseline');
        return [row.tsigKeyName, row.domain, row.allowedTypes.join(',')];
      });
    }
    if (typeof value === 'string') policies = value === '' || value.toLowerCase() === 'false' ? [] : value.split('|').filter(Boolean);
    if (policies) {
      if (policies.length % 3 !== 0) usage('Update security policies require key, domain and allowed types');
      const rows = new Map<string, string[]>();
      for (let i = 0; i < policies.length; i += 3) {
        const key = `${literalName(policies[i]!)}|${literalName(policies[i + 1]!)}`;
        rows.set(key, [...rows.get(key) ?? [], ...policies[i + 2]!.split(/[, ]+/).filter(Boolean).map(type => type.toUpperCase())]);
      }
      return [...rows].map(([key, types]) => `${key}|${types.sort().join(',')}`).sort().join('|');
    }
  }
  return value;
}

function selectedValues(values: Record<string, unknown>, dhcp = false): Record<string, unknown> {
  return Object.fromEntries(Object.entries(values).map(([key, value]) => [key, dhcp ? dhcpValue(key, value) : baselineValue(key, value)]));
}

function validateValue(key: string, value: unknown): void {
  if (['allowedZones', 'blockedZones'].includes(key)) {
    if (!Array.isArray(value) || value.some(item => typeof item !== 'string' || !item.length || /[\x00-\x20\x7f,]/.test(item))) usage('Zone import requires an array of domain names without separators');
    return;
  }
  if (['userPermissions', 'groupPermissions'].includes(key)) { permissionRows(key, value); }
  else if (booleans.has(key)) { if (typeof value !== 'boolean') usage('Boolean input requires true or false'); }
  else if (integers.has(key)) { if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > 4294967295) usage('Integer input is outside its supported range'); }
  else if (lists.has(key)) { if (!Array.isArray(value) || value.some(item => typeof item !== 'string' || /[\x00-\x1f\x7f,]/.test(item))) usage('List input requires an array of strings without separators'); }
  else if ((key === 'algorithm' || key === 'newAlgorithm') && typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0 || value > 255) usage('Invalid DNSSEC algorithm');
  } else if (typeof value !== 'string' || value.length > 1024 * 1024 || /[\x00\r]/.test(value)) usage('String input has an invalid type or size');
  if (value === '[REDACTED]') usage('Redacted output cannot be used as an update value');
}

function validateRecord(contract: WriteContract, parameters: Record<string, unknown>): void {
  const suppliedType = parameters.type;
  if (typeof suppliedType !== 'string') usage('Record type must be a name or decimal number');
  const numeric = /^\d+$/.test(suppliedType) && Number(suppliedType) > 0 && Number(suppliedType) <= 65535;
  const knownType = numeric ? recordTypeNames[Number(suppliedType)] : undefined;
  const type = knownType ?? suppliedType;
  parameters.type = type;
  const family = recordFamilies[type] ?? (numeric && !knownType ? recordFamilies.raw : undefined);
  if (!family) usage('Unsupported record type; generated DNSSEC records use lifecycle operations');
  const action = contract.id;
  if (type === 'SOA' && action !== 'OP-051') usage('SOA records use apex update or zone lifecycle operations');
  if (type === 'SOA' && parameters.domain !== parameters.zone) usage('SOA must select the zone apex');
  if (type === 'DNAME' && action === 'OP-052') throw new ToolError('PREREQUISITE_PENDING', 'DNAME deletion requires reviewed shipped-library mapping', 'Track the DNAME mapping follow-up before accepting deletion coverage', 1);
  const metadata = action === 'OP-049' ? ['ttl', 'overwrite', 'comments', 'expiryTtl'] : action === 'OP-051' ? ['ttl', 'newDomain', 'disable', 'comments', 'expiryTtl'] : [];
  const optional = action === 'OP-052' ? (['A', 'AAAA'].includes(type) ? ['updateSvcbHints'] : type === 'TXT' ? ['splitText', 'characterStringsBase64'] : [])
    : (family.optional ?? []).filter(key => action !== 'OP-049' || !key.startsWith('new'));
  const fields = new Set(['node', 'zone', 'domain', 'type', ...metadata, ...optional,
    ...(action === 'OP-052' ? family.selector : action === 'OP-049' ? (family.selector.length ? family.selector : family.replacement) : [...family.selector, ...family.replacement])]);
  // Add uses current rData names. Singleton replacement fields already use those names.
  const required = action === 'OP-049' ? (family.selector.length ? family.selector : family.replacement)
    : action === 'OP-051' && !family.selector.length ? family.replacement : family.selector;
  for (const key of Object.keys(parameters)) if (!fields.has(key)) usage('Field does not apply to this record type and action');
  for (const key of required) {
    if (type === 'TXT' && key === 'text' && Object.hasOwn(parameters, 'characterStringsBase64')) continue;
    if (!Object.hasOwn(parameters, key)) usage('The record selector or data is incomplete');
  }
  for (const prefix of ['', 'new']) {
    const text = prefix ? 'newText' : 'text';
    const base64 = prefix ? 'newCharacterStringsBase64' : 'characterStringsBase64';
    const split = prefix ? 'newSplitText' : 'splitText';
    if (Object.hasOwn(parameters, base64) && (Object.hasOwn(parameters, text) || Object.hasOwn(parameters, split))) usage('Choose TXT text or characterStringsBase64, not both');
  }
}

export interface WriteInput {
  parameters: Record<string, unknown>;
  baseline?: Record<string, unknown>;
  upload?: { file: string; format?: 'multipart' | 'text' };
  encoding?: 'form' | 'json';
}

export async function writeInput(contract: WriteContract, path?: string): Promise<WriteInput> {
  if (!path) usage('A protected --input-file is required');
  let input: unknown;
  try { input = JSON.parse(await files.read(path)); } catch (error) {
    if (error instanceof SyntaxError) usage('Input must be valid JSON');
    throw error;
  }
  if (!object(input) || !object(input.parameters) || Object.keys(input).some(key => !['parameters', 'baseline', 'upload', 'encoding'].includes(key))) usage('Input requires parameters and optional baseline or upload');
  if (input.encoding !== undefined && (contract.id !== 'OP-080' || !['form', 'json'].includes(String(input.encoding)))) usage('Only settings set supports form or json encoding');
  const parameters = input.parameters;
  if (contract.id === 'OP-003' && ((parameters.user === undefined) !== (parameters.pass === undefined) || parameters.totp !== undefined && parameters.pass === undefined)) usage('Password acquisition requires user and pass together; omit all password fields for the selected bearer');
  if (['OP-008', 'OP-104'].includes(contract.id) && parameters.iterations !== undefined && (!Number.isInteger(parameters.iterations) || Number(parameters.iterations) < 100000 || Number(parameters.iterations) > 1000000)) usage('Iterations must be between 100000 and 1000000');
  if (['OP-013', 'OP-104'].includes(contract.id) && parameters.sessionTimeoutSeconds !== undefined && (!Number.isInteger(parameters.sessionTimeoutSeconds) || Number(parameters.sessionTimeoutSeconds) < 0 || Number(parameters.sessionTimeoutSeconds) > 604800)) usage('Session timeout must be between 0 and 604800 seconds');
  if (contract.id === 'OP-076' && (!object(parameters.config) || typeof parameters.config.file !== 'string')) usage('App config requires a protected absolute file SecretRef');
  if (contract.id === 'OP-092' && parameters.useThisDnsServer === true && Object.hasOwn(parameters, 'dnsServers')) usage('dnsServers is ignored when useThisDnsServer is true; select one DNS server mode');
  if (contract.command.startsWith('dhcp lease ') && (
    (parameters.clientIdentifier === undefined) === (parameters.hardwareAddress === undefined) ||
    parameters.clientIdentifier === '' || parameters.hardwareAddress === '')) usage('Choose exactly one nonempty clientIdentifier or hardwareAddress');
  if (contract.id === 'OP-080') for (const values of [parameters, input.baseline]) {
    if (!object(values) || !Object.hasOwn(values, 'defaultResponsiblePerson')) continue;
    const value = values.defaultResponsiblePerson;
    if (typeof value !== 'string' || value !== '' && !/^[^\s@()<>\[\]",:;\\]+@[^\s@()<>\[\]",:;\\]+$/.test(value)) usage('defaultResponsiblePerson requires a plain local@domain address without display names, comments or angle brackets, or an empty string to clear it');
  }
  if (contract.id === 'OP-080') for (const [modern, legacy] of [['ipv6Mode', 'preferIPv6'], ['loggingType', 'enableLogging'], ['dnsReverseProxyNetworkACL', 'reverseProxyNetworkACL']]) {
    if (Object.hasOwn(parameters, modern!) && Object.hasOwn(parameters, legacy!)) usage('Choose the modern setting or its compatibility alias, not both');
  }
  for (const key of Object.keys(parameters)) if (!contract.fields.includes(key)) usage('Unknown input field');
  for (const key of contract.required) if (!Object.hasOwn(parameters, key) || parameters[key] === '') usage('Required input is missing');
  if (['OP-070', 'OP-071'].includes(contract.id)) {
    let url: URL;
    try { url = new URL(String(parameters.url)); } catch { usage('App download URL must be an absolute HTTPS URL'); }
    if (url.protocol !== 'https:') usage('App download URL must use HTTPS');
  }
  if (contract.command.startsWith('dhcp ') && parameters.hardwareAddress !== undefined &&
    (typeof parameters.hardwareAddress !== 'string' || !/^(?:[\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}$/.test(parameters.hardwareAddress))) usage('hardwareAddress requires six hexadecimal octets separated by colons or hyphens');
  if (contract.id === 'OP-093' && isIP(String(parameters.ipAddress)) !== 4) usage('ipAddress requires an IPv4 address');
  if (contract.id === 'OP-136' && (typeof parameters.log !== 'string' || /[\\/:]/.test(parameters.log) || ['.', '..'].includes(parameters.log))) usage('Log deletion requires the fileName returned by log list, without a path');
  for (const [key, value] of Object.entries(parameters)) {
    if (contract.secrets?.includes(key)) {
      if (!object(value) || Object.keys(value).length !== 1 || !(
        (typeof value.env === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(value.env)) ||
        (typeof value.file === 'string' && isAbsolute(value.file)))) usage('Secret fields require an environment or protected absolute file SecretRef');
    } else {
      if (contract.id === 'OP-080') validateConfiguration(settingsFields[key]!, value);
      else if (contract.id === 'OP-092') validateDhcp(key, value);
      else if (contract.id === 'OP-083' && key === 'minutes') {
        if (!Number.isSafeInteger(value) || Number(value) <= 0 || Number(value) > 2147483647) usage('Minutes must be a positive 32-bit integer');
      } else if (contract.id === 'OP-085' && key !== 'node') {
        if (typeof value !== 'boolean') usage('Restore selections require true or false');
      } else if (key === 'totpEnabled') {
        if (typeof value !== 'boolean') usage('A boolean is required');
      } else if (key === 'memberOfGroups') {
        if (!Array.isArray(value) || value.some(group => typeof group !== 'string' || !group || /[,|\x00-\x1f]/.test(group))) usage('memberOfGroups requires an array of group names');
      } else if (['iterations', 'sessionTimeoutSeconds'].includes(key)) {
        if (!Number.isSafeInteger(value)) usage('An integer is required');
      } else validateValue(key, value);
      if (key === 'updateSecurityPolicies') baselineValue(key, value);
    }
  }
  if (['OP-049', 'OP-051', 'OP-052'].includes(contract.id)) validateRecord(contract, parameters);
  if (contract.command.startsWith('zone dnssec ')) {
    const bounds: Record<string, number> = { keyTag: 65535, rolloverDays: 365, zskRolloverDays: 365, iterations: 50, saltLength: 32 };
    for (const [key, maximum] of Object.entries(bounds)) {
      if (parameters[key] !== undefined && Number(parameters[key]) > maximum) usage(`${key} must be between 0 and ${maximum}`);
    }
  }
  if (['OP-022', 'OP-026'].includes(contract.id) && !['Primary', 'Secondary', 'Stub', 'Forwarder', 'SecondaryForwarder', 'Catalog', 'SecondaryCatalog'].includes(String(parameters.type))) usage('Unsupported zone type');
  if (contract.id === 'OP-022' && ['SecondaryForwarder', 'SecondaryCatalog'].includes(String(parameters.type)) && (!Array.isArray(parameters.primaryNameServerAddresses) || !parameters.primaryNameServerAddresses.length)) usage('Secondary forwarder and catalog creation require primary name server addresses');
  if (contract.id === 'OP-029' && ((parameters.zone === undefined) === (parameters.zones === undefined) || parameters.zone === '' || (Array.isArray(parameters.zones) && parameters.zones.length === 0))) usage('Choose a zone or a nonempty zones list');
  if (input.baseline !== undefined && !object(input.baseline)) usage('Baseline must be an object');
  if (contract.baselinePath) {
    const fields = Object.keys(parameters).filter(key => !contract.baselineTarget?.includes(key));
    if (!fields.length || !object(input.baseline) || canonical(Object.keys(input.baseline).sort()) !== canonical(fields.sort())) usage('Provide the exact selected baseline for every changed field');
    for (const [key, value] of Object.entries(input.baseline)) {
      if (contract.id === 'OP-080') validateConfiguration(settingsFields[key]!, baselineValue(key, value));
      else if (contract.id === 'OP-092') validateDhcp(key, dhcpValue(key, value));
      else validateValue(key, baselineValue(key, value));
    }
  } else if (input.baseline !== undefined) usage('Baseline is not supported by this operation');
  if (input.upload !== undefined) {
    if (!['OP-022', 'OP-023', 'OP-072', 'OP-073', 'OP-085'].includes(contract.id) || !object(input.upload) || Object.keys(input.upload).some(key => !['file', 'format'].includes(key)) || typeof input.upload.file !== 'string' || !isAbsolute(input.upload.file)) usage('Upload requires a protected absolute file for a supported upload operation');
    if (input.upload.format !== undefined && !['multipart', 'text'].includes(String(input.upload.format))) usage('Upload format must be multipart or text');
    if (!['OP-022', 'OP-023'].includes(contract.id) && input.upload.format !== undefined) usage('Package uploads require multipart transport');
    if (Object.hasOwn(parameters, 'records') || (contract.id === 'OP-022' && (!['Primary', 'Forwarder'].includes(String(parameters.type)) || input.upload.format === 'text'))) usage('Uploaded records require Primary or Forwarder multipart creation, or an import without inline records');
  }
  if (contract.id === 'OP-023' && input.upload === undefined && typeof parameters.records !== 'string') usage('Import requires records or an upload');
  if (['OP-072', 'OP-073', 'OP-085'].includes(contract.id) && !input.upload) usage('A protected package or backup upload is required');
  return input as unknown as WriteInput;
}

function journalPath(digest: string): string {
  const base = process.platform === 'win32' ? process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local')
    : process.env.XDG_STATE_HOME && isAbsolute(process.env.XDG_STATE_HOME) ? process.env.XDG_STATE_HOME : join(homedir(), '.local', 'state');
  const path = process.env.TECHNITIUM_AXI_WRITE_LOG ?? join(base, 'technitium-axi', 'writes.log');
  if (!isAbsolute(path)) usage('TECHNITIUM_AXI_WRITE_LOG must be absolute');
  return join(`${path}.d`, `${digest}.json`);
}

async function baselineRead(contract: WriteContract, profile: Profile, token: string, parameters: Record<string, unknown>, fields: string[]) {
  const target = new URLSearchParams();
  for (const key of contract.baselineTarget ?? []) if (parameters[key] !== undefined) target.set(key, String(parameters[key]));
  const result = await vendorRequest(profile, contract.baselinePath!, target.toString(), token, {}, { bytes: 16 * 1024 * 1024, elapsedMs: 10000 });
  if (result.status !== 200 || result.contentType !== 'application/json') throw new ToolError('UPSTREAM_INVALID', 'Baseline read failed', 'Repeat the selected target read', 1);
  const value: unknown = JSON.parse(result.bytes.toString());
  checkStatus(value);
  if (!object(value.response)) throw new ToolError('UPSTREAM_INVALID', 'Selected baseline fields are missing', 'Check the selected target and API version', 1);
  const response = value.response;
  const preserved: Record<string, unknown> = {};
  if (contract.id === 'OP-080') for (const prefix of ['webServiceTlsCertificate', 'dnsTlsCertificate']) {
    if (fields.includes(`${prefix}Password`) && !fields.includes(`${prefix}Path`)) {
      const path = response[`${prefix}Path`];
      if (typeof path !== 'string' || !path) usage('A certificate password update requires an existing or selected certificate path');
      preserved[`${prefix}Path`] = path;
    }
  }
  if (contract.id === 'OP-080' && fields.includes('forwarders') && !fields.includes('forwarderProtocol')) {
    validateValue('forwarderProtocol', response.forwarderProtocol);
    preserved.forwarderProtocol = response.forwarderProtocol;
  }
  if (contract.id === 'OP-080' && fields.includes('forwarderProtocol') && !fields.includes('forwarders')) {
    preserved.forwarders = baselineValue('forwarders', response.forwarders);
    validateConfiguration(settingsFields.forwarders!, preserved.forwarders, true);
  }
  if (contract.id === 'OP-080' && fields.some(key => key.startsWith('proxy')) && parameters.proxyType !== 'None') {
    for (const target of ['proxyType', 'proxyAddress', 'proxyPort', 'proxyUsername', 'proxyPassword', 'proxyBypass']) {
      if (fields.includes(target)) continue;
      const item = settingValue(response, target);
      validateValue(target, item);
      preserved[target] = item;
    }
  }
  const selected = Object.fromEntries(fields.map(key => {
    if (contract.command.startsWith('dhcp ')) {
      if (key === 'reservedLeases' && !Array.isArray(response[key])) throw new ToolError('UPSTREAM_INVALID', 'Scope reservations are missing', 'Read the selected scope and check the server API version', 1);
      const item = dhcpValue(key, response[key === 'newName' ? 'name' : key]);
      validateDhcp(key, item);
      return [key, item];
    }
    if (contract.id === 'OP-080') {
      const item = baselineValue(key, settingValue(response, key));
      validateConfiguration(settingsFields[key]!, item, true);
      return [key, item];
    }
    const source = contract.id === 'OP-109' && key === 'newGroup' ? 'name' : key;
    if (!Object.hasOwn(response, source)) throw new ToolError('UPSTREAM_INVALID', 'Selected baseline fields are missing', 'Check the selected target and API version', 1);
    const item = baselineValue(key, response[source]);
    validateValue(key, item);
    return [key, item];
  }));
  const unchanged: Record<string, unknown> = {};
  if (contract.id === 'OP-080') {
    const changed = new Set(fields);
    if (changed.has('preferIPv6')) changed.add('ipv6Mode');
    if (changed.has('enableLogging')) changed.add('loggingType');
    if (changed.has('reverseProxyNetworkACL')) changed.add('dnsReverseProxyNetworkACL');
    if (changed.has('proxyType') && parameters.proxyType === 'None') for (const key of Object.keys(settingsFields).filter(key => key.startsWith('proxy'))) changed.add(key);
    if (changed.has('forwarders')) changed.add('forwarderProtocol');
    for (const prefix of ['webServiceTlsCertificate', 'dnsTlsCertificate']) if (changed.has(`${prefix}Path`)) changed.add(`${prefix}Password`);
    for (const key of Object.keys(settingsFields)) {
      if (changed.has(key) || ['preferIPv6', 'enableLogging', 'reverseProxyNetworkACL'].includes(key)) continue;
      const item = settingValue(response, key);
      if (item !== undefined) unchanged[key] = baselineValue(key, item);
    }
  }
  return { selected, preserved, ...(contract.id === 'OP-080' ? { unchanged } : {}) };
}

async function soaSerial(profile: Profile, token: string, parameters: Record<string, unknown>): Promise<number> {
  const form = new URLSearchParams({ domain: String(parameters.zone), zone: String(parameters.zone), listZone: 'true' });
  if (parameters.node !== undefined) form.set('node', String(parameters.node));
  const result = await vendorRequest(profile, '/api/zones/records/get', form.toString(), token, {}, { bytes: 16 * 1024 * 1024, elapsedMs: 10000 });
  if (result.status !== 200 || result.contentType !== 'application/json') throw new ToolError('UPSTREAM_INVALID', 'SOA read failed', 'Read the selected secondary zone', 1);
  const value: unknown = JSON.parse(result.bytes.toString());
  checkStatus(value);
  if (!object(value.response) || !Array.isArray(value.response.records)) usage('SOA read requires complete zone records');
  const soa = value.response.records.find(record => object(record) && record.type === 'SOA' && domainName(String(record.name)) === domainName(String(parameters.zone)));
  if (!object(soa) || !object(soa.rData) || !Number.isSafeInteger(soa.rData.serial)) usage('Selected zone SOA serial is missing');
  return Number(soa.rData.serial);
}

export async function writeOperation(contract: WriteContract, input: WriteInput, profile: Profile, identity: string, token: string,
  options: { execute: boolean; confirm?: string; reconcile?: string }, redactor: Redactor) {
  const capability = contract.id === 'OP-077' ? input.parameters.import === true ? 'OP-077.import' : 'OP-077.resolve' : contract.id;
  const mutating = capability !== 'OP-077.resolve';
  const parameters = { ...input.parameters };
  const acquisition = contract.id === 'OP-002' || contract.id === 'OP-003' && parameters.pass !== undefined;
  if (['OP-003', 'OP-004', 'OP-008', 'OP-009', 'OP-010', 'OP-011', 'OP-013'].includes(contract.id) && !acquisition && profile.tokenKind !== 'session') throw new ToolError('TOKEN_KIND', 'A Standard session is required', 'Explicitly sign in with a session profile', 1);
  if (contract.id === 'OP-002' && (profile.tokenKind !== 'session' || !profile.username || profile.username !== parameters.user)) usage('Login requires a session profile whose username matches user');
  if (contract.id === 'OP-002') parameters.includeInfo = true;
  let route: { requested: string; effective: string; caller: string } | undefined;
  if (['OP-116', 'OP-117'].includes(contract.id)) {
    if (profile.tokenKind === 'single-use') throw new ToolError('TOKEN_KIND', 'SSO preflight needs multiple requests', 'Use an API or session profile', 1);
    const session = await identityResponse(profile, '/api/user/session/get', 'includeInfo=true', token);
    if (typeof session.token === 'string') redactor.add(session.token);
    if (!object(session.info) || !object(session.info.permissions) || !object(session.info.permissions.Administration) || session.info.permissions.Administration.canModify !== true || typeof session.username !== 'string') throw new ToolError('PERMISSION_DENIED', 'The actual caller requires Administration Modify', 'Use a caller with Administration Modify on the selected secondary', 1);
    const state = await identityResponse(profile, '/api/admin/cluster/state', '', token);
    const cluster = state.response;
    const nodes = object(cluster) && Array.isArray(cluster.clusterNodes) ? cluster.clusterNodes.filter(object) : [];
    const secondary = nodes.find(node => node.state === 'Self' && node.type === 'Secondary');
    const primary = nodes.find(node => node.type === 'Primary');
    if (!object(cluster) || cluster.clusterInitialized !== true || !secondary || !primary || typeof primary.url !== 'string') throw new ToolError('PREREQUISITE_REQUIRED', 'SSO writes require an initialized secondary-to-primary route', 'Select an initialized secondary profile; the vendor proxy supplies the cluster identity', 1);
    route = { requested: profile.origin, effective: primary.url, caller: session.username };
  }
  const baselineInput = input.baseline ? { ...input.baseline } : undefined;
  if (contract.id === 'OP-080') for (const values of [parameters, baselineInput]) {
    if (!Array.isArray(values?.tsigKeys)) continue;
    values!.tsigKeys = await Promise.all(values!.tsigKeys.map(async row => {
      const ref = row.sharedSecret as { env?: string; file?: string };
      const value = ref.file ? await files.read(ref.file) : process.env[ref.env!];
      if (value === undefined || value.length > 1024 * 1024) usage('TSIG SecretRef is missing or too large');
      redactor.add(value);
      const resolved = { ...row, sharedSecret: value };
      validateConfiguration(settingsFields.tsigKeys!, [resolved], true);
      return resolved;
    }));
  }
  for (const values of [parameters, baselineInput]) for (const key of contract.secrets ?? []) {
    const ref = values?.[key];
    if (ref === undefined) continue;
    const selected = ref as { env?: string; file?: string };
    const value = selected.file ? await files.read(selected.file) : process.env[selected.env!];
    if (value === undefined || value.length > 1024 * 1024) usage('SecretRef is missing or too large');
    redactor.add(value);
    if (contract.id === 'OP-080') validateConfiguration(settingsFields[key]!, value, true);
    values![key] = value;
  }
  let upload: Buffer | undefined;
  if (input.upload) {
    upload = await files.readBytes(input.upload.file);
    if (['OP-072', 'OP-073', 'OP-085'].includes(contract.id)) validateUploadArchive(upload);
  }
  // A keyed digest binds credential and secret revisions without publishing an offline secret verifier.
  const intentId = !options.execute && !options.reconcile ? randomUUID() : options.confirm?.split('.')[0];
  const digest = `${intentId}.${createHmac('sha256', token).update(canonical({ intentId, origin: profile.origin, identity, username: profile.username ?? null,
    tokenKind: profile.tokenKind, caFile: profile.caFile ?? null, tlsServerName: profile.tlsServerName ?? null,
    capability, parameters, route: route ?? null, baseline: baselineInput ?? null, encoding: input.encoding ?? 'form', upload: upload ? { sha256: hash(upload), format: input.upload?.format ?? 'multipart' } : null })).digest('hex')}`;
  const permitted = !mutating || (!readOnly() && profile.writes?.allowWrites === true && profile.writes.operations.includes(capability));
  if (!options.execute && !options.reconcile) return { bytes: Buffer.alloc(0), projection: { preview: { digest, operation: capability,
    origin: profile.origin, identity, node: parameters.node ?? null, target: parameters.zone ?? parameters.zones ?? parameters.domain ?? parameters.group ?? parameters.log ?? parameters.name ?? null,
    permitted, upload: upload ? { bytes: upload.length, sha256: hash(upload) } : null,
    ...(route ? { route } : {}),
    replaces: contract.baselinePath ? Object.keys(input.baseline!) : [],
    ...(contract.baselinePath ? { concurrency: 'A single-writer window is required between the final read and write; the vendor has no atomic conditional setter' } : {}) } } };
  if (!permitted) throw new ToolError('WRITE_DENIED', 'Exact write grant is required and read-only mode overrides grants', 'Enable only the selected operation in the selected profile', 1);
  if (!intentId || !/^[a-f0-9-]{36}$/.test(intentId) || options.confirm !== digest) throw new ToolError('CONFIRMATION_MISMATCH', 'Preview confirmation no longer matches the selected input', 'Preview again and supply its exact digest', 1);
  if ((contract.baselinePath || ['OP-030', 'OP-093'].includes(contract.id)) && profile.tokenKind === 'single-use') throw new ToolError('TOKEN_KIND', 'This action needs multiple authenticated requests', 'Select an API or session profile for this operation', 1);
  const auditId = randomUUID();
  const path = journalPath(digest);
  const postconditionHash = (value: unknown) => createHmac('sha256', token).update(canonical(value)).digest('hex');
  let resyncSerial: number | undefined;
  const postcondition = async (expected: string | undefined) => {
    if (contract.id === 'OP-030' && resyncSerial !== undefined) {
      const serial = await soaSerial(profile, token, parameters);
      const distance = (serial - resyncSerial + 4294967296) % 4294967296;
      return distance > 0 && distance < 2147483648;
    }
    if (!contract.baselinePath || !expected) return false;
    const target = contract.id === 'OP-109' && parameters.newGroup !== undefined ? { ...parameters, group: parameters.newGroup }
      : contract.id === 'OP-092' && parameters.newName !== undefined ? { ...parameters, name: parameters.newName } : parameters;
    return postconditionHash(await baselineRead(contract, profile, token, target, Object.keys(input.baseline!))) === expected;
  };
  if (options.reconcile) {
    const prior = JSON.parse(await files.read(path)) as { auditId: string; state: string; postconditionHash?: string; resyncSerial?: number };
    if (prior.auditId !== options.reconcile) usage('Audit ID does not match the confirmed operation');
    resyncSerial = prior.resyncSerial;
    let proven = false;
    try { proven = Boolean(await postcondition(prior.postconditionHash)); } catch { /* A failed read cannot prove an outcome. */ }
    if (!proven) throw new ToolError('OUTCOME_UNKNOWN', `Outcome remains unknown; audit ID ${prior.auditId}`, 'Read the exact selected target and compare its full postcondition; never replay an uncertain write', 1);
    await files.write(path, JSON.stringify({ ...prior, state: 'reconciled' }));
    return { bytes: Buffer.alloc(0), projection: { status: 'reconciled', auditId: prior.auditId, operation: capability } };
  }
  let expected: string | undefined;
  if (contract.id === 'OP-093') {
    const scope = await baselineRead({ ...contract, baselinePath: '/api/dhcp/scopes/get', baselineTarget: ['name'] }, profile, token, parameters, ['reservedLeases']);
    const mac = String(parameters.hardwareAddress).replace(/:/g, '-').toUpperCase();
    if ((scope.selected.reservedLeases as Record<string, unknown>[]).some(row => row.hardwareAddress === mac || row.address === parameters.ipAddress)) {
      throw new ToolError('CONFLICT', 'A reservation already uses the selected hardware or IP address', 'Read the selected scope reservations and choose an unused address and hardware identifier', 1);
    }
  }
  if (contract.id === 'OP-030') resyncSerial = await soaSerial(profile, token, parameters);
  let expectedState: Awaited<ReturnType<typeof baselineRead>> | undefined;
  if (contract.baselinePath) {
    const baseline = await baselineRead(contract, profile, token, parameters, Object.keys(input.baseline!));
    if (canonical(baseline.selected) !== canonical(selectedValues(baselineInput!, contract.id === 'OP-092'))) throw new ToolError('CONFLICT', 'Selected baseline changed after preview', 'Read the selected values and preview a new explicit replacement', 1);
    const selected = selectedValues(Object.fromEntries(Object.keys(input.baseline!).map(key => [key, parameters[key]])), contract.id === 'OP-092');
    if (contract.id === 'OP-034' && Array.isArray(selected.groupPermissions)) {
      const mandatory = ['administrators', 'dns administrators'];
      selected.groupPermissions = baselineValue('groupPermissions', [
        ...permissionRows('groupPermissions', selected.groupPermissions).filter(row => !mandatory.includes(String(row.name))),
        ...mandatory.map(name => ({ name, canView: true, canModify: true, canDelete: true })),
      ]);
    }
    if (contract.id === 'OP-109' && Array.isArray(selected.members) && String(parameters.newGroup ?? parameters.group).toLowerCase() === 'administrators') {
      const session = await vendorRead(profile, 'user session get', token);
      redactor.add(session.secret!);
      if (!('username' in session.projection)) throw new ToolError('UPSTREAM_INVALID', 'Authenticated caller identity is missing', 'Check the selected server API version and operation', 1);
      selected.members = baselineValue('members', [...selected.members, session.projection.username]);
    }
    const preserved = { ...baseline.preserved };
    if (contract.id === 'OP-080') for (const prefix of ['webServiceTlsCertificate', 'dnsTlsCertificate']) {
      if (Object.hasOwn(selected, `${prefix}Password`)) selected[`${prefix}Password`] = (parameters[`${prefix}Path`] ?? preserved[`${prefix}Path`]) ? '************' : '';
    }
    const forwarders = selected.forwarders ?? preserved.forwarders;
    if (contract.id === 'OP-080' && Array.isArray(forwarders) && forwarders.length === 0) {
      if (Object.hasOwn(selected, 'forwarderProtocol')) selected.forwarderProtocol = 'Udp';
      else preserved.forwarderProtocol = 'Udp';
    }
    expectedState = { selected, preserved, ...('unchanged' in baseline ? { unchanged: baseline.unchanged } : {}) };
    expected = postconditionHash(expectedState);
    if (typeof baseline.preserved.proxyPassword === 'string') redactor.add(baseline.preserved.proxyPassword);
    Object.assign(parameters, baseline.preserved);
  }
  if (mutating) {
    try { await files.create(path, JSON.stringify({ auditId, digest, operation: capability, state: 'intent', postconditionHash: expected, resyncSerial })); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new ToolError('REPLAY_DENIED', 'This confirmed mutation already has a durable intent', 'Inspect its protected journal entry and reconcile the original audit ID; do not replay', 1);
      throw new ToolError('JOURNAL_FAILED', 'Durable intent could not be recorded', 'Repair the protected journal before executing any mutation', 1);
    }
  }
  const form = new URLSearchParams(Object.entries(parameters).map(([key, value]) => [key,
    ['userPermissions', 'groupPermissions'].includes(key) ? permissionRows(key, value).flatMap(row => [row[key === 'userPermissions' ? 'username' : 'name'], row.canView, row.canModify, row.canDelete]).join('|')
      : configurationForm(contract.id === 'OP-080' ? settingsFields[key] : contract.id === 'OP-092' ? dhcpFields[key] : undefined, value)]));
  let body: string | Buffer = form.toString();
  let requestPath = contract.path;
  const headers: Record<string, string> = {};
  if (input.encoding === 'json') {
    body = JSON.stringify(parameters);
    headers['content-type'] = 'application/json';
  }
  if (upload) {
    requestPath += `?${form}`;
    if (input.upload?.format === 'text') {
      headers['content-type'] = 'text/plain';
      body = upload;
    } else {
      const boundary = `technitium-${randomUUID()}`;
      headers['content-type'] = `multipart/form-data; boundary=${boundary}`;
      const archive = ['OP-072', 'OP-073', 'OP-085'].includes(contract.id);
      body = Buffer.concat([Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${archive ? 'package.zip' : 'zone.txt'}"\r\nContent-Type: ${archive ? 'application/zip' : 'text/plain'}\r\n\r\n`), upload, Buffer.from(`\r\n--${boundary}--\r\n`)]);
    }
  }
  try {
    const response = await vendorRequest(profile, requestPath, body, acquisition ? undefined : token, headers, { bytes: 16 * 1024 * 1024, elapsedMs: 10000 });
    if (response.status !== 200 || response.contentType !== 'application/json') throw new Error('Response unavailable');
    const value: unknown = JSON.parse(response.bytes.toString());
    checkStatus(value);
    if (['OP-002', 'OP-003', 'OP-004'].includes(contract.id)) {
      const credential = contract.id === 'OP-004' ? value.response : value;
      if (!object(credential) || typeof credential.token !== 'string' || !credential.token || /[\s\x00-\x1f\x7f]/.test(credential.token)) throw new Error('Issued credential is invalid');
      redactor.add(credential.token);
    }
    if (contract.id === 'OP-002') {
      if (value.username !== profile.username || typeof value.token !== 'string' || !object(value.info) || !object(value.info.permissions)) throw new Error('Issued identity does not match the selected profile');
      if (Object.values(value.info.permissions).some(permission => !object(permission) || Object.values(permission).some(flag => typeof flag !== 'boolean'))) throw new Error('Invalid permission response');
      await storeSession(identity, profile, value.token);
    }
    const localRemoved = contract.id === 'OP-005' ? await removeSession(identity, profile, token) : undefined;
    if (contract.id === 'OP-080' && expectedState && Array.isArray(parameters.tsigKeys) && parameters.tsigKeys.some(row => row.sharedSecret === '')) {
      if (!object(value.response)) throw new Error('Generated TSIG keys are unavailable');
      const returned = baselineValue('tsigKeys', value.response.tsigKeys);
      validateConfiguration(settingsFields.tsigKeys!, returned, true);
      const requested = baselineValue('tsigKeys', parameters.tsigKeys) as Record<string, string>[];
      const generated = returned as Record<string, string>[];
      if (generated.length !== requested.length || generated.some((row, i) => row.keyName !== requested[i]!.keyName || row.algorithmName !== requested[i]!.algorithmName || !row.sharedSecret || requested[i]!.sharedSecret !== '' && row.sharedSecret !== requested[i]!.sharedSecret)) throw new Error('Generated TSIG keys do not match the selected replacement');
      for (const row of generated) redactor.add(row.sharedSecret!);
      expectedState.selected.tsigKeys = generated;
      expected = postconditionHash(expectedState);
      await files.write(path, JSON.stringify({ auditId, digest, operation: capability, state: 'intent', postconditionHash: expected }));
    }
    let resolution: Record<string, unknown> | undefined;
    if (contract.id === 'OP-083') {
      if (!object(value.response) || typeof value.response.temporaryDisableBlockingTill !== 'string' || !Number.isFinite(Date.parse(value.response.temporaryDisableBlockingTill))) throw new ToolError('UPSTREAM_INVALID', 'Invalid blocking expiry response', 'Read settings to verify the blocking expiry', 1);
      resolution = { response: { temporaryDisableBlockingTill: value.response.temporaryDisableBlockingTill } };
    }
    if (contract.id === 'OP-077') {
      if (!object(value.response) || !object(value.response.result) || (value.response.warningMessage !== undefined && typeof value.response.warningMessage !== 'string')) throw new ToolError('UPSTREAM_INVALID', 'Invalid DNS client response', 'Check the selected server API version', 1);
      resolution = { response: value.response.result,
        ...(mutating && value.response.warningMessage ? { mutation: 'suppressed' } : {}),
        ...(typeof value.response.warningMessage === 'string' ? { warningMessage: value.response.warningMessage } : {}) };
    }
    if (contract.baselinePath && !await postcondition(expected)) throw new Error('Postcondition is not proven');
    if (contract.id === 'OP-030') {
      let completed = false;
      for (let attempt = 0; attempt < 3 && !completed; attempt++) completed = await postcondition(undefined);
      if (!completed) throw new Error('Transfer completion is not proven');
    }
    const partial = contract.id === 'OP-029' && object(value.response) && object(value.response.failed) && Object.keys(value.response.failed).length > 0;
    if (mutating) await files.write(path, JSON.stringify({ auditId, digest, operation: capability, state: partial ? 'partial' : 'completed', postconditionHash: expected, resyncSerial }));
    return { bytes: response.bytes, projection: { status: partial ? 'partial' : 'ok', operation: capability,
      ...(partial && object(value.response) ? { deleted: value.response.deleted, failed: value.response.failed } : {}), ...(mutating ? { auditId } : {}),
      ...resolution,
      ...(contract.id === 'OP-002' ? { username: value.username, stored: true, info: { permissions: object(value.info) ? value.info.permissions : {} } } : {}),
      ...(contract.id === 'OP-005' ? { revoked: true, localRemoved } : {}),
      ...(profile.tokenKind === 'single-use' ? { credential: 'consumed' } : {}) } };
  } catch (error) {
    if (contract.id === 'OP-005') {
      const localRemoved = await removeSession(identity, profile, token);
      await files.write(path, JSON.stringify({ auditId, digest, operation: capability, state: 'revoke-failed', localRemoved }));
      return { bytes: Buffer.alloc(0), projection: { status: 'revoke-failed', operation: capability, auditId, revoked: false, localRemoved } };
    }
    if (error instanceof ToolError && ['AUTH_REQUIRED', 'TWO_FACTOR_REQUIRED'].includes(error.code)) throw error;
    if (!mutating) throw error;
    // The durable intent deliberately survives transport, handler and final-read failures.
    throw new ToolError('OUTCOME_UNKNOWN', `Mutation may have applied; audit ID ${auditId}${profile.tokenKind === 'single-use' ? '; credential consumed-or-uncertain' : ''}`,
      'Do not replay; read the exact selected target, or use --reconcile <audit-id> with the original input and confirmation', 1);
  }
}

async function identityResponse(profile: Profile, path: string, body: string, token: string): Promise<Record<string, unknown>> {
  const response = await vendorRequest(profile, path, body, token, {}, { bytes: 1024 * 1024, elapsedMs: 10000 });
  if (response.status !== 200 || response.contentType !== 'application/json') throw new ToolError('UPSTREAM_INVALID', 'Identity preflight failed', 'Check the selected server and identity', 1);
  let value: unknown;
  try { value = JSON.parse(response.bytes.toString()); } catch { throw new ToolError('UPSTREAM_INVALID', 'Invalid identity response', 'Check the selected API version', 1); }
  checkStatus(value);
  return value;
}
