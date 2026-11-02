import { createHash, createHmac, randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { readOnly } from './credentials.js';
import type { Profile } from './credentials.js';
import { ToolError } from './errors.js';
import { PrivateFiles } from './private-file.js';
import { checkStatus, Redactor, vendorRequest } from './vendor.js';
import { recordFamilies, recordTypeNames } from './write-contracts.js';
import type { WriteContract } from './write-contracts.js';

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
const lists = new Set('primaryNameServerAddresses queryAccessNetworkACL zoneTransferNetworkACL zoneTransferTsigKeyNames notifyNameServers notifySecondaryCatalogsNameServers updateNetworkACL blockListUrls forwarders proxyBypass members glue'.split(' '));

function baselineValue(key: string, value: unknown): unknown {
  if (['blockListUrls', 'forwarders'].includes(key) && value === null) return [];
  if (['catalog', 'primaryZoneTransferTsigKeyName'].includes(key) && value === null) return '';
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
      const rows = [];
      for (let i = 0; i < policies.length; i += 3) rows.push(`${policies[i]!.replace(/^\.+|\.+$/g, '').toLowerCase()}|${policies[i + 1]!.replace(/^\.+|\.+$/g, '').toLowerCase()}|${policies[i + 2]!.split(/[, ]+/).filter(Boolean).map(type => type.toUpperCase()).sort().join(',')}`);
      return rows.sort().join('|');
    }
  }
  return value;
}

function selectedValues(values: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(values).map(([key, value]) => [key, baselineValue(key, value)]));
}

function validateValue(key: string, value: unknown): void {
  if (['allowedZones', 'blockedZones'].includes(key)) {
    if (!Array.isArray(value) || value.some(item => typeof item !== 'string' || !item.length || /[\x00-\x20\x7f,]/.test(item))) usage('Zone import requires an array of domain names without separators');
    return;
  }
  if (booleans.has(key)) { if (typeof value !== 'boolean') usage('Boolean input requires true or false'); }
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
  upload?: { file: string };
}

export async function writeInput(contract: WriteContract, path?: string): Promise<WriteInput> {
  if (!path) usage('A protected --input-file is required');
  let input: unknown;
  try { input = JSON.parse(await files.read(path)); } catch (error) {
    if (error instanceof SyntaxError) usage('Input must be valid JSON');
    throw error;
  }
  if (!object(input) || !object(input.parameters) || Object.keys(input).some(key => !['parameters', 'baseline', 'upload'].includes(key))) usage('Input requires parameters and optional baseline or upload');
  const parameters = input.parameters;
  for (const key of Object.keys(parameters)) if (!contract.fields.includes(key)) usage('Unknown input field');
  for (const key of contract.required) if (!Object.hasOwn(parameters, key) || parameters[key] === '') usage('Required input is missing');
  for (const [key, value] of Object.entries(parameters)) {
    if (contract.secrets?.includes(key)) {
      if (!object(value) || Object.keys(value).length !== 1 || !(
        (typeof value.env === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(value.env)) ||
        (typeof value.file === 'string' && isAbsolute(value.file)))) usage('Secret fields require an environment or protected absolute file SecretRef');
    } else {
      validateValue(key, value);
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
  if (input.baseline !== undefined && !object(input.baseline)) usage('Baseline must be an object');
  if (contract.baselinePath) {
    const fields = Object.keys(parameters).filter(key => !contract.baselineTarget?.includes(key));
    if (!fields.length || !object(input.baseline) || canonical(Object.keys(input.baseline).sort()) !== canonical(fields.sort())) usage('Provide the exact selected baseline for every changed field');
    for (const [key, value] of Object.entries(input.baseline)) validateValue(key, baselineValue(key, value));
  } else if (input.baseline !== undefined) usage('Baseline is not supported by this operation');
  if (input.upload !== undefined) {
    if (!['OP-022', 'OP-023'].includes(contract.id) || !object(input.upload) || Object.keys(input.upload).length !== 1 || typeof input.upload.file !== 'string' || !isAbsolute(input.upload.file)) usage('Upload requires a protected absolute file for zone create or import');
    if (Object.hasOwn(parameters, 'records') || (contract.id === 'OP-022' && parameters.type !== 'Primary')) usage('Uploaded records require Primary creation or an import without inline records');
  }
  if (contract.id === 'OP-023' && input.upload === undefined && typeof parameters.records !== 'string') usage('Import requires records or an upload');
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
  if (contract.id === 'OP-080' && fields.includes('forwarders')) {
    validateValue('forwarderProtocol', response.forwarderProtocol);
    preserved.forwarderProtocol = response.forwarderProtocol;
  }
  if (contract.id === 'OP-080' && fields.includes('proxyBypass')) {
    if (!object(response.proxy)) usage('Proxy bypass replacement requires an existing proxy');
    for (const [source, target] of Object.entries({ type: 'proxyType', address: 'proxyAddress', port: 'proxyPort', username: 'proxyUsername', password: 'proxyPassword' })) {
      const item = response.proxy[source];
      if (['username', 'password'].includes(source) && (item === undefined || item === null)) continue;
      validateValue(target, item);
      preserved[target] = item;
    }
  }
  const selected = Object.fromEntries(fields.map(key => {
    const source = contract.id === 'OP-109' && key === 'newGroup' ? 'name' : key;
    const container = contract.id === 'OP-080' && key === 'proxyBypass' ? response.proxy : response;
    const field = container === response ? source : 'bypass';
    if (!object(container) || !Object.hasOwn(container, field)) throw new ToolError('UPSTREAM_INVALID', 'Selected baseline fields are missing', 'Check the selected target and API version', 1);
    const item = baselineValue(key, container[field]);
    validateValue(key, item);
    return [key, item];
  }));
  return { selected, preserved };
}

export async function writeOperation(contract: WriteContract, input: WriteInput, profile: Profile, identity: string, token: string,
  options: { execute: boolean; confirm?: string; reconcile?: string }, redactor: Redactor) {
  const capability = contract.id === 'OP-077' ? input.parameters.import === true ? 'OP-077.import' : 'OP-077.resolve' : contract.id;
  const mutating = capability !== 'OP-077.resolve';
  const parameters = { ...input.parameters };
  for (const key of contract.secrets ?? []) {
    const ref = parameters[key];
    if (ref === undefined) continue;
    const selected = ref as { env?: string; file?: string };
    const value = selected.file ? await files.read(selected.file) : process.env[selected.env!];
    if (value === undefined || value.length > 1024 * 1024) usage('SecretRef is missing or too large');
    redactor.add(value);
    parameters[key] = value;
  }
  let upload: Buffer | undefined;
  if (input.upload) {
    upload = await files.readBytes(input.upload.file);
  }
  // A keyed digest binds credential and secret revisions without publishing an offline secret verifier.
  const intentId = !options.execute && !options.reconcile ? randomUUID() : options.confirm?.split('.')[0];
  const digest = `${intentId}.${createHmac('sha256', token).update(canonical({ intentId, origin: profile.origin, identity, username: profile.username ?? null,
    tokenKind: profile.tokenKind, caFile: profile.caFile ?? null, tlsServerName: profile.tlsServerName ?? null,
    capability, parameters, baseline: input.baseline ?? null, upload: upload ? hash(upload) : null })).digest('hex')}`;
  const permitted = !mutating || (!readOnly() && profile.writes?.allowWrites === true && profile.writes.operations.includes(capability));
  if (!options.execute && !options.reconcile) return { bytes: Buffer.alloc(0), projection: { preview: { digest, operation: capability,
    origin: profile.origin, identity, node: parameters.node ?? null, target: parameters.zone ?? parameters.domain ?? parameters.group ?? null,
    permitted, upload: upload ? { bytes: upload.length, sha256: hash(upload) } : null,
    replaces: contract.baselinePath ? Object.keys(input.baseline!) : [],
    ...(contract.baselinePath ? { concurrency: 'A single-writer window is required between the final read and write; the vendor has no atomic conditional setter' } : {}) } } };
  if (!permitted) throw new ToolError('WRITE_DENIED', 'Exact write grant is required and read-only mode overrides grants', 'Enable only the selected operation in the selected profile', 1);
  if (!intentId || !/^[a-f0-9-]{36}$/.test(intentId) || options.confirm !== digest) throw new ToolError('CONFIRMATION_MISMATCH', 'Preview confirmation no longer matches the selected input', 'Preview again and supply its exact digest', 1);
  if (contract.baselinePath && profile.tokenKind === 'single-use') throw new ToolError('TOKEN_KIND', 'A read-modify-write action needs multiple authenticated requests', 'Select an API or session profile for this operation', 1);
  const auditId = randomUUID();
  const path = journalPath(digest);
  const postconditionHash = (value: unknown) => createHmac('sha256', token).update(canonical(value)).digest('hex');
  const postcondition = async (expected: string | undefined) => {
    if (!contract.baselinePath || !expected) return false;
    const target = contract.id === 'OP-109' && parameters.newGroup !== undefined ? { ...parameters, group: parameters.newGroup } : parameters;
    return postconditionHash(await baselineRead(contract, profile, token, target, Object.keys(input.baseline!))) === expected;
  };
  if (options.reconcile) {
    const prior = JSON.parse(await files.read(path)) as { auditId: string; state: string; postconditionHash?: string };
    if (prior.auditId !== options.reconcile) usage('Audit ID does not match the confirmed operation');
    let proven = false;
    try { proven = Boolean(await postcondition(prior.postconditionHash)); } catch { /* A failed read cannot prove an outcome. */ }
    if (!proven) throw new ToolError('OUTCOME_UNKNOWN', `Outcome remains unknown; audit ID ${prior.auditId}`, 'Read the exact selected target and compare its full postcondition; never replay an uncertain write', 1);
    await files.write(path, JSON.stringify({ ...prior, state: 'reconciled' }));
    return { bytes: Buffer.alloc(0), projection: { status: 'reconciled', auditId: prior.auditId, operation: capability } };
  }
  let expected: string | undefined;
  if (contract.baselinePath) {
    const baseline = await baselineRead(contract, profile, token, parameters, Object.keys(input.baseline!));
    if (canonical(baseline.selected) !== canonical(selectedValues(input.baseline!))) throw new ToolError('CONFLICT', 'Selected baseline changed after preview', 'Read the selected values and preview a new explicit replacement', 1);
    const selected = selectedValues(Object.fromEntries(Object.keys(input.baseline!).map(key => [key, parameters[key]])));
    const preserved = { ...baseline.preserved };
    if (contract.id === 'OP-080' && Array.isArray(selected.forwarders) && selected.forwarders.length === 0) preserved.forwarderProtocol = 'Udp';
    expected = postconditionHash({ selected, preserved });
    if (typeof baseline.preserved.proxyPassword === 'string') redactor.add(baseline.preserved.proxyPassword);
    Object.assign(parameters, baseline.preserved);
  }
  if (mutating) {
    try { await files.create(path, JSON.stringify({ auditId, digest, operation: capability, state: 'intent', postconditionHash: expected })); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new ToolError('REPLAY_DENIED', 'This confirmed mutation already has a durable intent', 'Inspect its protected journal entry and reconcile the original audit ID; do not replay', 1);
      throw new ToolError('JOURNAL_FAILED', 'Durable intent could not be recorded', 'Repair the protected journal before executing any mutation', 1);
    }
  }
  const form = new URLSearchParams(Object.entries(parameters).map(([key, value]) => [key, Array.isArray(value) ? value.join(',') : String(value)]));
  let body: string | Buffer = form.toString();
  let requestPath = contract.path;
  const headers: Record<string, string> = {};
  if (upload) {
    const boundary = `technitium-${randomUUID()}`;
    requestPath += `?${form}`;
    headers['content-type'] = `multipart/form-data; boundary=${boundary}`;
    body = Buffer.concat([Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="zone.txt"\r\nContent-Type: text/plain\r\n\r\n`), upload, Buffer.from(`\r\n--${boundary}--\r\n`)]);
  }
  try {
    const response = await vendorRequest(profile, requestPath, body, token, headers, { bytes: 16 * 1024 * 1024, elapsedMs: 10000 });
    if (response.status !== 200 || response.contentType !== 'application/json') throw new Error('Response unavailable');
    const value: unknown = JSON.parse(response.bytes.toString());
    checkStatus(value);
    let resolution: Record<string, unknown> | undefined;
    if (contract.id === 'OP-077') {
      if (!object(value.response) || !object(value.response.result) || (value.response.warningMessage !== undefined && typeof value.response.warningMessage !== 'string')) throw new ToolError('UPSTREAM_INVALID', 'Invalid DNS client response', 'Check the selected server API version', 1);
      resolution = { response: value.response.result,
        ...(mutating && value.response.warningMessage ? { mutation: 'suppressed' } : {}),
        ...(typeof value.response.warningMessage === 'string' ? { warningMessage: value.response.warningMessage } : {}) };
    }
    if (contract.baselinePath && !await postcondition(expected)) throw new Error('Postcondition is not proven');
    if (mutating) await files.write(path, JSON.stringify({ auditId, digest, operation: capability, state: 'completed', postconditionHash: expected }));
    return { bytes: response.bytes, projection: { status: 'ok', operation: capability, ...(mutating ? { auditId } : {}),
      ...resolution,
      ...(profile.tokenKind === 'single-use' ? { credential: 'consumed' } : {}) } };
  } catch (error) {
    if (!mutating) throw error;
    // The durable intent deliberately survives transport, handler and final-read failures.
    throw new ToolError('OUTCOME_UNKNOWN', `Mutation may have applied; audit ID ${auditId}${profile.tokenKind === 'single-use' ? '; credential consumed-or-uncertain' : ''}`,
      'Do not replay; read the exact selected target, or use --reconcile <audit-id> with the original input and confirmation', 1);
  }
}
