import { createHash } from 'node:crypto';
import type { Profile } from './credentials.js';
import { ToolError } from './errors.js';
import { readContracts } from './read-contracts.js';
import type { ReadContract, Shape } from './read-contracts.js';
import { checkStatus, vendorRequest } from './vendor.js';

const invalid = (): never => { throw new ToolError('UPSTREAM_INVALID', 'Unexpected server response fields or types', 'Check the selected server API version and operation', 1); };
const usage = (message: string): never => { throw new ToolError('USAGE', message, 'Run the selected command with --help'); };
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const sensitive = /password|secret|^token$|^privateKey$|^stackTrace$|^innerError/i;

export function readInputs(contract: ReadContract, options: Record<string, string>) {
  const form = new URLSearchParams();
  const headers: Record<string, string> = {};
  for (const parameter of contract.parameters) {
    const value = options[parameter.flag];
    if (value === undefined) {
      if (parameter.required) usage(`Missing ${parameter.flag}`);
      continue;
    }
    if (parameter.required && value === '') usage(`Missing ${parameter.flag}`);
    if (parameter.type === 'boolean' && !['true', 'false'].includes(value)) usage(`${parameter.flag} requires true or false`);
    if (parameter.type === 'integer' && (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) < (parameter.name === 'limit' ? 0 : 1) || Number(value) > 2147483647)) usage(`${parameter.flag} requires a bounded integer`);
    if (parameter.values && !parameter.values.includes(value)) usage(`Invalid value for ${parameter.flag}`);
    if (parameter.type === 'http-date' && (Number.isNaN(Date.parse(value)) || new Date(value).toUTCString() !== value)) usage(`${parameter.flag} requires an RFC 1123 GMT date`);
    if (parameter.type === 'date' && (!/^\d{4}-\d\d-\d\dT/.test(value) || Number.isNaN(Date.parse(value)))) usage(`${parameter.flag} requires an ISO 8601 date time`);
    if (parameter.type === 'zone-list' && value && value.split(',').some(zone => !/^(?=.{1,253}$)[\p{L}\p{N}_*-]+(?:\.[\p{L}\p{N}_*-]+)*\.?$/u.test(zone))) usage(`${parameter.flag} requires comma-separated zone names`);
    if (/[\x00-\x1f\x7f]/.test(value) || value.length > 65536) usage(`Invalid value for ${parameter.flag}`);
    if (parameter.location === 'header') headers[parameter.name] = value;
    else form.set(parameter.name, value);
  }
  return { form, headers };
}

function project(value: unknown, shape: Shape, nullable = false): unknown {
  if (typeof shape === 'string') {
    if (shape === 'unknown') return null;
    if (shape === 'nullable') {
      if (value !== null && typeof value !== 'string') invalid();
    } else if (typeof value !== shape) invalid();
    return value;
  }
  if ('array' in shape) {
    if (!Array.isArray(value)) return invalid();
    const itemShape = shape.array!;
    return value.map(item => {
      if (record(itemShape) && !('array' in itemShape)) {
        if (!record(item)) return invalid();
        const identity = ['name', 'rowNumber', 'fileName', 'username', 'section', 'scope', 'keyTag'].find(key => Object.hasOwn(itemShape, key));
        if (identity && !Object.hasOwn(item, identity)) return invalid();
      }
      return project(item, itemShape);
    });
  }
  if (value === null && nullable) return null;
  if (!record(value)) return invalid();
  return Object.fromEntries(Object.entries(shape).filter(([key]) => !sensitive.test(key) && Object.hasOwn(value, key))
    .map(([key, field]) => [key, project(value[key], field, key === 'proxy')]));
}

const listKeys: Record<string, string> = {
  'OP-020': 'zones', 'OP-021': 'catalogZoneNames', 'OP-037': 'dsRecords', 'OP-038': 'dnssecPrivateKeys',
  'OP-050': 'records', 'OP-053': 'zones', 'OP-056': 'zones', 'OP-062': 'zones', 'OP-068': 'apps',
  'OP-069': 'storeApps', 'OP-081': 'tsigKeyNames', 'OP-086': 'leases', 'OP-090': 'scopes',
  'OP-098': 'sessions', 'OP-101': 'users', 'OP-106': 'groups', 'OP-111': 'permissions',
  'OP-134': 'logFiles', 'OP-138': 'entries',
};

export async function readOperation(profile: Profile, command: string, token: string | undefined,
  options: Record<string, string>, full: boolean) {
  const contract = readContracts.find(item => item.command === command)!;
  const { form, headers } = readInputs(contract, options);
  const listKey = listKeys[contract.id];
  const listShape = listKey ? contract.response[listKey] : undefined;
  const rowShape = listShape && typeof listShape === 'object' && 'array' in listShape ? listShape.array : undefined;
  const fieldShape = rowShape && typeof rowShape === 'object' ? rowShape : contract.response;
  const fields = options['--fields']?.split(',');
  if (fields && (new Set(fields).size !== fields.length || fields.some(field => !Object.hasOwn(fieldShape, field) || sensitive.test(field)))) usage('Unknown or repeated output field');
  const cap = (flag: string, fallback: number, maximum: number): number => {
    const raw = options[flag];
    if (raw === undefined) return fallback;
    if (!/^[1-9]\d*$/.test(raw) || Number(raw) > maximum) usage(`${flag} requires an integer from 1 to ${maximum}`);
    return Number(raw);
  };
  const byteCap = cap('--max-bytes', 16 * 1024 * 1024, 64 * 1024 * 1024);
  const requestCap = cap('--max-requests', 12, 100);
  const pageCap = cap('--max-pages', 10, 100);
  const elapsedCap = cap('--max-elapsed-ms', 30000, 120000);
  const started = Date.now();
  let requests = 0;
  let bytesRead = 0;
  const request = async () => {
    let response;
    for (let attempt = 0; attempt < 2; attempt++) {
      if (++requests > requestCap || Date.now() - started >= elapsedCap) throw new ToolError('READ_LIMIT', 'Read request or elapsed cap reached', 'Resume with narrower filters or a larger bounded cap', 1);
      response = await vendorRequest(profile, contract.path, form.toString(), token, headers,
        { bytes: byteCap - bytesRead, elapsedMs: elapsedCap - (Date.now() - started) });
      bytesRead += response.bytes.length;
      if (![429, 502, 503, 504].includes(response.status) || profile.tokenKind === 'single-use' || attempt || requests === requestCap) break;
      // Never ignore server backoff. Retry only immediate transient reads; return longer guidance.
      if (response.retryAfter && response.retryAfter !== '0') break;
    }
    if (response!.status !== 200) {
      const code = response!.status === 401 ? 'AUTH_REQUIRED' : response!.status === 403 ? 'PERMISSION_DENIED'
        : response!.status === 404 ? 'UNSUPPORTED_OPERATION' : response!.status === 429 ? 'RATE_LIMITED' : 'UPSTREAM_HTTP';
      const backoff = response!.retryAfter;
      const hint = backoff && /^\d{1,9}$/.test(backoff) ? `Retry after ${backoff} seconds` : 'Check the selected server version, credential and permissions';
      throw new ToolError(code, 'Server rejected the read', hint, 1);
    }
    return response!;
  };
  const paged = ['OP-020', 'OP-138'].includes(contract.id);
  const pageSizeField = contract.id === 'OP-020' ? 'zonesPerPage' : 'entriesPerPage';
  if (paged) {
    if (!form.has('pageNumber')) form.set('pageNumber', '1');
    if (!form.has(pageSizeField)) form.set(pageSizeField, '100');
  }
  const response = await request();
  const metadata = { bytes: response.bytes.length, contentType: response.contentType,
    sha256: createHash('sha256').update(response.bytes).digest('hex'),
    ...(contract.id === 'OP-125' ? { lastModified: response.lastModified } : {}) };
  if (contract.kind !== 'json') {
    if (response.contentType === 'application/json' || /^\s*\{\s*"(?:status|errorMessage)"\s*:/.test(response.bytes.toString('utf8', 0, 64))) {
      let value: unknown;
      try { value = JSON.parse(response.bytes.toString('utf8')); } catch { invalid(); }
      checkStatus(value);
      invalid();
    }
    if (contract.id === 'OP-125' && (!response.lastModified || Number.isNaN(Date.parse(response.lastModified)) || new Date(response.lastModified).toUTCString() !== response.lastModified)) invalid();
    const expected = contract.kind === 'zip' ? ['application/zip', 'application/octet-stream']
      : contract.kind === 'csv' ? ['text/csv', 'text/plain', 'application/octet-stream'] : ['text/plain', 'application/octet-stream'];
    if (!expected.includes(response.contentType)) invalid();
    if (contract.kind === 'zip' && (!response.bytes.subarray(0, 2).equals(Buffer.from('PK')) || response.bytes.length < 22)) invalid();
    return { bytes: response.bytes, projection: { status: 'ok', operation: contract.id, ...metadata,
      ...(contract.kind === 'prometheus-text' ? { text: response.bytes.toString('utf8').slice(0, full ? 100000 : 1000),
        complete: response.bytes.length <= (full ? 100000 : 1000) } : {}) } };
  }
  const decode = (bytes: Buffer): Record<string, unknown> => {
    let value: unknown;
    try { value = JSON.parse(bytes.toString('utf8')); } catch { invalid(); }
    checkStatus(value);
    if (contract.id === 'OP-078') {
      if (typeof value.server !== 'string') return invalid();
      return value;
    }
    if (!record(value.response)) return invalid();
    const payload = value.response;
    const required = contract.id === 'OP-018' ? ({ TopClients: 'topClients', TopDomains: 'topDomains', TopBlockedDomains: 'topBlockedDomains' }[form.get('statsType')!])
      : listKeys[contract.id] ?? Object.keys(contract.response)[0];
    if (required && !Object.hasOwn(payload, required)) invalid();
    return payload;
  };
  if (response.contentType !== 'application/json') invalid();
  const payload = decode(response.bytes);
  if (contract.id === 'OP-075') return { bytes: response.bytes, projection: { status: 'ok', operation: contract.id, ...metadata } };
  let pages = 1;
  let complete = true;
  let continuation: number | undefined;
  let stoppedBy: string | undefined;
  if (paged && listKey) {
    if (!Array.isArray(payload[listKey]) || payload.pageNumber !== Number(form.get('pageNumber'))) invalid();
    const identity = (row: unknown): string => {
      if (!record(row) || (contract.id === 'OP-020' ? typeof row.name !== 'string' : !Number.isSafeInteger(row.rowNumber))) return invalid();
      return JSON.stringify(contract.id === 'OP-020' ? row.name : row.rowNumber);
    };
    const rows: unknown[] = [];
    const seen = new Set<string | undefined>();
    for (const row of payload[listKey] as unknown[]) {
      const key = identity(row);
      if (!seen.has(key)) { seen.add(key); rows.push(row); }
    }
    payload[listKey] = rows;
    let page = Number(form.get('pageNumber'));
    const hasNext = (value: Record<string, unknown>) => {
      if (value.totalPages !== undefined && (!Number.isInteger(value.totalPages) || Number(value.totalPages) < 0)) invalid();
      return value.totalPages === undefined ? (value[listKey] as unknown[]).length > 0 : page < Number(value.totalPages);
    };
    let last = payload;
    while (hasNext(last)) {
      continuation = page + 1;
      complete = false;
      if (!full || pages >= pageCap || requests >= requestCap || Date.now() - started >= elapsedCap || bytesRead >= byteCap) break;
      form.set('pageNumber', String(++page));
      let next;
      try { next = await request(); }
      catch (error) {
        if (!(error instanceof ToolError) || !['RESPONSE_LIMIT', 'READ_LIMIT', 'READ_TIMEOUT'].includes(error.code)) throw error;
        stoppedBy = error.code;
        break;
      }
      if (next.contentType !== 'application/json') invalid();
      last = decode(next.bytes);
      if (last.pageNumber !== page || !Array.isArray(last[listKey])) invalid();
      for (const row of last[listKey] as unknown[]) {
        const key = identity(row);
        if (!seen.has(key)) { seen.add(key); rows.push(row); }
      }
      pages++;
      complete = true;
      continuation = undefined;
    }
    const total = payload[contract.id === 'OP-020' ? 'totalZones' : 'totalEntries'];
    if (total !== undefined && (!Number.isSafeInteger(total) || Number(total) < 0)) invalid();
    if (complete && total !== undefined && Number(options['--page-number'] ?? 1) === 1 && rows.length !== total) {
      complete = false;
      stoppedBy = 'PROVIDER_TOTAL_MISMATCH';
    }
  }
  let projected = project(payload, contract.response) as Record<string, unknown>;
  if (fields && !(rowShape && typeof rowShape === 'object')) {
    projected = Object.fromEntries(fields.filter(field => Object.hasOwn(projected, field)).map(field => [field, projected[field]]));
  }
  const bounds: Record<string, { returned: number; available: number; complete: boolean }> = {};
  const truncations: Record<string, { returned: number; available: number }> = {};
  const bound = (value: unknown, path: string): unknown => {
    const limit = full ? 10000 : 100;
    if (typeof value === 'string') {
      const stringLimit = full ? 1000000 : 1000;
      if (value.length > stringLimit) { complete = false; truncations[path] = { returned: stringLimit, available: value.length }; }
      return value.slice(0, stringLimit);
    }
    if (Array.isArray(value)) {
      if (value.length > limit) { complete = false; truncations[path] = { returned: limit, available: value.length }; }
      return value.slice(0, limit).map((row, index) => bound(row, `${path}[${index}]`));
    }
    if (record(value)) return Object.fromEntries(Object.entries(value).map(([key, field]) => [key, bound(field, `${path}.${key}`)]));
    return value;
  };
  for (const [key, value] of Object.entries(projected)) {
    if (!Array.isArray(value)) continue;
    const limit = full ? 10000 : 100;
    let selected = value.slice(0, limit);
    bounds[key] = { returned: selected.length, available: value.length, complete: value.length <= limit };
    if (value.length > limit) complete = false;
    if (value.length > limit && paged && key === listKey) continuation = Number(options['--page-number'] ?? 1);
    if (fields && key === listKey && rowShape && typeof rowShape === 'object') {
      selected = selected.map(row => Object.fromEntries(fields.filter(field => record(row) && Object.hasOwn(row, field)).map(field => [field, (row as Record<string, unknown>)[field]])));
    } else if (!full) {
      selected = selected.map(row => record(row) ? Object.fromEntries(Object.entries(row).slice(0, 4)) : row);
    }
    projected[key] = selected;
  }
  projected = bound(projected, 'response') as Record<string, unknown>;
  return { bytes: response.bytes, projection: { status: 'ok', response: projected,
    output: { complete, pages, requests, bytesRead, collections: bounds,
      ...(Object.keys(truncations).length ? { truncations } : {}),
      ...(stoppedBy ? { stoppedBy } : {}),
      ...(continuation === undefined ? {} : { nextPage: continuation }) } } };
}
