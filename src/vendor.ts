import { request } from 'node:https';
import { checkServerIdentity } from 'node:tls';
import type { Profile } from './credentials.js';
import { ToolError } from './errors.js';
import { PrivateFiles } from './private-file.js';

export class Redactor {
  private readonly values = new Set<string>();
  add(value: string): void {
    if (!value) return;
    for (const form of [value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value), encodeURI(value)]) this.values.add(form);
  }
  text(value: string): string {
    for (const secret of [...this.values].sort((a, b) => b.length - a.length)) value = value.replaceAll(secret, '[REDACTED]');
    return value;
  }
}

function responseInvalid(): never {
  throw new ToolError('UPSTREAM_INVALID', 'Unexpected server response', 'Check the selected server API version and operation', 1);
}
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export async function vendorRequest(profile: Profile, path: string, body: string, token: string | undefined,
  headers: Record<string, string>, limits: { bytes: number; elapsedMs: number }) {
  const origin = new URL(profile.origin);
  const ca = profile.caFile ? await new PrivateFiles().read(profile.caFile, false) : undefined;
  return await new Promise<{ bytes: Buffer; contentType: string; status: number; retryAfter?: string; lastModified?: string }>((resolve, reject) => {
    const call = request(origin, {
      method: 'POST', path, ca, rejectUnauthorized: true,
      ...(profile.tlsServerName ? { servername: profile.tlsServerName,
        checkServerIdentity: (_hostname: string, certificate) => checkServerIdentity(profile.tlsServerName!, certificate) } : {}),
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body),
        ...headers, ...(token ? { authorization: `Bearer ${token}` } : {}) },
      signal: AbortSignal.timeout(Math.max(1, Math.min(10000, limits.elapsedMs))),
    }, incoming => {
      const chunks: Buffer[] = [];
      let size = 0;
      incoming.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > limits.bytes) incoming.destroy(new ToolError('RESPONSE_LIMIT', 'Response exceeded the byte cap', 'Use narrower filters or raise --max-bytes within its bound', 1));
        else chunks.push(chunk);
      });
      incoming.once('error', reject);
      incoming.once('end', () => {
        if (!incoming.complete) { reject(new ToolError('TRANSFER_INCOMPLETE', 'Server response was interrupted', 'Retry the read; no result file was completed', 1)); return; }
        resolve({ bytes: Buffer.concat(chunks), contentType: incoming.headers['content-type']?.split(';')[0]?.trim() ?? '',
          status: incoming.statusCode ?? 0, ...(incoming.headers['retry-after'] ? { retryAfter: incoming.headers['retry-after'] } : {}),
          ...(incoming.headers['last-modified'] ? { lastModified: incoming.headers['last-modified'] } : {}) });
      });
    });
    call.once('error', reject);
    call.end(body);
  }).catch(error => {
    if (error instanceof ToolError) throw error;
    if (error instanceof Error && error.name === 'AbortError') throw new ToolError('READ_TIMEOUT', 'Read exceeded its elapsed time cap', 'Retry with narrower filters', 1);
    throw new ToolError('TRANSPORT_FAILED', 'Verified HTTPS request failed', 'Check origin, caFile and tlsServerName; certificate verification is required', 1);
  });
}

export function checkStatus(value: unknown): asserts value is Record<string, unknown> {
  if (!object(value) || typeof value.status !== 'string') responseInvalid();
  if (value.status === 'invalid-token') throw new ToolError('AUTH_REQUIRED', 'The selected credential has expired or is invalid', 'Supply a valid credential for the same profile', 1);
  if (value.status === '2fa-required') throw new ToolError('TWO_FACTOR_REQUIRED', 'The server requires a second authentication factor', 'Supply a previously authenticated credential', 1);
  if (value.status === 'error') throw new ToolError('UPSTREAM_ERROR', 'Server reported an operation failure', 'Check the selected identity and operation permissions', 1);
  if (value.status !== 'ok') responseInvalid();
}

export async function vendorRead(profile: Profile, operation: 'status' | 'user session get', token?: string) {
  const path = operation === 'status' ? '/api/status' : '/api/user/session/get';
  const body = operation === 'status' ? '' : 'includeInfo=true';
  const response = await vendorRequest(profile, path, body, token, {}, { bytes: 1024 * 1024, elapsedMs: 10000 });
  if (response.status !== 200) throw new ToolError(response.status === 401 ? 'AUTH_REQUIRED' : response.status === 403 ? 'PERMISSION_DENIED'
    : response.status === 404 ? 'UNSUPPORTED_OPERATION' : response.status === 429 ? 'RATE_LIMITED' : 'UPSTREAM_HTTP',
    'Server rejected the request', 'Check the selected profile and server permissions', 1);
  if (response.contentType !== 'application/json') responseInvalid();
  const bytes = response.bytes;
  let value: unknown;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { responseInvalid(); }
  checkStatus(value);
  if (operation === 'status') {
    if (typeof value.server !== 'string' || typeof value.hasDefaultCredentials !== 'boolean' || typeof value.ssoEnabled !== 'boolean') responseInvalid();
    return { bytes, projection: { status: 'ok', server: value.server, hasDefaultCredentials: value.hasDefaultCredentials, ssoEnabled: value.ssoEnabled } };
  }
  if (typeof value.username !== 'string' || typeof value.token !== 'string' || !object(value.info) || typeof value.info.version !== 'string') responseInvalid();
  if ((profile.tokenKind === 'api' || value.tokenName !== undefined) && typeof value.tokenName !== 'string') responseInvalid();
  const permissions = value.info.permissions;
  if (!object(permissions)) responseInvalid();
  if (value.hasDnssecPrivateKeys !== undefined && typeof value.hasDnssecPrivateKeys !== 'boolean') responseInvalid();
  for (const permission of Object.values(permissions)) {
    if (!object(permission) || Object.values(permission).some(flag => typeof flag !== 'boolean')) responseInvalid();
  }
  return { bytes, projection: { status: 'ok', username: value.username,
    ...(value.tokenName !== undefined ? { tokenName: value.tokenName } : {}),
    ...(value.hasDnssecPrivateKeys !== undefined ? { hasDnssecPrivateKeys: value.hasDnssecPrivateKeys } : {}),
    info: { version: value.info.version, permissions } }, secret: value.token };
}

export async function saveResult(path: string, bytes: Buffer): Promise<void> {
  await new PrivateFiles().write(path, bytes);
}
