import { request } from 'node:https';
import { readFile } from 'node:fs/promises';
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

export async function vendorRead(profile: Profile, operation: 'status' | 'user session get', token?: string) {
  const origin = new URL(profile.origin);
  if (origin.origin !== profile.origin || origin.protocol !== 'https:') responseInvalid();
  const ca = profile.caFile ? await readFile(profile.caFile) : undefined;
  const body = operation === 'status' ? '' : 'includeInfo=true';
  const bytes = await new Promise<Buffer>((resolve, reject) => {
    const call = request(origin, {
      method: 'POST', path: operation === 'status' ? '/api/status' : '/api/user/session/get',
      ca, rejectUnauthorized: true,
      ...(profile.tlsServerName ? { servername: profile.tlsServerName,
        checkServerIdentity: (_hostname: string, certificate) => checkServerIdentity(profile.tlsServerName!, certificate) } : {}),
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body),
        ...(token ? { authorization: `Bearer ${token}` } : {}) },
      signal: AbortSignal.timeout(10000),
    }, incoming => {
      if (incoming.statusCode !== 200) {
        incoming.resume();
        reject(new ToolError(incoming.statusCode === 401 ? 'AUTH_REQUIRED' : 'UPSTREAM_HTTP', 'Server rejected the request', 'Check the selected profile and server permissions', 1));
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      incoming.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > 1024 * 1024) incoming.destroy(new Error('Response limit'));
        else chunks.push(chunk);
      });
      incoming.once('error', reject);
      incoming.once('end', () => resolve(Buffer.concat(chunks)));
    });
    call.once('error', reject);
    call.end(body);
  }).catch(error => {
    if (error instanceof ToolError) throw error;
    throw new ToolError('TRANSPORT_FAILED', 'Verified HTTPS request failed', 'Check origin, caFile and tlsServerName; certificate verification is required', 1);
  });
  let value: unknown;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { responseInvalid(); }
  if (!object(value)) responseInvalid();
  if (value.status === 'invalid-token') throw new ToolError('AUTH_REQUIRED', 'The selected credential has expired or is invalid', 'Supply a valid credential for the same profile', 1);
  if (value.status !== 'ok') throw new ToolError('UPSTREAM_ERROR', 'Server reported an operation failure', 'Check the selected identity and operation permissions', 1);
  if (operation === 'status') {
    if (typeof value.server !== 'string' || typeof value.hasDefaultCredentials !== 'boolean' || typeof value.ssoEnabled !== 'boolean') responseInvalid();
    return { bytes, projection: { status: 'ok', server: value.server, hasDefaultCredentials: value.hasDefaultCredentials, ssoEnabled: value.ssoEnabled } };
  }
  if (typeof value.username !== 'string' || typeof value.tokenName !== 'string' || typeof value.token !== 'string' || !object(value.info) || typeof value.info.version !== 'string') responseInvalid();
  const permissions = value.info.permissions;
  if (!object(permissions)) responseInvalid();
  if (value.hasDnssecPrivateKeys !== undefined && typeof value.hasDnssecPrivateKeys !== 'boolean') responseInvalid();
  for (const permission of Object.values(permissions)) {
    if (!object(permission) || Object.values(permission).some(flag => typeof flag !== 'boolean')) responseInvalid();
  }
  return { bytes, projection: { status: 'ok', username: value.username, tokenName: value.tokenName,
    ...(value.hasDnssecPrivateKeys !== undefined ? { hasDnssecPrivateKeys: value.hasDnssecPrivateKeys } : {}),
    info: { version: value.info.version, permissions } }, secret: value.token };
}

export async function saveResult(path: string, bytes: Buffer): Promise<void> {
  await new PrivateFiles().write(path, bytes);
}
