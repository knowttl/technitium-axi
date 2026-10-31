import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { Ajv } from 'ajv';
import { PrivateFiles } from './private-file.js';
import { invalid, ToolError } from './errors.js';

type SecretRef = { env: string } | { file: string } | { stored: true };
export interface Profile {
  origin: string;
  auth: 'token';
  tokenKind: 'api' | 'session' | 'single-use';
  token?: SecretRef;
  username?: string;
  caFile?: string;
  tlsServerName?: string;
  writes?: { allowWrites: false; operations: [] };
}
interface Config { version: 1; defaultProfile?: string; profiles: Record<string, Profile> }
const profileName = '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$';
const files = new PrivateFiles();
const fields = { origin: 'ORIGIN', auth: 'AUTH', tokenKind: 'TOKEN_KIND', token: 'TOKEN', username: 'USERNAME', caFile: 'CA_FILE', tlsServerName: 'TLS_SERVER_NAME' };

export function configPath(explicit?: string): string {
  const base = process.platform === 'win32' ? process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming')
    : process.env.XDG_CONFIG_HOME && isAbsolute(process.env.XDG_CONFIG_HOME) ? process.env.XDG_CONFIG_HOME : join(homedir(), '.config');
  return resolve(explicit ?? process.env.TECHNITIUM_AXI_CONFIG ?? join(base, 'technitium-axi', 'config.json'));
}

function statePath(): string {
  const base = process.platform === 'win32' ? process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local')
    : process.env.XDG_STATE_HOME && isAbsolute(process.env.XDG_STATE_HOME) ? process.env.XDG_STATE_HOME : join(homedir(), '.local', 'state');
  return join(base, 'technitium-axi', 'credentials.json');
}

export function readOnly(): boolean {
  const value = process.env.TECHNITIUM_AXI_READ_ONLY?.toLowerCase();
  if (value === undefined || ['0', 'false'].includes(value)) return false;
  if (['1', 'true'].includes(value)) return true;
  return invalid('TECHNITIUM_AXI_READ_ONLY must be a boolean');
}

async function validator() {
  const schema = JSON.parse(await readFile(new URL('../axi-credential.schema.json', import.meta.url), 'utf8'));
  const ajv = new Ajv({ strict: true });
  ajv.addKeyword({ keyword: 'x-secret', schemaType: 'boolean' });
  return { profile: ajv.compile<Profile>(schema), config: ajv.compile<Config>({
    type: 'object', additionalProperties: false, required: ['version', 'profiles'],
    properties: { version: { const: 1 }, defaultProfile: { type: 'string', pattern: profileName },
      profiles: { type: 'object', propertyNames: { pattern: profileName }, additionalProperties: schema } },
  }) };
}

export async function loadConfig(path: string, explicit = false): Promise<Config> {
  let raw;
  try { raw = await files.read(path, false); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    if (explicit) invalid('Selected config file does not exist');
    return { version: 1, profiles: {} };
  }
  let config: unknown;
  try { config = JSON.parse(raw); } catch { invalid('Config must contain valid JSON'); }
  if (!(await validator()).config(config)) invalid('Invalid config, profile fields or SecretRef');
  for (const profile of Object.values(config.profiles)) validateOrigin(profile);
  if (config.defaultProfile && !Object.hasOwn(config.profiles, config.defaultProfile)) invalid('Default profile does not exist');
  return config;
}

export async function selectProfile(options: { config?: string; profile?: string }, verifyAcl = false) {
  readOnly();
  const path = configPath(options.config);
  const config = await loadConfig(path, options.config !== undefined || process.env.TECHNITIUM_AXI_CONFIG !== undefined);
  const requested = options.profile ?? process.env.TECHNITIUM_AXI_PROFILE;
  const envFields = Object.entries(fields).filter(([, field]) => process.env[`TECHNITIUM_AXI_${field}`] !== undefined);
  let name: string;
  let source: string;
  let profile: Profile;
  if (requested !== undefined) {
    if (!new RegExp(profileName).test(requested)) invalid('Invalid profile name');
    const selected = config.profiles[requested];
    if (!selected) throw new ToolError('PROFILE_NOT_FOUND', 'Selected profile does not exist', 'Run technitium-axi profile list');
    name = requested;
    source = options.profile !== undefined ? 'flag' : 'profile-env';
    profile = selected;
  } else if (envFields.length) {
    const value = Object.fromEntries(envFields.map(([field, suffix]) => [field, field === 'token'
      ? { env: 'TECHNITIUM_AXI_TOKEN' } : process.env[`TECHNITIUM_AXI_${suffix}`]]));
    if (!(await validator()).profile(value)) invalid('Incomplete or invalid environment profile');
    name = 'env'; source = 'environment'; profile = value;
  } else {
    const names = Object.keys(config.profiles);
    const selected = config.defaultProfile ?? (names.length === 1 ? names[0] : undefined);
    if (!selected) throw new ToolError(names.length ? 'PROFILE_AMBIGUOUS' : 'PROFILE_REQUIRED', 'Select a credential profile', 'Use --config <file> --profile <name>');
    name = selected; source = config.defaultProfile ? 'default' : 'sole'; profile = config.profiles[name]!;
  }
  validateOrigin(profile);
  if (verifyAcl && source !== 'environment') await files.read(path, false, true);
  const tokenRef = profile.token ?? { env: 'TECHNITIUM_AXI_TOKEN' };
  const tokenSource = 'env' in tokenRef ? { env: tokenRef.env } : 'file' in tokenRef ? { file: tokenRef.file } : { stored: statePath() };
  return { name, source, path, profile, tokenSource, async token(): Promise<string> {
    let token: string | undefined;
    if ('env' in tokenRef) token = process.env[tokenRef.env];
    else if ('file' in tokenRef) token = (await files.read(tokenRef.file, true, verifyAcl)).replace(/^\uFEFF/, '').trimEnd();
    else {
      let stored: Record<string, { binding: unknown; token: string }>;
      try { stored = JSON.parse(await files.read(statePath(), true, verifyAcl)); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        stored = {};
      }
      const entry = stored[name];
      const binding = { origin: profile.origin, username: profile.username ?? null, tokenKind: profile.tokenKind,
        tlsServerName: profile.tlsServerName ?? null, caFile: profile.caFile ?? null };
      if (entry && JSON.stringify(entry.binding) === JSON.stringify(binding)) token = entry.token;
    }
    if (!token) throw new ToolError('AUTH_REQUIRED', 'A supplied token is required', 'Set the environment variable or protected file named by the selected token SecretRef', 1);
    if (/[\s\x00-\x1f\x7f]/.test(token)) invalid('Token contains invalid header characters');
    return token;
  } };
}

function validateOrigin(profile: Profile): void {
  let url;
  try { url = new URL(profile.origin); } catch { invalid('Invalid HTTPS origin'); }
  if (url.origin !== profile.origin || url.protocol !== 'https:') invalid('Use a canonical HTTPS origin without a path, query or userinfo');
}
