import { readContracts } from './read-contracts.js';
import { archiveContract } from './archive-contract.js';
import { writeContracts, writeFlags, recordFamilies } from './write-contracts.js';
import { settingsFields, dhcpFields, identityFields } from './configuration.js';
import { routing } from './routing.js';

export const readFlags = ['--json', '--help', '--config', '--profile', '--result-file', '--fields', '--full', '--max-bytes', '--max-requests', '--max-pages', '--max-elapsed-ms'];

export const commands = [
  { command: 'schema', description: 'Show the credential profile JSON Schema', effect: 'local', arguments: [], flags: ['--json', '--help'] },
  { command: 'inventory', description: 'Show the packaged command inventory', effect: 'local', arguments: [], flags: ['--json', '--help'] },
  { command: 'status', description: 'Read the selected server status without sending a credential', effect: 'read', operation: 'OP-001', arguments: [], flags: ['--json', '--help', '--config', '--profile'] },
  { command: 'user session get', description: 'Read the selected session with a redacted projection and optional protected result file', effect: 'read', operation: 'OP-006', arguments: [], flags: ['--json', '--help', '--config', '--profile', '--result-file'] },
  { command: 'auth status', description: 'Verify the selected credential and report its source without values', effect: 'local', arguments: [], flags: ['--json', '--help', '--config', '--profile'] },
  ...['login', 'logout'].map(action => ({ command: `auth ${action}`, description: `Alias for user ${action}`, effect: 'write', arguments: [], flags: writeFlags })),
  { command: 'profile list', description: 'List profile names from the selected config', effect: 'local', arguments: [], flags: ['--json', '--help', '--config'] },
  { command: 'config path', description: 'Show the selected config path', effect: 'local', arguments: [], flags: ['--json', '--help', '--config'] },
  { command: 'config import', description: 'Validate and atomically install a config containing SecretRefs', effect: 'local', arguments: [], flags: ['--json', '--help', '--config', '--input-file'] },
  { command: 'doctor', description: 'Verify credential protection and perform one bounded session read', effect: 'read', arguments: [], flags: ['--json', '--help', '--config', '--profile'] },
  ...readContracts.filter(item => !['OP-001', 'OP-006'].includes(item.id)).map(item => ({
    command: item.command, description: `Read ${item.command}`, effect: 'read', operation: item.id, routing: routing(item.id),
    arguments: item.parameters, flags: [...readFlags, ...item.parameters.map(parameter => parameter.flag)],
    ...(['OP-084', 'OP-125'].includes(item.id) ? { archive: archiveContract } : {}),
  })),
  ...writeContracts.map(item => ({ command: item.command, description: `Preview or execute ${item.command}`, effect: item.id === 'OP-077' ? 'conditional' : 'write', operation: item.id,
    arguments: [], flags: [...writeFlags, ...(['OP-119', 'OP-127'].includes(item.id) ? ['--reconcile-profile'] : [])], routing: routing(item.id), input: { envelope: ['parameters', 'baseline', 'upload'], fields: item.fields,
      required: item.required, secrets: item.secrets ?? [], baseline: item.baselinePath ?? null,
      ...(['OP-002', 'OP-003', 'OP-004', 'OP-009', 'OP-099'].includes(item.id) ? { resultPolicy: { classification: 'confidential-fields', ordinaryOutput: 'metadata and approved projection only', localResult: item.id === 'OP-002' ? 'issued Standard session stored privately; optional exact protected result' : 'required protected result file', hostedResult: 'caller and credential revision bound protected custody' } } : {}),
      ...(['OP-022', 'OP-023'].includes(item.id) ? { upload: { file: 'protected absolute path', format: item.id === 'OP-023' ? ['multipart (default)', 'text'] : ['multipart'] } } : {}),
      ...(['OP-072', 'OP-073', 'OP-085'].includes(item.id) ? { upload: { file: 'required protected absolute ZIP path', transport: 'multipart first binary file; parameters in query string' } } : {}),
      ...(item.id === 'OP-076' ? { config: 'File SecretRef containing the exact opaque config string; never printed' } : {}),
      ...(item.id === 'OP-029' ? { target: 'Exactly one of zone or nonempty zones array' } : {}),
      ...(item.id === 'OP-034' ? { permissions: { userPermissions: ['username', 'canView', 'canModify', 'canDelete'], groupPermissions: ['name', 'canView', 'canModify', 'canDelete'], shape: 'Array of rows; permission flags are booleans; an empty user array clears user permissions; group replacements retain Administrators and DNS Administrators with all permissions' } } : {}),
      ...(item.id === 'OP-113' ? { permissions: { userPermissions: ['username', 'canView', 'canModify', 'canDelete'], groupPermissions: ['name', 'canView', 'canModify', 'canDelete'], shape: 'Array of rows with boolean flags; empty arrays clear permissions; vendor retains Administrators, plus DNS Administrators for Zones or DHCP Administrators for DhcpServer; section writes require the primary' } } : {}),
      ...(item.id === 'OP-080' ? { configuration: settingsFields, encoding: ['form', 'json'], secretRows: 'tsigKeys rows require a SecretRef for sharedSecret' } : {}),
      ...(item.id === 'OP-092' ? { configuration: dhcpFields, target: 'Existing scope; baseline.newName is the current name when renaming; collections replace the selected collection' } : {}),
      ...(['OP-115', 'OP-142', 'OP-143'].includes(item.id) ? { configuration: Object.fromEntries(item.fields.map(key => [key, identityFields[key]])), target: item.id === 'OP-143' ? 'Outbound LDAP bind using stored fields and explicit overrides; requires exact OP-143 write grant' : 'Only supplied fields change; scopes and group maps replace their selected collection', ...(item.id === 'OP-115' ? { scopesEncoding: 'pipe-delimited string array' } : {}) } : {}),
      ...(item.command.startsWith('dhcp lease ') ? { target: 'Exactly one of clientIdentifier or hardwareAddress' } : {}),
      ...(item.id === 'OP-077' ? { capabilities: ['OP-077.resolve', 'OP-077.import'] } : {}),
      ...(['OP-049', 'OP-051', 'OP-052'].includes(item.id) ? { recordFamilies, dnameDeletion: 'pending shipped-library mapping and independent review' } : {}) } })),
];

export const inventory = { version: 1, tool: 'technitium-axi', commands, dhcpFields };
