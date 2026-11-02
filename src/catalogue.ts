import { readContracts } from './read-contracts.js';
import { archiveContract } from './archive-contract.js';
import { writeContracts, writeFlags, recordFamilies } from './write-contracts.js';

export const readFlags = ['--json', '--help', '--config', '--profile', '--result-file', '--fields', '--full', '--max-bytes', '--max-requests', '--max-pages', '--max-elapsed-ms'];

export const commands = [
  { command: 'schema', description: 'Show the credential profile JSON Schema', effect: 'local', arguments: [], flags: ['--json', '--help'] },
  { command: 'inventory', description: 'Show the packaged command inventory', effect: 'local', arguments: [], flags: ['--json', '--help'] },
  { command: 'status', description: 'Read the selected server status without sending a credential', effect: 'read', operation: 'OP-001', arguments: [], flags: ['--json', '--help', '--config', '--profile'] },
  { command: 'user session get', description: 'Read the selected session with a redacted projection and optional protected result file', effect: 'read', operation: 'OP-006', arguments: [], flags: ['--json', '--help', '--config', '--profile', '--result-file'] },
  { command: 'auth status', description: 'Verify the selected credential and report its source without values', effect: 'local', arguments: [], flags: ['--json', '--help', '--config', '--profile'] },
  { command: 'profile list', description: 'List profile names from the selected config', effect: 'local', arguments: [], flags: ['--json', '--help', '--config'] },
  { command: 'config path', description: 'Show the selected config path', effect: 'local', arguments: [], flags: ['--json', '--help', '--config'] },
  { command: 'config import', description: 'Validate and atomically install a config containing SecretRefs', effect: 'local', arguments: [], flags: ['--json', '--help', '--config', '--input-file'] },
  { command: 'doctor', description: 'Verify credential protection and perform one bounded session read', effect: 'read', arguments: [], flags: ['--json', '--help', '--config', '--profile'] },
  ...readContracts.filter(item => !['OP-001', 'OP-006'].includes(item.id)).map(item => ({
    command: item.command, description: `Read ${item.command}`, effect: 'read', operation: item.id,
    arguments: item.parameters, flags: [...readFlags, ...item.parameters.map(parameter => parameter.flag)],
    ...(['OP-084', 'OP-125'].includes(item.id) ? { archive: archiveContract } : {}),
  })),
  ...writeContracts.map(item => ({ command: item.command, description: `Preview or execute ${item.command}`, effect: item.id === 'OP-077' ? 'conditional' : 'write', operation: item.id,
    arguments: [], flags: writeFlags, input: { envelope: ['parameters', 'baseline', 'upload'], fields: item.fields,
      required: item.required, secrets: item.secrets ?? [], baseline: item.baselinePath ?? null,
      ...(['OP-022', 'OP-023'].includes(item.id) ? { upload: { file: 'protected absolute path', format: item.id === 'OP-023' ? ['multipart (default)', 'text'] : ['multipart'] } } : {}),
      ...(item.id === 'OP-029' ? { target: 'Exactly one of zone or nonempty zones array' } : {}),
      ...(item.id === 'OP-034' ? { permissions: { userPermissions: ['username', 'canView', 'canModify', 'canDelete'], groupPermissions: ['name', 'canView', 'canModify', 'canDelete'], shape: 'Array of rows; permission flags are booleans; an empty user array clears user permissions; group replacements retain Administrators and DNS Administrators with all permissions' } } : {}),
      ...(item.id === 'OP-077' ? { capabilities: ['OP-077.resolve', 'OP-077.import'] } : {}),
      ...(['OP-049', 'OP-051', 'OP-052'].includes(item.id) ? { recordFamilies, dnameDeletion: 'pending shipped-library mapping and independent review' } : {}) } })),
];

export const inventory = { version: 1, tool: 'technitium-axi', commands };
