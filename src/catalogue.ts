import { readContracts } from './read-contracts.js';
import { archiveContract } from './archive-contract.js';

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
];

export const inventory = { version: 1, tool: 'technitium-axi', commands };
