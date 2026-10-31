export const commands = [
  { command: 'schema', description: 'Show the credential profile JSON Schema', effect: 'local', arguments: [], flags: ['--json', '--help'] },
  { command: 'inventory', description: 'Show the packaged command inventory', effect: 'local', arguments: [], flags: ['--json', '--help'] },
] as const;

export const inventory = { version: 1, tool: 'technitium-axi', commands };
