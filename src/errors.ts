export class ToolError extends Error {
  constructor(readonly code: string, message: string, readonly hint: string, readonly exitCode = 2) {
    super(message);
  }
}

export function invalid(message: string): never {
  throw new ToolError('CONFIG_INVALID', message, 'Run technitium-axi schema --json to inspect valid profile fields');
}
