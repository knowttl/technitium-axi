import type { SpawnOptions } from 'node:child_process';
import type { fakeVendors } from './vendor-fixture.ts';

export interface RunResult { code: number | null; stdout: string; stderr: string }
export interface DiscoveryOutput {
  commands: { command: string }[]; command: string; error: { code: string }; help: string[];
}
export interface CatalogueCommand {
  command: string; operation?: string; effect?: string; flags: string[]; arguments: { name: string }[];
  input?: { fields: string[]; capabilities: string[]; envelope: string[] };
  archive?: typeof import('../src/archive-contract.ts').archiveContract;
}
export interface CatalogueOutput { commands: CatalogueCommand[] }
export type RunOptions = Omit<SpawnOptions, 'stdio'> & { stdin?: string; forwardStderr?: boolean };
export type Run = (executable: string, argv: string[], options?: RunOptions) => Promise<RunResult>;
export type Environment = NodeJS.ProcessEnv & { XDG_CONFIG_HOME: string; XDG_STATE_HOME: string };
export interface JourneyContext {
  task: string; temporary: string; env: Environment; run: Run; executable: string;
  vendors: Awaited<ReturnType<typeof fakeVendors>>;
}
export interface WriteInput {
  parameters: Record<string, unknown>; baseline?: Record<string, unknown>;
  upload?: Record<string, unknown>; encoding?: string;
}
export interface WriteOutput {
  preview: {
    digest: string; permitted: boolean; operation: string;
    upload: { sha256: string }; sideEffects: string[]; replaces: unknown[];
    routing: { replication: string }; target: unknown;
  };
  error: { code: string; message: string };
  result: { sha256: string };
  response: unknown; status: string; auditId: string; operation: string;
  warningMessage: string; mutation: string; verifiedProfile: string;
  deleted: unknown; failed: unknown;
  help: string[]; cluster: { uncertainty: string };
}
export type WriteArgs = [command: string, input: WriteInput, flags?: string[], extraEnv?: NodeJS.ProcessEnv];
export type SecretWriteContext = WriteContext & { secret: string };
export interface WriteContext extends Omit<JourneyContext, 'temporary'> {
  directory: string; config: string; token: string; secret?: string;
  configure: (operations?: string[], extra?: Record<string, unknown>) => Promise<void>;
  success: (...args: WriteArgs) => Promise<WriteOutput>;
  failure: (code: string, ...args: WriteArgs) => Promise<WriteOutput>;
  execute: (command: string, input: WriteInput, extraEnv?: NodeJS.ProcessEnv) => Promise<WriteOutput>;
}
