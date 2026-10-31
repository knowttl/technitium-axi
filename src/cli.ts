import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { encode } from '@toon-format/toon';
import { commands, inventory } from './catalogue.js';
import { configPath, loadConfig, selectProfile } from './credentials.js';
import { ToolError } from './errors.js';
import { PrivateFiles } from './private-file.js';
import { Redactor, saveResult, vendorRead } from './vendor.js';
import { readContracts } from './read-contracts.js';
import { readInputs, readOperation } from './reads.js';

const help = {
  description: 'Manage Technitium DNS Server through one selected credential profile', commands,
  flags: ['--help', '--version', '-v', '-V', '--json', '--config', '--profile'],
  examples: ['technitium-axi status --profile <name>', 'technitium-axi schema --json', 'technitium-axi user session get'],
};

export async function main(args: string[]): Promise<void> {
  const redactor = new Redactor();
  const json = args.includes('--json');
  const print = (value: unknown): void => { console.log(redactor.text(json ? JSON.stringify(value) : encode(value))); };
  try {
    const options: { config?: string; profile?: string; resultFile?: string; inputFile?: string } = {};
    const readOptions: Record<string, string> = {};
    const valueFlags = new Set(['--config', '--profile', '--result-file', '--input-file', '--fields', '--max-bytes', '--max-requests', '--max-pages', '--max-elapsed-ms',
      ...readContracts.flatMap(item => item.parameters.map(parameter => parameter.flag))]);
    const positional: string[] = [];
    const flags = new Set<string>();
    for (let i = 0; i < args.length; i++) {
      const arg = args[i]!;
      if (!arg.startsWith('-')) { positional.push(arg); continue; }
      if (flags.has(arg)) throw new ToolError('USAGE', 'Repeated flag', 'Provide each flag once');
      flags.add(arg);
      if (valueFlags.has(arg)) {
        const value = args[++i];
        if (value === undefined || value.startsWith('-') || (value === '' && ['--config', '--profile', '--result-file', '--input-file'].includes(arg))) throw new ToolError('USAGE', 'Flag requires a value', `Use ${arg} <value>`);
        if (arg === '--config') options.config = value;
        else if (arg === '--profile') options.profile = value;
        else if (arg === '--result-file') options.resultFile = value;
        else if (arg === '--input-file') options.inputFile = value;
        else readOptions[arg] = value;
      }
    }
    const command = positional.join(' ');
    const selected = commands.find(item => item.command === command);
    const allowed: readonly string[] = selected ? [...selected.flags, '--version', '-v', '-V'] : help.flags;
    if ([...flags].some(flag => !allowed.includes(flag))) throw new ToolError('USAGE', 'Unknown or prohibited flag', `Valid flags: ${allowed.join(', ')}`);
    if (command && !selected) throw new ToolError('USAGE', 'Unknown command or unexpected argument', 'Run technitium-axi --help');
    if (args.some(arg => ['--version', '-v', '-V'].includes(arg))) {
      console.log((JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }).version);
      return;
    }
    if (flags.has('--help')) {
      print(selected ? { command: selected.command, description: selected.description, flags: selected.flags, arguments: selected.arguments,
        examples: [`technitium-axi ${selected.command}`, `technitium-axi ${selected.command} --json`] } : help);
      return;
    }
    if (command === 'schema') { print(JSON.parse(await readFile(new URL('../axi-credential.schema.json', import.meta.url), 'utf8'))); return; }
    if (command === 'inventory') { print(inventory); return; }
    if (command === 'config path') { print({ config: configPath(options.config) }); return; }
    if (command === 'config import') {
      if (!options.inputFile) throw new ToolError('USAGE', 'Config input is required', 'Use config import --input-file <file>');
      const config = await loadConfig(resolve(options.inputFile), true);
      await new PrivateFiles().write(configPath(options.config), JSON.stringify(config));
      print({ config: configPath(options.config), profiles: Object.keys(config.profiles).length });
      return;
    }
    if (command === 'profile list') {
      const config = await loadConfig(configPath(options.config), options.config !== undefined || process.env.TECHNITIUM_AXI_CONFIG !== undefined);
      const profiles = Object.keys(config.profiles).sort().map(name => ({ name, default: name === config.defaultProfile }));
      print({ count: profiles.length, profiles, help: ['Run technitium-axi auth status --profile <name>'] });
      return;
    }
    if (options.resultFile && !isAbsolute(options.resultFile)) throw new ToolError('USAGE', 'Result file must be absolute', 'Use --result-file <absolute-path>');
    const readContract = readContracts.find(item => item.command === command);
    if (readContract) readInputs(readContract, readOptions);
    const credential = await selectProfile(options);
    let token: string | undefined;
    if (command && command !== 'status') { token = await credential.token(); redactor.add(token); }
    if (command === 'auth status') {
      print({ profile: credential.name, source: credential.source, origin: credential.profile.origin,
        tokenKind: credential.profile.tokenKind, tokenSource: credential.tokenSource });
      return;
    }
    const result = readContract && !['OP-001', 'OP-006'].includes(readContract.id)
      ? await readOperation(credential.profile, command, token, readOptions, flags.has('--full'))
      : await vendorRead(credential.profile, command === '' || command === 'status' ? 'status' : 'user session get', token);
    if ('secret' in result && typeof result.secret === 'string') redactor.add(result.secret);
    let reference;
    if (options.resultFile) {
      await saveResult(options.resultFile, result.bytes);
      reference = { path: options.resultFile, bytes: result.bytes.length, sha256: createHash('sha256').update(result.bytes).digest('hex') };
    }
    const executable = resolve(process.argv[1] ?? 'bin/technitium-axi.js');
    const home = homedir();
    print({ ...(command === '' ? { bin: executable.startsWith(`${home}/`) ? `~${executable.slice(home.length)}` : executable, description: help.description } : {}),
      ...result.projection, ...(reference ? { result: reference } : {}) });
  } catch (error) {
    const failure = error instanceof ToolError ? error : new ToolError('CONFIG_INVALID', 'Unable to read the selected configuration or protected file', 'Check config path, SecretRef, ownership and file permissions');
    print({ error: { code: failure.code, message: failure.message }, help: [failure.hint] });
    process.exitCode = failure.exitCode;
  }
}
