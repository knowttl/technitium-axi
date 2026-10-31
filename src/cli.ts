import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { encode } from '@toon-format/toon';
import { commands, inventory } from './catalogue.js';

const help = {
  description: 'Discover the Technitium DNS Server command and credential contracts',
  commands,
  flags: ['--help', '--version', '-v', '-V', '--json'],
  examples: ['technitium-axi --help', 'technitium-axi schema --json', 'technitium-axi inventory'],
};

export async function main(args: string[]): Promise<void> {
  const json = args.includes('--json');
  const print = (value: unknown): void => { console.log(json ? JSON.stringify(value) : encode(value)); };
  const fail = (code: string, message: string, hint: string): void => {
    print({ error: { code, message }, help: [hint] });
    process.exitCode = 2;
  };
  const positional = args.filter(arg => !arg.startsWith('-'));
  const command = positional[0];
  const selected = commands.find(item => item.command === command);
  const allowed: readonly string[] = selected ? [...selected.flags, '--version', '-v', '-V'] : help.flags;
  const unknown = args.find(arg => arg.startsWith('-') && !allowed.includes(arg));
  if (unknown) {
    // Do not echo input: an unrecognised flag can contain a secret value.
    fail('USAGE', 'Unknown flag', `Valid flags: ${allowed.join(', ')}`);
    return;
  }
  if (positional.length > 1 || (command !== undefined && selected === undefined)) {
    fail('USAGE', 'Unknown command or unexpected argument', 'Run technitium-axi --help; commands: schema, inventory');
    return;
  }
  if (args.some(arg => ['--version', '-v', '-V'].includes(arg))) {
    console.log((JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }).version);
    return;
  }
  if (args.includes('--help')) {
    print(selected ? {
      command: selected.command, description: selected.description, flags: selected.flags,
      examples: [`technitium-axi ${selected.command}`, `technitium-axi ${selected.command} --json`],
    } : help);
    return;
  }
  if (command === 'schema') {
    print(JSON.parse(await readFile(new URL('../axi-credential.schema.json', import.meta.url), 'utf8')));
    return;
  }
  if (command === 'inventory') {
    print(inventory);
    return;
  }
  const executable = resolve(process.argv[1] ?? 'bin/technitium-axi.js');
  const home = homedir();
  print({ bin: executable.startsWith(`${home}/`) ? `~${executable.slice(home.length)}` : executable,
    description: help.description,
    status: 'Package foundation installed; vendor operations are not yet available',
    help: ['Run technitium-axi schema --json', 'Run technitium-axi inventory'] });
}
