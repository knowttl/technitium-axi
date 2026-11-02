import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import source from '../tests/fixtures/source-inventory.json' with { type: 'json' };
import { credentialJourney } from './credential-journey.mjs';
import { readJourney } from './read-journey.mjs';
import { writeJourney, writeTasks } from './write-journey.mjs';
import { fakeVendors } from './vendor-fixture.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const sorted = values => [...values].sort();

// These inputs are intentionally owned by the credential/command boundary.
const parameterDispositions = {
  token: 'Profile bearer header; never a normal argument',
  'OP-002.includeInfo': 'Fixed true for private Standard-session acquisition and identity verification',
  'OP-022.domain': 'Compatibility spelling rejected; zone is the sole creation target',
};
export const closureExclusions = [{ operation: 'OP-052', branch: 'DNAME deletion', issue: 'https://github.com/knowttl/technitium-axi/issues/18',
  reason: 'Shipped library mapping and independent deletion review are unavailable; diagnostic rejection does not complete the mutation' }];

function outcomeTask(operation, command, readContract) {
  if (['OP-001', 'OP-006'].includes(operation)) return `B1.${operation}`;
  if (readContract) return readContract.kind === 'json' ? 'B2.01' : 'B2.02';
  if (command.startsWith('user ')) return 'B5.01';
  if (command.startsWith('admin sso user ')) return 'B5.02';
  if (command.startsWith('admin cluster ')) return 'B5.03';
  if (command.startsWith('admin sso ') || command.startsWith('admin ldap ')) return 'B5.sso-ldap';
  if (command.startsWith('admin ')) return 'B5.admin-accounts';
  if (command.startsWith('dhcp ')) return 'B4.dhcp';
  if (command.startsWith('zone dnssec ')) return 'B3.dnssec';
  if (command.startsWith('zone record ')) return 'B3.02';
  if (command.startsWith('cache ') || command.startsWith('allowed ') || command.startsWith('blocked ') || ['OP-019', 'OP-077'].includes(operation)) return 'B3.lists-cache';
  const task = writeTasks.find(task => task.endsWith(`.${operation}`));
  assert.ok(task, `${operation} has no executable outcome journey`);
  return task;
}

export async function closureJourney({ temporary, env, run, executable, packageRoot, packagePins }) {
  const checks = [];
  // The packed bytes, captured before installation, are the admission authority.
  const admit = async () => {
    for (const [file, expected] of Object.entries(packagePins)) {
      assert.equal(hash(await readFile(join(packageRoot, file))), expected, `Package integrity mismatch: ${file}`);
    }
  };
  await admit();
  for (const file of ['command-inventory.json', 'axi-credential.schema.json', 'bin/technitium-axi.js', 'package.json']) {
    const path = join(packageRoot, file);
    const original = await readFile(path);
    try {
      await writeFile(path, Buffer.concat([original, Buffer.from('\nTAMPERED\n')]));
      await assert.rejects(admit, /Package integrity mismatch/);
    } finally { await writeFile(path, original); }
  }
  await admit();
  checks.push('native:package-admission-and-tamper-refusal');
  const invoke = async args => {
    const result = await run(executable, [...args, '--json'], { env });
    assert.equal(result.code, 0, result.stdout + result.stderr);
    assert.equal(result.stderr, '');
    return JSON.parse(result.stdout);
  };
  const inventory = await invoke(['inventory']);
  assert.deepEqual(inventory, JSON.parse(await readFile(join(packageRoot, 'command-inventory.json'), 'utf8')));
  assert.deepEqual(await invoke(['schema']), JSON.parse(await readFile(join(packageRoot, 'axi-credential.schema.json'), 'utf8')));
  const { readContracts } = await import(pathToFileURL(join(packageRoot, 'dist/read-contracts.js')));
  const { writeContracts } = await import(pathToFileURL(join(packageRoot, 'dist/write-contracts.js')));
  const contracts = [...readContracts, ...writeContracts];
  assert.deepEqual(sorted(contracts.map(row => row.id)), sorted(source.operations.map(row => row.id)));
  const commands = inventory.commands.filter(row => row.operation);
  assert.deepEqual(sorted(commands.map(row => row.operation)), sorted(source.operations.map(row => row.id)));
  assert.equal(commands.length, 143);
  assert.equal(source.operations.flatMap(row => row.capabilities).length, 144);
  assert.equal(source.routes.length, 145);
  assert.equal(source.routes.reduce((count, row) => count + row.methods.length, 0), 287);
  assert.deepEqual(sorted(source.operations.flatMap(row => [row.path, ...row.aliases])), sorted(source.routes.map(row => row.path)));
  // APIDOCS repeats /api/zone/options and omits the leading slash on api/getStats.
  const obsolete = [...new Set([...source.operations.flatMap(row => row.obsolete), ...source.additionalObsoletePaths])];
  assert.equal(obsolete.length, 79);
  const routes = new Map(source.routes.map(row => [row.path, row]));
  for (const operation of source.operations) for (const alias of operation.aliases) {
    assert.equal(routes.get(alias).handler, routes.get(operation.path).handler, `${alias} changed handler identity`);
  }
  assert.equal(source.operations.flatMap(row => row.aliases).length, 2);
  assert.ok(obsolete.every(path => !routes.has(path)), 'An obsolete spelling is advertised as a supported source route');
  checks.push('native:pinned-routes-aliases-and-obsolete-spellings');
  const outcomes = [];
  let parameterCount = 0;
  for (const operation of source.operations) {
    const contract = contracts.find(row => row.id === operation.id);
    const command = commands.find(row => row.operation === operation.id);
    assert.equal(contract.path, operation.path, `${operation.id} source path differs`);
    assert.equal(command.command, operation.command, `${operation.id} public command differs`);
    const fields = command.input?.fields ?? command.arguments.map(row => row.name);
    for (const parameter of operation.parameters) {
      const disposition = parameterDispositions[`${operation.id}.${parameter}`] ?? parameterDispositions[parameter];
      assert.ok(fields.includes(parameter) || disposition, `${operation.id}.${parameter} has no public input or reviewed disposition`);
      parameterCount++;
    }
    const capabilities = command.input?.capabilities ?? [operation.id];
    assert.deepEqual(sorted(capabilities), sorted(operation.capabilities), `${operation.id} capability drift`);
    const help = await invoke([...operation.command.split(' '), '--help']);
    assert.equal(help.command, operation.command);
    assert.deepEqual(help.flags, command.flags);
    assert.deepEqual(help.arguments, command.arguments);
    const task = outcomeTask(operation.id, operation.command, readContracts.find(row => row.id === operation.id));
    outcomes.push(...operation.capabilities.map(capability => ({ capability, operation: operation.id, task })));
  }
  checks.push('native:all-operations-parameters-capabilities-and-public-help');
  const tasks = [...new Set([...outcomes.map(row => row.task), 'B2.05'])];
  const requests = new Set();
  for (const [index, task] of tasks.entries()) {
    const directory = join(temporary, `audit-${index}`);
    await mkdir(directory, { mode: 0o700 });
    const home = join(directory, 'home');
    await mkdir(home, { mode: 0o700 });
    const taskEnv = { ...env, HOME: home, XDG_CONFIG_HOME: join(home, 'config'), XDG_STATE_HOME: join(home, 'state'),
      APPDATA: join(home, 'config'), LOCALAPPDATA: join(home, 'state') };
    const vendors = await fakeVendors(directory);
    try {
      const context = { task, temporary: directory, env: taskEnv, run, executable, vendors };
      if (task.startsWith('B1.')) await credentialJourney(context);
      else if (task.startsWith('B2.')) await readJourney(context);
      else await writeJourney(context);
      for (const trace of vendors.traces) {
        const route = routes.get(trace.path);
        assert.ok(route, `Unexpected vendor route: ${trace.path}`);
        assert.ok(route.methods.includes(trace.method), `Unexpected vendor method: ${trace.method} ${trace.path}`);
        requests.add(trace.path);
      }
    } finally { await vendors.close(); }
    checks.push(`native:${task}:outcomes`);
    process.stderr.write(`B6.01: ${index + 1}/${tasks.length} outcome journeys passed (${task})\n`);
  }
  for (const operation of source.operations) assert.ok(requests.has(operation.path), `${operation.id} never reached the vendor boundary`);
  return { checks, expected: 3 + tasks.length, audit: { revision: source.revision, operations: commands.length, capabilities: outcomes.length,
    apiRoutes: source.routes.length, methodPathCombinations: 287, aliases: 2, obsoleteSpellings: obsolete.length,
    parameters: { reconciled: parameterCount, dispositions: parameterDispositions },
    outcomes: outcomes.map(row => ({ ...row, native: row.operation === 'OP-052' ? 'passed-with-excluded-branch' : 'passed', hosted: 'release-candidate-check-not-selected' })),
    browserRoutes: source.browserRoutes, exclusions: closureExclusions,
    scope: 'Pinned catalogue declarations and existing executable outcome journeys; not a new stable-version review or certification of every semantic branch',
    fullManagementComplete: false } };
}
