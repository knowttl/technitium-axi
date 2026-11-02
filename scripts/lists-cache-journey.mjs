import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import seeds from '../tests/fixtures/read-seeds.json' with { type: 'json' };
import { resolveJourney } from './resolve-journey.mjs';

export const listsCacheTasks = [19, 54, 55, 57, 58, 59, 60, 63, 64, 65, 66, 77].map(id => `B3.OP-${String(id).padStart(3, '0')}`);

// Synthetic worlds based on the pinned cache, list and dashboard handlers.
export async function listsCacheJourney(context) {
  const { task, directory, env, run, executable, vendors, config, token, configure, success, failure, execute } = context;
  if (task === 'B3.OP-077') return await resolveJourney(context);
  const id = task.slice(3);
  const rows = {
    'OP-019': ['dashboard stats delete-all', '/api/dashboard/stats/deleteAll', { node: 'node-a.example.test' }, 'stats', []],
    'OP-054': ['cache delete', '/api/cache/delete', { domain: 'example.test' }, 'cache', ['other.test']],
    'OP-055': ['cache flush', '/api/cache/flush', {}, 'cache', []],
    ...Object.fromEntries(['allowed', 'blocked'].flatMap((family, index) => ['add', 'delete', 'flush', 'import'].map((action, offset) => [
      `OP-${String(57 + index * 6 + offset).padStart(3, '0')}`,
      [`${family} ${action}`, `/api/${family}/${action}`, action === 'import' ? { [`${family}Zones`]: ['a.test', 'b.test', 'a.test'] }
        : action === 'flush' ? {} : { domain: 'example.test' }, family,
      action === 'add' ? ['example.test', 'keep.test'] : action === 'delete' ? ['keep.test'] : action === 'flush' ? [] : ['a.test', 'b.test', 'example.test', 'keep.test']],
    ]))),
  };
  const [command, path, parameters, family, expected] = rows[id];
  const initial = { cache: ['example.test', 'child.example.test', 'other.test'], allowed: ['example.test', 'keep.test'],
    blocked: ['example.test', 'keep.test'], stats: ['a.stat', 'b.stat'], nodeB: ['keep.stat'], authoritative: ['example.test'], counters: 42 };
  let world = structuredClone(initial);
  let writes = 0;
  let denied = false;
  let submitted = parameters;
  vendors.responders.set(path, (incoming, bytes) => {
    assert.equal(incoming.method, 'POST');
    assert.equal(incoming.headers['content-type'], 'application/x-www-form-urlencoded');
    assert.deepEqual(Object.fromEntries(new URLSearchParams(bytes.toString())), Object.fromEntries(Object.entries(submitted).map(([key, value]) => [key, Array.isArray(value) ? value.join(',') : String(value)])));
    writes++;
    if (denied) return { body: { status: 'error', errorMessage: 'Permission denied' } };
    if (command.endsWith('add')) world[family] = [...new Set([...world[family], parameters.domain])].sort();
    else if (command.endsWith('import')) world[family] = [...new Set([...world[family], ...submitted[`${family}Zones`]])].sort();
    else if (command.endsWith('delete')) world[family] = world[family].filter(domain => domain !== parameters.domain && !domain.endsWith(`.${parameters.domain}`));
    else world[family] = [];
    return { body: { status: 'ok' } };
  });
  for (const name of ['cache', 'allowed', 'blocked']) vendors.responders.set(`/api/${name}/list`, () => ({ body: { status: 'ok', response: { domain: '', zones: world[name], records: [] } } }));
  vendors.responders.set('/api/dashboard/stats/get', () => ({ body: { status: 'ok', response: { ...seeds.responses['OP-017'], stats: { ...seeds.responses['OP-017'].stats, totalQueries: world.stats.length ? 42 : 0 } } } }));
  let reads = 0;
  const verify = async expectedWorld => {
    for (const name of ['cache', 'allowed', 'blocked']) {
      const resultFile = join(directory, `${id}-${reads++}.json`);
      const result = await run(executable, [name, 'list', '--domain', '', '--config', config, '--json', '--result-file', resultFile], { env: { ...env, WRITE_TOKEN: token } });
      assert.equal(result.code, 0, result.stdout + result.stderr);
      assert.deepEqual(JSON.parse(await readFile(resultFile, 'utf8')).response.zones, expectedWorld[name]);
    }
    assert.deepEqual(world, expectedWorld, 'Only the selected storage changes');
    if (id === 'OP-019') {
      const resultFile = join(directory, `${id}-${reads++}.json`);
      const result = await run(executable, ['dashboard', 'stats', 'get', '--node', parameters.node, '--config', config, '--json', '--result-file', resultFile], { env: { ...env, WRITE_TOKEN: token } });
      assert.equal(result.code, 0, result.stdout + result.stderr);
      assert.equal(JSON.parse(await readFile(resultFile, 'utf8')).response.stats.totalQueries, expectedWorld.stats.length ? 42 : 0);
    }
  };
  await configure([id]);
  const input = { parameters };
  await verify(initial);
  const before = vendors.traces.length;
  const preview = await success(command, input);
  assert.equal(vendors.traces.length, before, 'Preview never dispatches');
  await success(command, input, ['--execute', '--confirm', preview.preview.digest]);
  await verify({ ...initial, [family]: expected });
  await failure('REPLAY_DENIED', command, input, ['--execute', '--confirm', preview.preview.digest]);
  assert.equal(writes, 1);
  if (command.endsWith('add')) {
    await execute(command, input);
    await verify({ ...initial, [family]: expected });
  }
  if (command.endsWith('import')) {
    submitted = { [`${family}Zones`]: [] };
    await execute(command, { parameters: submitted });
    await verify({ ...initial, [family]: expected });
    const count = vendors.traces.length;
    await failure('USAGE', command, { parameters: { [`${family}Zones`]: ['a.test,b.test'] } });
    assert.equal(vendors.traces.length, count);
  }
  world = structuredClone(initial);
  submitted = parameters;
  denied = true;
  const deniedPreview = await success(command, input);
  await failure('OUTCOME_UNKNOWN', command, input, ['--execute', '--confirm', deniedPreview.preview.digest]);
  await verify(initial);
}
