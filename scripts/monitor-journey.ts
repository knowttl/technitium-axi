import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { IncomingMessage } from 'node:http';
import { join } from 'node:path';

type ObjectValue = Record<string, unknown>;
interface Row {
  operation: string; command: string; path: string; kind: string;
  parameters: { name: string; flag: string; requested: string; location: string }[];
  response: { status: string; response: ObjectValue }; ordinaryResponse: ObjectValue;
}
interface Output {
  response: ObjectValue; output: { complete: boolean; nextPage?: number };
  result: { sha256: string }; [key: string]: unknown;
}
interface Response { body?: unknown; bytes?: Buffer; contentType?: string; status?: number }
interface Context {
  row: Row; directory: string;
  vendors: {
    responders: Map<string, (request: IncomingMessage, body: Buffer) => Response>;
    traces: { inputHash: string; path: string; method: string }[];
  };
  success: (args: string[], json?: boolean) => Promise<Output>;
  fail: (args: string[], code: string) => Promise<void>;
  archive: (names: string[]) => Buffer;
  components: Record<string, string[]>;
}
const hash = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');

export async function monitorJourney({ row, directory, vendors, success, fail, archive, components }: Context): Promise<string[]> {
  const scenarios = JSON.parse(await readFile(new URL('../tests/fixtures/monitor-reads.json', import.meta.url), 'utf8')) as {
    operations: Record<string, { text?: string; up?: ObjectValue; unfiltered?: ObjectValue[] }>;
  };
  const scenario = scenarios.operations[row.operation]!;
  const args = [...row.command.split(' '), ...row.parameters.flatMap(parameter => [parameter.flag, parameter.requested])];
  const form = new URLSearchParams(row.parameters.filter(parameter => parameter.location === 'form').map(parameter => [parameter.name, parameter.requested]));
  const respond = (body: unknown) => vendors.responders.set(row.path, () => ({ body }));
  const trace = () => {
    assert.equal(vendors.traces.at(-1)!.inputHash, hash(form.toString()));
    assert.equal(vendors.traces.at(-1)!.path, row.path);
    assert.equal(vendors.traces.at(-1)!.method, 'POST');
  };
  const destination = join(directory, `${row.operation}.result`);
  const saved = async (bytes: Buffer, command = args) => {
    const value = await success([...command, '--result-file', destination]);
    assert.deepEqual(await readFile(destination), bytes);
    assert.equal(value.result.sha256, hash(bytes));
    return value;
  };
  if (row.kind !== 'json') {
    const bytes = row.kind === 'zip' ? archive(Object.values(components).flat()) : Buffer.from(scenario.text!);
    const contentType = row.kind === 'zip' ? 'application/zip' : row.kind === 'csv' ? 'text/csv' : 'text/plain';
    vendors.responders.set(row.path, () => ({ bytes, contentType }));
    await saved(bytes);
    trace();
    respond({ status: 'error', errorMessage: 'SYNTHETIC-upstream-canary' });
    await fail([...args, '--result-file', destination], 'UPSTREAM_ERROR');
    assert.deepEqual(await readFile(destination), bytes);
    if (row.operation === 'OP-084') {
      for (const [component, names] of Object.entries(components)) {
        const selected = archive(names);
        vendors.responders.set(row.path, (_request, body) => {
          assert.deepEqual([...new URLSearchParams(body.toString())], [[component, 'true']]);
          return { bytes: selected, contentType };
        });
        const flag = row.parameters.find(parameter => parameter.name === component)!.flag;
        await saved(selected, [...row.command.split(' '), flag, 'true']);
      }
      vendors.responders.set(row.path, () => ({ status: 403, body: {} }));
      await fail(args, 'PERMISSION_DENIED');
      vendors.responders.set(row.path, () => ({ bytes: Buffer.from('not a zip'), contentType }));
      await fail(args, 'UPSTREAM_INVALID');
    }
    if (row.operation === 'OP-135') {
      const invalid = [...args];
      invalid[invalid.indexOf('--file-name') + 1] = '../2024-01-01';
      const before = vendors.traces.length;
      await fail(invalid, 'USAGE');
      assert.equal(vendors.traces.length, before);
      vendors.responders.set(row.path, () => ({ bytes, contentType }));
      for (const limit of ['0', undefined]) {
        const selected = [...args];
        selected.splice(selected.indexOf('--limit'), 2, ...(limit ? ['--limit', limit] : []));
        await saved(bytes, selected);
      }
      await fail([...args, '--max-bytes', '10', '--result-file', destination], 'RESPONSE_LIMIT');
      assert.deepEqual(await readFile(destination), bytes);
    }
  } else {
    respond({ ...row.response, vendorExtension: 'future metadata', ...(row.operation === 'OP-078' ? {} : {
      response: { ...row.response.response, vendorExtension: 'future metadata' },
    }) });
    const value = await success([...args, '--full']);
    trace();
    if (row.operation === 'OP-075') {
      respond(row.response);
      const bytes = Buffer.from(JSON.stringify(row.response));
      const output = await saved(bytes);
      assert.equal(output.response, undefined);
      assert.ok(!JSON.stringify(output).includes('SYNTHETIC-opaque-canary'));
      respond({ status: 'ok', response: { config: null } });
      await saved(Buffer.from('{"status":"ok","response":{"config":null}}'));
      respond({ status: 'ok', response: { config: {} } });
      await fail(args, 'UPSTREAM_INVALID');
    } else {
      assert.deepEqual(value.response, row.ordinaryResponse);
      assert.deepEqual((await success([...args, '--full'], false)).response, row.ordinaryResponse);
    }
    if (row.operation === 'OP-079') {
      respond(row.response);
      const output = await saved(Buffer.from(JSON.stringify(row.response)));
      for (const canary of ['SYNTHETIC-proxy-canary', 'SYNTHETIC-tsig-canary']) assert.ok(!JSON.stringify(output).includes(canary));
    }
    if (row.operation === 'OP-015') {
      respond({ status: 'ok', response: { uptimestamp: '2024-01-01T00:00:00Z', uptimeSeconds: 9 } });
      await fail(args, 'UPSTREAM_INVALID');
      respond({ status: 'ok', response: { ...row.response.response, uptimeSeconds: 0, lifetimeCounters: { totalQueries: 0, totalBlocked: 0 } } });
      assert.deepEqual((await success(args)).response, { ...row.response.response, uptimeSeconds: 0, lifetimeCounters: { totalQueries: 0, totalBlocked: 0 } });
    }
    if (row.operation === 'OP-018') {
      respond({ status: 'ok', response: { topClients: scenario.unfiltered } });
      assert.deepEqual((await success(['dashboard', 'stats', 'get-top', '--stats-type', 'TopClients', '--full'])).response.topClients, scenario.unfiltered);
    }
    if (row.operation === 'OP-053') {
      vendors.responders.set(row.path, (_request, body) => ({ body: { status: 'ok', response:
        new URLSearchParams(body.toString()).get('direction') === 'up' ? scenario.up : row.response.response } }));
      const up = [...args];
      up[up.indexOf('--direction') + 1] = 'up';
      assert.deepEqual((await success(up)).response, scenario.up);
    }
    if (row.operation === 'OP-081') {
      respond({ status: 'ok', response: { tsigKeyNames: [] } });
      const empty = await success(args);
      assert.deepEqual(empty.response.tsigKeyNames, []);
      assert.equal(empty.output.complete, true);
    }
    if (row.operation === 'OP-138') {
      const entries = Array.from({ length: 13 }, (_, index) => ({ rowNumber: 13 - index, timestamp: `2024-01-01T00:00:${String(13 - index).padStart(2, '0')}Z`,
        qname: 'www.example.test', qtype: 'A', qclass: 'IN', clientIpAddress: '192.0.2.10', rcode: 'NoError', answer: `192.0.2.${13 - index}` }));
      vendors.responders.set(row.path, (_request, body) => {
        const requested = new URLSearchParams(body.toString());
        const page = Number(requested.get('pageNumber'));
        requested.set('pageNumber', '1');
        assert.equal(requested.toString(), form.toString());
        return { body: { status: 'ok', response: { pageNumber: page, totalPages: 2, totalEntries: 13, entries: entries.slice((page - 1) * 10, page * 10) } } };
      });
      const first = await success(args);
      assert.deepEqual([first.response.pageNumber, first.response.totalPages, first.response.totalEntries], [1, 2, 13]);
      assert.equal(first.output.complete, false);
      assert.equal(first.output.nextPage, 2);
      const full = await success([...args, '--full']);
      assert.deepEqual(full.response.entries, entries);
      assert.equal(full.output.complete, true);
      const bounded = await success([...args, '--full', '--max-pages', '1']);
      assert.equal(bounded.output.complete, false);
      assert.equal(bounded.output.nextPage, 2);
    }
    respond(row.operation === 'OP-078' ? { status: 'error' } : { status: 'ok', response: {} });
    await fail(args, row.operation === 'OP-078' ? 'UPSTREAM_ERROR' : 'UPSTREAM_INVALID');
    if (row.operation === 'OP-078') {
      vendors.responders.set(row.path, () => ({ status: 403, body: {} }));
      await fail(args, 'PERMISSION_DENIED');
    }
  }
  return [`${row.operation}:accepted-read-and-failure`];
}
