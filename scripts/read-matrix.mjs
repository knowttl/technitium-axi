import { readFile, writeFile } from 'node:fs/promises';
import { readContracts } from '../dist/read-contracts.js';

const seeds = JSON.parse(await readFile(new URL('../tests/fixtures/read-seeds.json', import.meta.url), 'utf8')).responses;
const ordinary = value => Array.isArray(value) ? value.map(ordinary) : value && typeof value === 'object'
  ? Object.fromEntries(Object.entries(value).filter(([key]) => !/password|secret|^token$/i.test(key)).map(([key, field]) => [key, ordinary(field)])) : value;
const input = parameter => parameter.values?.[0] ?? (parameter.type === 'boolean' ? 'true'
  : parameter.name === 'pageNumber' ? '1' : parameter.type === 'integer' ? '2' : parameter.type === 'http-date' ? 'Mon, 01 Jan 2024 00:00:00 GMT'
    : parameter.type === 'date' ? '2024-01-01T00:00:00Z' : parameter.type === 'zone-list' ? 'alpha.example.test,beta.example.test'
      : ['zone', 'domain', 'node', 'qname'].includes(parameter.name) ? 'alpha.example.test' : `Synthetic${parameter.name}`);
const matrix = {
  provenance: { status: 'synthetic-source-reviewed',
    source: 'https://github.com/TechnitiumSoftware/DnsServer/blob/0dd592aad21eced4221a9a46204cb1a299972ca0/APIDOCS.md',
    revision: '0dd592aad21eced4221a9a46204cb1a299972ca0',
    requests: 'POST form with profile bearer header; these fixtures are synthetic, not live observations' },
  operations: readContracts.filter(contract => !['OP-001', 'OP-006'].includes(contract.id)).map(contract => {
    const response = structuredClone(seeds[contract.id] ?? {});
    if (contract.id === 'OP-018') { delete response.topDomains; delete response.topBlockedDomains; }
    if (['OP-020', 'OP-138'].includes(contract.id)) {
      const key = contract.id === 'OP-020' ? 'zones' : 'entries';
      response[key] = response[key].slice(0, 2);
      response.pageNumber = 1; response.totalPages = 1;
      response[contract.id === 'OP-020' ? 'totalZones' : 'totalEntries'] = response[key].length;
    }
    if (contract.id === 'OP-075') response.config = '{"oddKey":"SYNTHETIC-opaque-canary"}';
    if (contract.id === 'OP-079') {
      response.proxy = { type: 'Http', address: 'proxy.example.test', port: 8080, username: 'synthetic', password: 'SYNTHETIC-proxy-canary' };
      response.tsigKeys = [{ keyName: 'synthetic', algorithmName: 'hmac-sha256', sharedSecret: 'SYNTHETIC-tsig-canary' }];
    }
    const ordinaryResponse = ordinary(response);
    return { operation: contract.id, command: contract.command, path: contract.path, kind: contract.kind,
      parameters: contract.parameters.map(parameter => ({ ...parameter, requested: input(parameter),
        invalid: parameter.type === 'boolean' ? 'yes' : parameter.type === 'integer' ? '-1'
          : parameter.type === 'date' || parameter.type === 'http-date' ? 'yesterday' : parameter.values ? 'not-an-option' : null })),
      response: contract.id === 'OP-078' ? { status: 'ok', server: 'SYNTHETIC-server' } : { status: 'ok', response },
      ordinaryResponse: contract.id === 'OP-078' ? { status: 'ok', server: 'SYNTHETIC-server' } : ordinaryResponse,
    };
  }),
};
const path = new URL('../tests/fixtures/read-matrix.json', import.meta.url);
const content = JSON.stringify(matrix, null, 2) + '\n';
if (process.argv.includes('--check')) {
  if (await readFile(path, 'utf8') !== content) throw new Error('Read matrix is stale; run npm run build');
} else await writeFile(path, content);
