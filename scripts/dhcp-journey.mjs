import assert from 'node:assert/strict';
import { readFile, writeFile, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import seeds from '../tests/fixtures/read-seeds.json' with { type: 'json' };
import matrix from '../tests/fixtures/configuration-matrix.json' with { type: 'json' };

// Synthetic worlds follow WebServiceDhcpApi and Scope at the pinned vendor revision.
const operations = [
  ['087', 'lease remove', 'leases/remove'],
  ['088', 'lease convert-to-reserved', 'leases/convertToReserved'],
  ['089', 'lease convert-to-dynamic', 'leases/convertToDynamic'],
  ['092', 'scope set', 'scopes/set'],
  ['093', 'scope add-reserved-lease', 'scopes/addReservedLease'],
  ['094', 'scope remove-reserved-lease', 'scopes/removeReservedLease'],
  ['095', 'scope enable', 'scopes/enable'],
  ['096', 'scope disable', 'scopes/disable'],
  ['097', 'scope delete', 'scopes/delete'],
];
export const dhcpTasks = ['B4.dhcp', ...operations.map(([id]) => `B4.OP-${id}`)];
const mac = '00-11-22-33-44-55';
const reservation = { hostName: null, hardwareAddress: mac, address: '192.0.2.20', comments: null };
const decoy = { hostName: 'keep', hardwareAddress: '00-11-22-33-44-66', address: '192.0.2.21', comments: 'keep' };
const normalizeMac = value => value.replace(/:/g, '-').toUpperCase();

export async function dhcpJourney({ task, directory, env, run, executable, vendors, config, token, configure, success, failure, execute }) {
  const read = async (command, flags = []) => {
    const result = await run(executable, [...command.split(' '), ...flags, '--full', '--config', config, '--json'], { env: { ...env, WRITE_TOKEN: token } });
    assert.equal(result.code, 0, result.stdout);
    return JSON.parse(result.stdout).response;
  };
  for (const [id, action, endpoint] of operations.filter(([id]) => task === 'B4.dhcp' || task === `B4.OP-${id}`)) {
    await configure([`OP-${id}`]);
    const command = `dhcp ${action}`;
    let scopes;
    let leases;
    let drop = false;
    const scopeFile = join(directory, 'lab.scope');
    const reset = async () => {
      scopes = [
        { ...structuredClone(seeds.responses['OP-091']), name: 'lab', enabled: id === '096', startingAddress: '192.0.2.10', endingAddress: '192.0.2.100',
          subnetMask: '255.255.255.0', networkAddress: '192.0.2.0', broadcastAddress: '192.0.2.255', pingCheckEnabled: true,
          reservedLeases: [structuredClone(decoy)], exclusions: [{ startingAddress: '192.0.2.90', endingAddress: '192.0.2.95' }] },
        { name: 'keep', enabled: id === '096', startingAddress: '198.51.100.10', endingAddress: '198.51.100.100', subnetMask: '255.255.255.0',
          networkAddress: '198.51.100.0', broadcastAddress: '198.51.100.255', reservedLeases: [], genericOptions: [] },
      ];
      leases = [
        { scope: 'lab', type: ['089', '094'].includes(id) ? 'Reserved' : 'Dynamic', hardwareAddress: mac, clientIdentifier: '1-001122334455',
          address: '192.0.2.20', hostName: 'workstation', leaseObtained: '2024-01-01T00:00:00Z', leaseExpires: '2024-01-08T00:00:00Z' },
        { scope: 'keep', type: 'Dynamic', hardwareAddress: decoy.hardwareAddress, clientIdentifier: '1-001122334466',
          address: '198.51.100.20', hostName: 'keep', leaseObtained: '2024-01-01T00:00:00Z', leaseExpires: '2024-01-08T00:00:00Z' },
      ];
      if (['089', '094'].includes(id)) scopes[0].reservedLeases.unshift(structuredClone(reservation));
      await writeFile(scopeFile, JSON.stringify(scopes[0]), { mode: 0o600 });
    };
    await reset();
    vendors.responders.set('/api/dhcp/scopes/list', () => ({ body: { status: 'ok', response: { scopes } } }));
    vendors.responders.set('/api/dhcp/leases/list', () => ({ body: { status: 'ok', response: { leases } } }));
    vendors.responders.set('/api/dhcp/scopes/get', (_incoming, bytes) => {
      const name = new URLSearchParams(bytes.toString()).get('name');
      const scope = scopes.find(row => row.name === name);
      return { body: scope ? { status: 'ok', response: scope } : { status: 'error', errorMessage: 'DHCP scope was not found' } };
    });
    let expectedWire;
    vendors.responders.set(`/api/dhcp/${endpoint}`, async (incoming, bytes) => {
      assert.equal(incoming.headers.authorization, `Bearer ${token}`);
      const p = Object.fromEntries(new URLSearchParams(bytes.toString()));
      assert.deepEqual(p, expectedWire, 'Exact vendor form must retain false, zero and row ordering');
      let scope = scopes.find(row => row.name === p.name);
      const denied = () => ({ body: { status: 'error', errorMessage: 'Selected scope or lease was not found' } });
      // The vendor scope setter creates a scope that does not exist yet.
      if (!scope && id === '092') {
        scope = { name: p.name, enabled: true, networkAddress: '203.0.113.0', broadcastAddress: '203.0.113.255', reservedLeases: [], genericOptions: [] };
        scopes.push(scope);
      }
      if (!scope) return denied();
      if (action.startsWith('lease ')) {
        const index = leases.findIndex(row => row.scope === p.name && (p.clientIdentifier ? row.clientIdentifier === p.clientIdentifier : row.hardwareAddress === normalizeMac(p.hardwareAddress)));
        if (index < 0) return denied();
        const lease = leases[index];
        if (id === '087') leases.splice(index, 1);
        else if (id === '088') {
          if (lease.type !== 'Dynamic') return denied();
          lease.type = 'Reserved';
          scope.reservedLeases.push(structuredClone(reservation));
        } else {
          if (lease.type !== 'Reserved') return denied();
          lease.type = 'Dynamic';
          scope.reservedLeases = scope.reservedLeases.filter(row => row.hardwareAddress !== lease.hardwareAddress);
        }
      } else if (id === '092') {
        for (const [key, raw] of Object.entries(p).filter(([key]) => !['name', 'newName'].includes(key))) {
          const field = matrix.dhcp[key];
          let value = raw;
          if (field.type === 'boolean') value = raw === 'true';
          else if (field.type === 'integer') value = Number(raw);
          else if (field.type === 'list') value = raw ? raw.split(',') : undefined;
          else if (field.type === 'rows') {
            const cells = raw ? raw.split('|') : [];
            value = [];
            for (let i = 0; i < cells.length; i += field.columns.length) value.push(Object.fromEntries(field.columns.map((column, j) => [column,
              column === 'code' ? Number(cells[i + j]) : column === 'hardwareAddress' ? normalizeMac(cells[i + j]) : cells[i + j]])));
            if (['genericOptions', 'vendorInfo'].includes(key)) value = value.map(row => {
              const column = key === 'genericOptions' ? 'value' : 'information';
              return { ...row, [column]: row[column].replace(/:/g, '').toUpperCase().match(/../g).join(':') };
            });
            if (!value.length && key !== 'reservedLeases') value = undefined;
          }
          if (value === undefined || value === '' && ['domainName', 'serverAddress', 'serverHostName', 'bootFileName', 'routerAddress'].includes(key)) delete scope[key];
          else scope[key] = value;
        }
        if (p.newName) { scope.name = p.newName; for (const lease of leases.filter(row => row.scope === p.name)) lease.scope = p.newName; }
      } else if (id === '093') {
        if (scope.reservedLeases.some(row => row.hardwareAddress === normalizeMac(p.hardwareAddress))) return denied();
        scope.reservedLeases.push({ hardwareAddress: normalizeMac(p.hardwareAddress), address: p.ipAddress, hostName: p.hostName ?? null, comments: p.comments ?? null });
      } else if (id === '094') scope.reservedLeases = scope.reservedLeases.filter(row => row.hardwareAddress !== normalizeMac(p.hardwareAddress));
      else if (id === '095' || id === '096') scope.enabled = id === '095';
      else { scopes = scopes.filter(row => row !== scope); leases = leases.filter(row => row.scope !== p.name); await rm(scopeFile); }
      if (id !== '097') {
        scope.reservedLeases.sort((a, b) => a.address.localeCompare(b.address, 'en', { numeric: true }));
        await writeFile(scopeFile, JSON.stringify(scope));
      }
      if (drop) { incoming.socket.destroy(); return {}; }
      return { body: { status: 'ok', response: {} } };
    });
    const beforeScopes = structuredClone(scopes);
    const beforeLeases = structuredClone(leases);
    const parameters = { name: 'lab', ...(id < '090' ? { clientIdentifier: '1-001122334455' }
      : id === '092' ? { newName: 'lab-new', leaseTimeDays: 1, leaseTimeHours: 2, leaseTimeMinutes: 0, pingCheckEnabled: false,
        genericOptions: [{ code: 150, value: 'c0000214' }], staticRoutes: [{ destination: '198.51.100.0', subnetMask: '255.255.255.0', router: '192.0.2.1' }] }
        : id === '093' ? { hardwareAddress: mac, ipAddress: '192.0.2.20', hostName: 'workstation', comments: 'owned' }
          : id === '094' ? { hardwareAddress: mac } : {}) };
    const input = { parameters, ...(id === '092' ? { baseline: { newName: 'lab', leaseTimeDays: 7, leaseTimeHours: 0, leaseTimeMinutes: 0,
      pingCheckEnabled: true, genericOptions: beforeScopes[0].genericOptions, staticRoutes: beforeScopes[0].staticRoutes } } : {}) };
    expectedWire = Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, key === 'genericOptions' ? '150|c0000214'
      : key === 'staticRoutes' ? '198.51.100.0|255.255.255.0|192.0.2.1' : String(value)]));
    const preview = await success(command, input);
    await failure('CONFIRMATION_MISMATCH', command, { ...input, parameters: { ...parameters, name: 'keep' } }, ['--execute', '--confirm', preview.preview.digest]);
    await success(command, input, ['--execute', '--confirm', preview.preview.digest]);
    const selectedName = id === '092' ? 'lab-new' : 'lab';
    const expectedScopes = structuredClone(beforeScopes);
    const expectedLeases = structuredClone(beforeLeases);
    if (id === '087') expectedLeases.shift();
    if (id === '088') { expectedLeases[0].type = 'Reserved'; expectedScopes[0].reservedLeases.unshift(reservation); }
    if (id === '089') { expectedLeases[0].type = 'Dynamic'; expectedScopes[0].reservedLeases.shift(); }
    if (id === '092') {
      const { name, newName, ...patch } = parameters;
      Object.assign(expectedScopes[0], patch, { name: newName, genericOptions: [{ code: 150, value: 'C0:00:02:14' }] });
      expectedLeases[0].scope = newName;
    }
    if (id === '093') expectedScopes[0].reservedLeases.unshift({ ...reservation, hostName: 'workstation', comments: 'owned' });
    if (id === '094') expectedScopes[0].reservedLeases.shift();
    if (['095', '096'].includes(id)) expectedScopes[0].enabled = id === '095';
    if (id === '097') { expectedScopes.shift(); expectedLeases.shift(); await assert.rejects(stat(scopeFile), { code: 'ENOENT' }); }
    assert.deepEqual((await read('dhcp scope list')).scopes, expectedScopes.map(({ name, enabled, startingAddress, endingAddress, subnetMask, networkAddress, broadcastAddress }) => ({ name, enabled, startingAddress, endingAddress, subnetMask, networkAddress, broadcastAddress })));
    assert.deepEqual((await read('dhcp lease list')).leases, expectedLeases);
    const { enabled: keepEnabled, networkAddress: keepNetwork, broadcastAddress: keepBroadcast, ...keepDetails } = expectedScopes.at(-1);
    assert.deepEqual(await read('dhcp scope get', ['--name', 'keep']), keepDetails);
    if (id !== '097') {
      const { enabled, networkAddress, broadcastAddress, ...details } = expectedScopes[0];
      assert.deepEqual(await read('dhcp scope get', ['--name', selectedName]), details);
      assert.deepEqual(JSON.parse(await readFile(scopeFile)), expectedScopes[0]);
    }
    if (id < '090') {
      await reset();
      const hardware = { parameters: { name: 'lab', hardwareAddress: mac } };
      expectedWire = hardware.parameters;
      await execute(command, hardware);
      assert.deepEqual((await read('dhcp lease list')).leases, expectedLeases);
      const count = vendors.traces.length;
      for (const selector of [{}, { clientIdentifier: '1-001122334455', hardwareAddress: mac }]) await failure('USAGE', command, { parameters: { name: 'lab', ...selector } });
      assert.equal(vendors.traces.length, count);
    } else if (id === '092') {
      await reset();
      const stale = await success(command, input);
      scopes[0].leaseTimeDays = 3;
      await failure('CONFLICT', command, input, ['--execute', '--confirm', stale.preview.digest]);
      assert.equal(scopes[0].name, 'lab');
      scopes[0].leaseTimeDays = 7;
      expectedWire = Object.fromEntries(Object.entries(parameters).map(([key, value]) => [key, key === 'genericOptions' ? '150|c0000214' : key === 'staticRoutes' ? '198.51.100.0|255.255.255.0|192.0.2.1' : String(value)]));
      drop = true;
      const unknown = await failure('OUTCOME_UNKNOWN', command, input, ['--execute', '--confirm', stale.preview.digest]);
      const auditId = unknown.error.message.match(/audit ID ([a-f0-9-]+)/)[1];
      const reconciled = await success(command, input, ['--confirm', stale.preview.digest, '--reconcile', auditId]);
      assert.equal(reconciled.status, 'reconciled');
      assert.equal(reconciled.auditId, auditId);
      drop = false;
      await reset();
      const changes = { startingAddress: '192.0.2.11', endingAddress: '192.0.2.99', subnetMask: '255.255.255.0', offerDelayTime: 1,
        pingCheckTimeout: 500, pingCheckRetries: 1, domainName: 'example.test', domainSearchList: ['example.test'], dnsUpdates: false,
        dnsOverwriteForDynamicLease: true, dnsTtl: 300, serverAddress: '192.0.2.2', serverHostName: 'boot', bootFileName: 'boot.img',
        routerAddress: '192.0.2.1', useThisDnsServer: false, dnsServers: ['192.0.2.2'], winsServers: [], ntpServers: ['192.0.2.3'],
        ntpServerDomainNames: ['time.example.test'], vendorInfo: [{ identifier: 'PXEClient', information: '0102' }],
        capwapAcIpAddresses: [], tftpServerAddresses: ['192.0.2.4'], exclusions: [], reservedLeases: [],
        allowOnlyReservedLeases: true, blockLocallyAdministeredMacAddresses: false, ignoreClientIdentifierOption: false };
      const baseline = Object.fromEntries(Object.keys(changes).map(key => [key, scopes[0][key] ?? []]));
      const expected = { ...structuredClone(scopes[0]), ...changes, vendorInfo: [{ identifier: 'PXEClient', information: '01:02' }] };
      delete expected.winsServers;
      delete expected.capwapAcIpAddresses;
      delete expected.exclusions;
      expectedWire = { name: 'lab', ...Object.fromEntries(Object.entries(changes).map(([key, value]) => [key,
        key === 'vendorInfo' ? 'PXEClient|0102' : Array.isArray(value) ? value.join(',') : String(value)])) };
      await execute(command, { parameters: { name: 'lab', ...changes }, baseline });
      const { enabled, networkAddress, broadcastAddress, ...details } = expected;
      assert.deepEqual(await read('dhcp scope get', ['--name', 'lab']), details);
      const count = vendors.traces.length;
      for (const [field, value] of [['leaseTimeHours', 24], ['leaseTimeMinutes', 60]]) {
        await failure('USAGE', command, { parameters: { name: 'lab', leaseTimeDays: 1, [field]: value },
          baseline: { leaseTimeDays: 7, [field]: 0 } });
      }
      assert.equal(vendors.traces.length, count, 'Invalid lease time must fail before partially changing the scope');
      assert.deepEqual(JSON.parse(await readFile(scopeFile)), expected);
      const empty = { parameters: { name: 'lab', domainName: '', serverAddress: '', dnsServers: [], vendorInfo: [] },
        baseline: { domainName: 'example.test', serverAddress: '192.0.2.2', dnsServers: ['192.0.2.2'], vendorInfo: changes.vendorInfo } };
      expectedWire = { name: 'lab', domainName: '', serverAddress: '', dnsServers: '', vendorInfo: '' };
      await execute(command, empty);
      delete details.domainName;
      delete details.serverAddress;
      delete details.dnsServers;
      delete details.vendorInfo;
      assert.deepEqual(await read('dhcp scope get', ['--name', 'lab']), details);
      const selected = { hostName: 'workstation', hardwareAddress: '00:11:22:33:44:55', address: '192.0.2.20', comments: 'owned' };
      expectedWire = { name: 'lab', reservedLeases: 'keep|00-11-22-33-44-66|192.0.2.21|keep|workstation|00:11:22:33:44:55|192.0.2.20|owned' };
      await execute(command, { parameters: { name: 'lab', reservedLeases: [decoy, selected] }, baseline: { reservedLeases: [] } });
      details.reservedLeases = [{ ...selected, hardwareAddress: mac }, decoy];
      assert.deepEqual(await read('dhcp scope get', ['--name', 'lab']), details);
      // Without a baseline the setter creates the scope, and the preview says so.
      const fresh = { parameters: { name: 'fresh', startingAddress: '203.0.113.10', endingAddress: '203.0.113.50', subnetMask: '255.255.255.0', domainName: 'fresh.test', dnsUpdates: true } };
      expectedWire = Object.fromEntries(Object.entries(fresh.parameters).map(([key, value]) => [key, String(value)]));
      const freshPreview = await success(command, fresh);
      assert.deepEqual(freshPreview.preview.replaces, []);
      assert.deepEqual(freshPreview.preview.sideEffects, ['Creates a new DHCP scope', 'May create the forward and reverse DNS zones for the scope domain name when DNS updates are enabled']);
      await success(command, fresh, ['--execute', '--confirm', freshPreview.preview.digest]);
      assert.deepEqual(await read('dhcp scope get', ['--name', 'fresh']), { name: 'fresh', ...fresh.parameters, reservedLeases: [], genericOptions: [] });
      const duplicate = { parameters: { ...fresh.parameters, name: 'lab' } };
      await failure('CONFLICT', command, duplicate, ['--execute', '--confirm', (await success(command, duplicate)).preview.digest]);
      await failure('USAGE', command, { parameters: { name: 'fresh-incomplete', dnsUpdates: true } });
      const absent = { parameters: { name: 'absent', leaseTimeDays: 1 }, baseline: { leaseTimeDays: 7 } };
      const absentError = await failure('UPSTREAM_ERROR', command, absent, ['--execute', '--confirm', (await success(command, absent)).preview.digest]);
      assert.match(absentError.help[0], /omit the baseline/);
      assert.ok(!scopes.some(row => row.name === 'absent'));
    } else if (id === '093') {
      await failure('CONFLICT', command, { parameters: { name: 'lab', hardwareAddress: '00-11-22-33-44-77', ipAddress: '192.0.2.21' } },
        ['--execute', '--confirm', (await success(command, { parameters: { name: 'lab', hardwareAddress: '00-11-22-33-44-77', ipAddress: '192.0.2.21' } })).preview.digest]);
      assert.deepEqual((await read('dhcp scope get', ['--name', 'lab'])).reservedLeases, expectedScopes[0].reservedLeases);
    } else {
      const missing = { parameters: { ...parameters, name: 'absent' } };
      expectedWire = Object.fromEntries(Object.entries(missing.parameters).map(([key, value]) => [key, String(value)]));
      const preview = await success(command, missing);
      await failure('UPSTREAM_ERROR', command, missing, ['--execute', '--confirm', preview.preview.digest]);
      assert.deepEqual(scopes, expectedScopes);
    }
  }
}
