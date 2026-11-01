import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, readFile } from 'node:fs/promises';
import { createServer, request } from 'node:https';
import { connect } from 'node:net';
import { join } from 'node:path';

export async function fakeVendors(temporary, run, env) {
  const key = join(temporary, 'vendor-key.pem');
  const cert = join(temporary, 'vendor-ca.pem');
  const generated = await run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-keyout', key, '-out', cert, '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { env });
  assert.equal(generated.code, 0, generated.stderr);
  await chmod(cert, 0o600);
  const tls = { key: await readFile(key), cert: await readFile(cert) };
  const traces = [];
  const tokens = new Map();
  const tokenKinds = new Map();
  const faults = new Map();
  const responders = new Map();
  const servers = [];
  try {
    for (const identity of ['alpha', 'beta']) {
      const server = createServer(tls, async (incoming, outgoing) => {
        const chunks = [];
        for await (const chunk of incoming) chunks.push(chunk);
        const body = Buffer.concat(chunks);
        const bearer = incoming.headers.authorization?.replace(/^Bearer /, '');
        traces.push({ method: incoming.method, path: incoming.url.split('?')[0],
          headers: { 'content-type': incoming.headers['content-type'] ?? null,
            ...(incoming.headers['if-modified-since'] ? { 'if-modified-since': incoming.headers['if-modified-since'] } : {}) },
          inputHash: createHash('sha256').update(body).digest('hex'),
          bearerHash: bearer ? createHash('sha256').update(bearer).digest('hex') : null, identity });
        const responder = responders.get(incoming.url) ?? responders.get(new URL(incoming.url, 'https://fixture.test').pathname);
        if (responder) {
          const response = bearer !== tokens.get(identity) ? { body: { status: 'invalid-token' } } : await responder(incoming, body);
          if (incoming.destroyed) return;
          outgoing.writeHead(response.status ?? 200, { 'content-type': response.contentType ?? 'application/json', ...response.headers });
          outgoing.end(response.bytes ?? JSON.stringify(response.body));
          return;
        }
        outgoing.writeHead(200, { 'content-type': 'application/json' });
        if (incoming.url === '/api/status') {
          outgoing.end(JSON.stringify({ status: 'ok', server: `dns-${identity}.example.test`, hasDefaultCredentials: false, ssoEnabled: false }));
        } else if (incoming.url === '/api/user/session/get') {
          const token = tokens.get(identity);
          outgoing.end(JSON.stringify(bearer !== token || incoming.method !== 'POST' || body.toString() !== 'includeInfo=true'
            ? { status: 'invalid-token' }
            : { status: 'ok', username: 'planner',
              ...((tokenKinds.get(identity) ?? 'api') === 'api' ? { tokenName: 'automation-1' } : {}), token,
              unknownConfidential: token, escaped: encodeURIComponent(token), hasDnssecPrivateKeys: false,
              info: { version: '15.4', permissions: { Administration: { canModify: faults.get(identity) ?? false } } } }));
        } else outgoing.end(JSON.stringify({ status: 'ok', fixtureIdentity: identity }));
      });
      servers.push(server);
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    }
    return {
      traces,
      tokens, tokenKinds, faults, responders, caFile: cert,
      origins: servers.map(server => `https://127.0.0.1:${server.address().port}`),
      async check() {
        for (const [index, server] of servers.entries()) {
          const response = await new Promise((resolve, reject) => {
            const call = request({ hostname: '127.0.0.1', port: server.address().port, path: '/harness-probe', ca: tls.cert }, incoming => {
              let body = '';
              incoming.on('data', chunk => { body += chunk; });
              incoming.once('end', () => resolve(JSON.parse(body)));
            });
            call.once('error', reject);
            call.end();
          });
          assert.deepEqual(response, { status: 'ok', fixtureIdentity: ['alpha', 'beta'][index] });
        }
        assert.deepEqual(traces.map(trace => ({ method: trace.method, path: trace.path, identity: trace.identity })), [
          { method: 'GET', path: '/harness-probe', identity: 'alpha' },
          { method: 'GET', path: '/harness-probe', identity: 'beta' },
        ]);
        await new Promise((resolve, reject) => {
          const socket = connect({ host: '192.0.2.1', port: 443 });
          socket.once('connect', () => { socket.destroy(); reject(new Error('Non-loopback egress succeeded')); });
          socket.once('error', error => {
            try { assert.ok(['ENETUNREACH', 'EHOSTUNREACH'].includes(error.code)); resolve(); }
            catch (failure) { reject(failure); }
          });
        });
      },
      async close() {
        await Promise.all(servers.map(server => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); })));
      },
    };
  } catch (error) {
    await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
    throw error;
  }
}
