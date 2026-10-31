import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const secret = 'samaritan-smoke-test-secret-0123456789abcdef';

async function freePort() {
  const server = createServer();
  await new Promise((ok, fail) => server.once('error', fail).listen(0, '127.0.0.1', ok));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Could not allocate a test port.');
  await new Promise((ok, fail) => server.close(err => err ? fail(err) : ok()));
  return address.port;
}

async function startServer(key) {
  const port = await freePort();
  const child = spawn(process.execPath, [resolve(root, 'scanner/server.js')], {
    cwd: root,
    env: { ...process.env, SCANNER_PORT: String(port), SCANNER_HOST: '127.0.0.1', SCANNER_KEY: key },
    stdio: 'ignore',
  });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 50; i++) {
    if (child.exitCode !== null) throw new Error(`Scanner exited early (${child.exitCode}).`);
    try {
      const response = await fetch(`${base}/health`, { signal: AbortSignal.timeout(300) });
      if (response.ok) return { child, base };
    } catch { /* wait for the listening socket */ }
    await delay(100);
  }
  child.kill('SIGKILL');
  throw new Error('Scanner did not become healthy within five seconds.');
}

async function stopServer(child) {
  child.kill('SIGTERM');
  await Promise.race([new Promise(resolveExit => child.once('exit', resolveExit)), delay(1500)]);
  if (child.exitCode === null) child.kill('SIGKILL');
}

// A syntactically present but weak shared key must not authorize requests.
const weak = await startServer('short');
try {
  const rejected = await fetch(`${weak.base}/scan/quick?target=example.com`, { headers: { 'x-scanner-key': 'short' } });
  assert.equal(rejected.status, 401, 'short placeholder secrets must not authorize the scanner');
} finally {
  await stopServer(weak.child);
}

const { child, base } = await startServer(secret);
try {
  const health = await fetch(`${base}/health`).then(r => r.json());
  assert.equal(health.ok, true);
  assert.equal(health.service, 'samaritan-scanner');
  assert.ok(Array.isArray(health.scans) && health.scans.includes('quick'));

  const unauthorized = await fetch(`${base}/scan/quick?target=example.com`);
  assert.equal(unauthorized.status, 401, 'scan endpoint must require the shared secret');

  const badKey = await fetch(`${base}/scan/quick?target=example.com`, { headers: { 'x-scanner-key': 'wrong-secret' } });
  assert.equal(badKey.status, 401, 'incorrect secrets must be rejected');

  const privateTarget = await fetch(`${base}/scan/quick?target=127.0.0.1`, { headers: { 'x-scanner-key': secret } });
  assert.equal(privateTarget.status, 400, 'private IP targets must be rejected before any outbound request');
  assert.match((await privateTarget.json()).error, /private|reserved|global/i);

  const localHostname = await fetch(`${base}/scan/quick?target=localhost`, { headers: { 'x-scanner-key': secret } });
  assert.equal(localHostname.status, 400, 'localhost must be rejected');

  const unsupported = await fetch(`${base}/scan/not-a-scan?target=example.com`, { headers: { 'x-scanner-key': secret } });
  assert.equal(unsupported.status, 404, 'unknown scan operations must not be dispatched');

  console.log('Samaritan scanner smoke tests passed (health, auth, private-target block, route allowlist).');
} finally {
  await stopServer(child);
}
