const assert = require('node:assert/strict');
const { mkdtemp, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawn } = require('node:child_process');
const { test } = require('node:test');

async function startServer() {
  const directory = await mkdtemp(join(tmpdir(), 'smart-accountant-license-'));
  const port = 3500 + Math.floor(Math.random() * 300);
  const child = spawn(process.execPath, ['server.js'], {
    cwd: __dirname,
    env: {
      ...process.env,
      PORT: String(port),
      DB_PATH: join(directory, 'licenses.db'),
      NODE_ENV: 'production',
      ADMIN_SECRET: 'test-admin-secret',
    },
    stdio: 'ignore',
  });
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) return { child, port, directory };
    } catch (_) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
  child.kill();
  throw new Error('License backend did not start');
}

async function stopServer(server) {
  await new Promise((resolve) => {
    if (server.child.exitCode !== null) return resolve();
    server.child.once('exit', resolve);
    server.child.kill();
  });
  await rm(server.directory, { recursive: true, force: true });
}

async function request(server, path, options = {}) {
  const response = await fetch(`http://127.0.0.1:${server.port}${path}`, options);
  return { status: response.status, data: await response.json() };
}

function jsonBody(value) {
  return { headers: { 'content-type': 'application/json' }, body: JSON.stringify(value) };
}

test('generates device-bound licenses and enforces admin authorization', async () => {
  const server = await startServer();
  try {
    const unauthorized = await request(server, '/generate', {
      method: 'POST',
      ...jsonBody({ device_id: 'phone-1' }),
    });
    assert.equal(unauthorized.status, 401);

    const headers = { 'x-admin-secret': 'test-admin-secret' };
    const generated = await request(server, '/generate', {
      method: 'POST',
      headers: { ...headers, 'content-type': 'application/json' },
      body: JSON.stringify({
        device_id: 'phone-1',
        client_name: 'عميل الاختبار',
        allow_multiple_users: false,
      }),
    });
    assert.equal(generated.status, 200);
    assert.ok(generated.data.key, JSON.stringify(generated.data));
    assert.equal(generated.data.allow_multiple_users, false);

    const wrongDevice = await request(server, '/verify', {
      method: 'POST',
      ...jsonBody({ key: generated.data.key, device_id: 'phone-2' }),
    });
    assert.equal(wrongDevice.data.valid, false);

    const verified = await request(server, '/verify', {
      method: 'POST',
      ...jsonBody({ key: generated.data.key, device_id: 'phone-1', user_id: 'user-1' }),
    });
    assert.equal(verified.data.valid, true, JSON.stringify(verified.data));

    const otherUser = await request(server, '/verify', {
      method: 'POST',
      ...jsonBody({ key: generated.data.key, device_id: 'phone-1', user_id: 'user-2' }),
    });
    assert.equal(otherUser.data.valid, false);
    assert.match(otherUser.data.message, /مستخدم واحد/);
  } finally {
    await stopServer(server);
  }
});

test('multi-user licenses accept multiple users on the bound device', async () => {
  const server = await startServer();
  try {
    const headers = { 'x-admin-secret': 'test-admin-secret', 'content-type': 'application/json' };
    const generated = await request(server, '/generate', {
      method: 'POST',
      headers,
      body: JSON.stringify({ device_id: 'phone-multi', allow_multiple_users: true }),
    });
    assert.ok(generated.data.key, JSON.stringify(generated.data));
    const first = await request(server, '/verify', {
      method: 'POST',
      ...jsonBody({ key: generated.data.key, device_id: 'phone-multi', user_id: 'user-1' }),
    });
    const second = await request(server, '/verify', {
      method: 'POST',
      ...jsonBody({ key: generated.data.key, device_id: 'phone-multi', user_id: 'user-2' }),
    });
    assert.equal(first.data.valid, true, JSON.stringify(first.data));
    assert.equal(second.data.valid, true, JSON.stringify(second.data));
  } finally {
    await stopServer(server);
  }
});
