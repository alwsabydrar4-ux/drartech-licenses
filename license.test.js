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
      SYNC_API_KEY: 'test-sync-api-key',
    },
    stdio: 'ignore',
  });
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) return { child, port, directory };
    } catch (_) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  child.kill();
  throw new Error(`License backend did not start on port ${port}`);
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

test('generates device-bound licenses and enforces admin authorization', { concurrency: false }, async () => {
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

test('owner single-device licenses are bound to the device and reject other users', { concurrency: false }, async () => {
  const server = await startServer();
  try {
    const headers = { 'x-admin-secret': 'test-admin-secret', 'content-type': 'application/json' };
    const generated = await request(server, '/generate', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        device_id: 'owner-phone-1',
        client_name: 'مالك',
        license_type: 'owner_single',
        owner_user_id: 'owner-1',
        shop_id: 'shop-1',
      }),
    });
    assert.equal(generated.status, 200, JSON.stringify(generated.data));
    assert.ok(generated.data.key, JSON.stringify(generated.data));

    const ownerValid = await request(server, '/verify', {
      method: 'POST',
      ...jsonBody({ key: generated.data.key, device_id: 'owner-phone-1', user_id: 'owner-1', shop_id: 'shop-1' }),
    });
    const staffBlocked = await request(server, '/verify', {
      method: 'POST',
      ...jsonBody({ key: generated.data.key, device_id: 'owner-phone-1', user_id: 'staff-1', shop_id: 'shop-1' }),
    });

    assert.equal(ownerValid.data.valid, true, JSON.stringify(ownerValid.data));
    assert.equal(staffBlocked.data.valid, false, JSON.stringify(staffBlocked.data));
    assert.match(staffBlocked.data.message, /مستخدم|owner|مرخص/i);
  } finally {
    await stopServer(server);
  }
});

test('owner team licenses allow the owner and approved staff users on the same shop', { concurrency: false }, async () => {
  const server = await startServer();
  try {
    const headers = { 'x-admin-secret': 'test-admin-secret', 'content-type': 'application/json' };
    const generated = await request(server, '/generate', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        device_id: 'owner-team-phone',
        client_name: 'مكتب',
        license_type: 'owner_team',
        owner_user_id: 'owner-9',
        shop_id: 'shop-9',
        allow_staff_access: true,
        max_staff_users: 3,
      }),
    });
    assert.equal(generated.status, 200, JSON.stringify(generated.data));

    const ownerAccess = await request(server, '/verify', {
      method: 'POST',
      ...jsonBody({ key: generated.data.key, device_id: 'owner-team-phone', user_id: 'owner-9', shop_id: 'shop-9' }),
    });
    const staffAccess = await request(server, '/verify', {
      method: 'POST',
      ...jsonBody({ key: generated.data.key, device_id: 'owner-team-phone', user_id: 'staff-1', shop_id: 'shop-9' }),
    });
    const extraStaff = await request(server, '/verify', {
      method: 'POST',
      ...jsonBody({ key: generated.data.key, device_id: 'owner-team-phone', user_id: 'staff-2', shop_id: 'shop-9' }),
    });

    assert.equal(ownerAccess.data.valid, true, JSON.stringify(ownerAccess.data));
    assert.equal(staffAccess.data.valid, true, JSON.stringify(staffAccess.data));
    assert.equal(extraStaff.data.valid, true, JSON.stringify(extraStaff.data));
  } finally {
    await stopServer(server);
  }
});

test('repeated login on the same device upserts user_devices', { concurrency: false }, async () => {
  const server = await startServer();
  try {
    const login = {
      shop_id: 'repeat-login-shop',
      user_code: '35809107',
      email: 'owner@repeat-login.test',
      device_id: 'repeat-login-device',
    };
    const headers = {
      'content-type': 'application/json',
      'x-sync-api-key': 'test-sync-api-key',
    };
    const first = await request(server, '/auth/login', {
      method: 'POST',
      headers,
      body: JSON.stringify(login),
    });
    const second = await request(server, '/auth/login', {
      method: 'POST',
      headers,
      body: JSON.stringify(login),
    });

    assert.equal(first.status, 200, JSON.stringify(first.data));
    assert.equal(second.status, 200, JSON.stringify(second.data));
    assert.ok(second.data.token);
  } finally {
    await stopServer(server);
  }
});
