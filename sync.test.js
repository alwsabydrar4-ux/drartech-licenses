const assert = require('node:assert/strict');
const { mkdtemp, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawn } = require('node:child_process');
const { test } = require('node:test');

async function startServer() {
  const directory = await mkdtemp(join(tmpdir(), 'smart-accountant-sync-'));
  const port = 3200 + Math.floor(Math.random() * 300);
  const database = join(directory, 'sync.db');
  const child = spawn(process.execPath, ['server.js'], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(port), DB_PATH: database, NODE_ENV: 'development' },
    stdio: 'ignore',
  });

  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) return { process: child, port, directory };
    } catch (_) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  child.kill();
  await rm(directory, { recursive: true, force: true });
  throw new Error('Backend did not start in time');
}

async function stopServer(server) {
  await new Promise((resolve) => {
    if (server.process.exitCode !== null) {
      resolve();
      return;
    }
    server.process.once('exit', resolve);
    server.process.kill();
  });
  await rm(server.directory, { recursive: true, force: true });
}

async function sync(port, payload, apiPrefix = '') {
  const response = await fetch(`http://127.0.0.1:${port}${apiPrefix}/sync`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  assert.equal(response.status, 200);
  return response.json();
}

test('detects concurrent edits and applies last-write-wins', async () => {
  const server = await startServer();
  try {
    const base = {
      id: 'user-conflict-1',
      shopId: 'shop-conflict',
      email: 'conflict@test.com',
      role: 'owner',
      status: 'active',
      createdAt: '2026-09-07T10:00:00.000Z',
    };

    await sync(server.port, {
      device_id: 'device-a',
      shop_id: 'shop-conflict',
      changes: { users: [{ ...base, name: 'من الجهاز الأول', updatedAt: '2026-09-07T10:01:00.000Z' }] },
    });

    const stale = await sync(server.port, {
      device_id: 'device-b',
      shop_id: 'shop-conflict',
      changes: { users: [{ ...base, name: 'تعديل قديم', updatedAt: '2026-09-07T10:00:30.000Z' }] },
    });
    assert.equal(stale.conflicts.length, 1);
    assert.equal(stale.conflicts[0].resolution, 'server_wins');
    assert.equal(stale.data.users[0].name, 'من الجهاز الأول');

    const newer = await sync(server.port, {
      device_id: 'device-b',
      shop_id: 'shop-conflict',
      changes: { users: [{ ...base, name: 'التعديل الأحدث', updatedAt: '2026-09-07T10:02:00.000Z' }] },
    });
    assert.equal(newer.conflicts.length, 1);
    assert.equal(newer.conflicts[0].resolution, 'incoming_wins');
    assert.equal(newer.data.users[0].name, 'التعديل الأحدث');
  } finally {
    await stopServer(server);
  }
});

test('uses last_sync to omit unchanged records', async () => {
  const server = await startServer();
  try {
    const first = await sync(server.port, {
      device_id: 'device-diff',
      shop_id: 'shop-diff',
      changes: {
        users: [{
          id: 'user-diff-1',
          shopId: 'shop-diff',
          name: 'مستخدم',
          email: 'diff@test.com',
          role: 'owner',
          status: 'active',
          createdAt: '2026-09-07T11:00:00.000Z',
          updatedAt: '2026-09-07T11:00:00.000Z',
        }],
      },
    });
    const second = await sync(server.port, {
      device_id: 'device-diff',
      shop_id: 'shop-diff',
      last_sync: first.server_time,
      changes: {},
    });
    assert.equal(second.data.users.length, 0);
  } finally {
    await stopServer(server);
  }
});

test('accepts sync requests under the public api v1 prefix', async () => {
  const server = await startServer();
  try {
    const result = await sync(server.port, {
      device_id: 'device-api-v1',
      shop_id: 'shop-api-v1',
      changes: {},
    }, '/api/v1');
    assert.equal(result.success, true);
  } finally {
    await stopServer(server);
  }
});

test('does not reset a device trial on repeated registration', async () => {
  const server = await startServer();
  try {
    const first = await fetch(`http://127.0.0.1:${server.port}/trial/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ device_id: 'trial-device-1' }),
    });
    const firstData = await first.json();
    const second = await fetch(`http://127.0.0.1:${server.port}/trial/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ device_id: 'trial-device-1' }),
    });
    const secondData = await second.json();

    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    assert.equal(firstData.trialStart, secondData.trialStart);
    assert.equal(firstData.trialEnd, secondData.trialEnd);
  } finally {
    await stopServer(server);
  }
});
