const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const SYNC_API_KEY = process.env.SYNC_API_KEY || '';
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// The public API is deployed under /api/v1, while local installs still use root routes.
app.use((req, res, next) => {
  if (req.url === '/api/v1' || req.url.startsWith('/api/v1/')) {
    req.url = req.url.slice('/api/v1'.length) || '/';
  }
  next();
});

function secureKeyEquals(receivedKey, expectedKey) {
  if (!receivedKey || !expectedKey) return false;
  const received = Buffer.from(receivedKey);
  const expected = Buffer.from(expectedKey);
  return received.length === expected.length && require('crypto').timingSafeEqual(received, expected);
}

function requireSyncAuthorization(req, res, next) {
  if (!SYNC_API_KEY) {
    if (IS_PRODUCTION) {
      return res.status(503).json({ error: 'SYNC_API_KEY غير مضبوط على الخادم' });
    }
    return next();
  }

  const receivedKey = req.get('x-sync-api-key');
  if (!secureKeyEquals(receivedKey, SYNC_API_KEY)) {
    return res.status(401).json({ error: 'طلب المزامنة غير مصرح به' });
  }
  return next();
}

function requireAdminAuthorization(req, res, next) {
  if (!ADMIN_SECRET) {
    if (IS_PRODUCTION) {
      return res.status(503).json({ error: 'ADMIN_SECRET غير مضبوط على الخادم' });
    }
    return next();
  }
  if (!secureKeyEquals(req.get('x-admin-secret'), ADMIN_SECRET)) {
    return res.status(401).json({ error: 'صلاحية المدير مطلوبة' });
  }
  return next();
}

const dbDir = process.env.DB_PATH ? path.dirname(process.env.DB_PATH) : './data';
const dbPath = process.env.DB_PATH || path.join(dbDir, 'smart_accountant.db');

if (!fs.existsSync(dbDir) && dbDir !== '.' && dbDir !== './') {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('خطأ في الاتصال بقاعدة البيانات:', err.message);
  } else {
    console.log(`تم الاتصال بقاعدة بيانات SQLite بنجاح: ${dbPath}`);
  }
});

function normalizeJsonValue(value) {
  if (value === undefined) return null;
  if (typeof value === 'object' && value !== null) {
    return JSON.stringify(value);
  }
  return value;
}

function serializeRow(row = {}) {
  const copy = { ...row };
  if (copy.shop_id !== undefined) {
    copy.shopId = copy.shop_id;
    delete copy.shop_id;
  }
  if (copy.user_id !== undefined) {
    copy.userId = copy.user_id;
    delete copy.user_id;
  }
  if (copy.device_id !== undefined) {
    copy.deviceId = copy.device_id;
    delete copy.device_id;
  }
  if (copy.entity_id !== undefined) {
    copy.entityId = copy.entity_id;
    delete copy.entity_id;
  }
  if (copy.user_code !== undefined) {
    copy.userCode = copy.user_code;
    delete copy.user_code;
  }
  for (const key of Object.keys(copy)) {
    if (copy[key] !== null && typeof copy[key] === 'string') {
      try {
        const parsed = JSON.parse(copy[key]);
        if (parsed !== null && typeof parsed === 'object') {
          copy[key] = parsed;
        }
      } catch (_) {
        // ignore; keep string
      }
    }
  }
  return copy;
}

function ensureSyncMetadata(record, deviceId, shopId, userId) {
  const base = { ...record };
  base.id = base.id || uuidv4();
  base.device_id = deviceId || base.device_id || base.deviceId || 'server';
  base.shop_id = shopId || base.shop_id || base.shopId || null;
  base.user_id = userId || base.user_id || base.userId || null;
  base.createdAt = base.createdAt || new Date().toISOString();
  base.updatedAt = base.updatedAt || new Date().toISOString();
  base.deletedAt = base.deletedAt ?? null;
  delete base.deviceId;
  delete base.shopId;
  delete base.userId;
  return base;
}

const tableColumns = {
  shops: ['id', 'shop_code', 'name', 'owner_id', 'owner_name', 'phone', 'currency', 'country', 'createdAt', 'updatedAt', 'device_id', 'shop_id', 'user_id'],
  users: ['id', 'shop_id', 'user_code', 'email', 'name', 'role', 'status', 'createdAt', 'updatedAt', 'device_id', 'user_id'],
  audit_logs: ['id', 'device_id', 'shop_id', 'user_id', 'entity', 'entity_id', 'action', 'details', 'createdAt'],
};

function normalizeTableRecord(tableName, record, deviceId, shopId, userId) {
  const item = ensureSyncMetadata(record, deviceId, shopId, userId);
  if (tableName === 'audit_logs') {
    item.entity_id = item.entity_id || item.entityId || null;
    item.details = item.details || {};
  }
  if (tableName === 'shops') {
    item.shop_code = item.shop_code || item.shopCode || null;
    item.owner_name = item.owner_name || item.ownerName || null;
    item.phone = item.phone || null;
    delete item.shopCode;
    delete item.ownerName;
  }
  if (tableName === 'users') {
    item.status = item.status || 'active';
    item.user_code = item.user_code || item.userCode || null;
    delete item.userCode;
  }
  delete item.entityId;
  delete item.syncStatus;
  delete item.serverId;
  const allowed = tableColumns[tableName];
  if (!allowed) return item;
  return Object.fromEntries(Object.entries(item).filter(([key]) => allowed.includes(key)));
}

function getRow(tableName, id) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM ${tableName} WHERE id = ?`, [id], (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function getUserById(id, shopId) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT id, shop_id, role FROM users WHERE id = ? AND shop_id = ?',
      [id, shopId],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      },
    );
  });
}

class AuthorizationError extends Error {}

async function authorizeUserRoleChange(incoming, existing, shopId, userId) {
  if (!existing || incoming.role === existing.role) return;
  const actorId = incoming.updatedBy || incoming.updated_by || incoming.user_id || userId;
  const actor = await getUserById(actorId, shopId);
  if (!actor || actor.role !== 'owner') {
    throw new AuthorizationError('لا تملك صلاحية تغيير أدوار المستخدمين');
  }
}

function conflictPayload(tableName, incoming, existing, resolution) {
  return {
    table: tableName,
    record_id: incoming.id,
    incoming_device_id: incoming.device_id,
    existing_device_id: existing.device_id,
    incoming_updatedAt: incoming.updatedAt,
    existing_updatedAt: existing.updatedAt,
    resolution,
  };
}

function upsertConflict(conflict) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO sync_conflicts
       (id, table_name, record_id, incoming_device_id, existing_device_id,
        incoming_updatedAt, existing_updatedAt, resolution, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        uuidv4(),
        conflict.table,
        conflict.record_id,
        conflict.incoming_device_id,
        conflict.existing_device_id,
        conflict.incoming_updatedAt,
        conflict.existing_updatedAt,
        conflict.resolution,
        new Date().toISOString(),
      ],
      (err) => (err ? reject(err) : resolve()),
    );
  });
}

function upsertTable(tableName, records, deviceId, shopId, userId) {
  if (!Array.isArray(records)) return Promise.resolve([]);

  return Promise.all(records.map((record) => {
    const item = normalizeTableRecord(tableName, record, deviceId, shopId, userId);
    return getRow(tableName, item.id).then(async (existing) => {
      if (tableName === 'users') {
        await authorizeUserRoleChange(item, existing, shopId, userId);
      }
      if (existing && existing.device_id !== item.device_id) {
        const incomingTime = Date.parse(item.updatedAt || item.createdAt || '') || 0;
        const existingTime = Date.parse(existing.updatedAt || existing.createdAt || '') || 0;
        if (incomingTime <= existingTime) {
          const conflict = conflictPayload(tableName, item, existing, 'server_wins');
          await upsertConflict(conflict);
          return conflict;
        }
        const conflict = conflictPayload(tableName, item, existing, 'incoming_wins');
        await upsertConflict(conflict);
        await writeRecord(tableName, item);
        return conflict;
      }
      await writeRecord(tableName, item);
      return null;
    });
  })).then((conflicts) => conflicts.filter(Boolean));
}

function writeRecord(tableName, item) {
  return new Promise((resolve, reject) => {
    const columns = Object.keys(item);
    const placeholders = columns.map(() => '?').join(',');
    const values = columns.map((key) => normalizeJsonValue(item[key]));

    db.run(
      `INSERT OR REPLACE INTO ${tableName} (${columns.join(',')}) VALUES (${placeholders})`,
      values,
      (err) => {
        if (err) {
          console.error(`خطأ في INSERT ${tableName}:`, err.message);
          reject(err);
          return;
        }
        resolve();
      },
    );
  });
}

function fetchTable(tableName, shopId, deviceId, lastSync) {
  return new Promise((resolve, reject) => {
    let query = `SELECT * FROM ${tableName}`;
    const params = [];

    if (shopId) {
      query += ' WHERE shop_id = ?';
      params.push(shopId);
    } else if (deviceId) {
      query += ' WHERE device_id = ?';
      params.push(deviceId);
    }

    if (lastSync) {
      const changedSince = tableName === 'audit_logs'
        ? 'createdAt > ?'
        : '(updatedAt > ? OR createdAt > ?)';
      query += query.includes(' WHERE ') ? ` AND ${changedSince}` : ` WHERE ${changedSince}`;
      params.push(lastSync);
      if (tableName !== 'audit_logs') params.push(lastSync);
    }

    db.all(query, params, (err, rows) => {
      if (err) return reject(err);
      resolve((rows || []).map((row) => serializeRow(row)));
    });
  });
}

function createSchema() {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS licenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      status TEXT DEFAULT 'active',
      device_id TEXT,
      client_name TEXT,
      notes TEXT,
      allow_multiple_users INTEGER DEFAULT 0,
      bound_user_id TEXT,
      expires_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      activated_at DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS trial_devices (
      device_id TEXT PRIMARY KEY,
      started_at DATETIME NOT NULL,
      expires_at DATETIME NOT NULL,
      createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`);

    for (const column of [
      ['client_name', 'TEXT'],
      ['notes', 'TEXT'],
      ['allow_multiple_users', 'INTEGER DEFAULT 0'],
      ['bound_user_id', 'TEXT'],
      ['expires_at', 'DATETIME'],
    ]) {
      db.run(`ALTER TABLE licenses ADD COLUMN ${column[0]} ${column[1]}`, () => {});
    }

    db.run(`CREATE TABLE IF NOT EXISTS shops (
      id TEXT PRIMARY KEY,
      shop_code TEXT,
      name TEXT,
      owner_id TEXT,
      owner_name TEXT,
      phone TEXT,
      currency TEXT DEFAULT 'SAR',
      country TEXT DEFAULT 'SA',
      createdAt DATETIME,
      updatedAt DATETIME,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT
    )`);
    db.run(`ALTER TABLE shops ADD COLUMN shop_code TEXT`, () => {});
    db.run(`ALTER TABLE shops ADD COLUMN owner_name TEXT`, () => {});
    db.run(`ALTER TABLE shops ADD COLUMN phone TEXT`, () => {});

    db.run(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      shop_id TEXT,
      user_code TEXT,
      email TEXT,
      name TEXT,
      role TEXT DEFAULT 'owner',
      status TEXT DEFAULT 'active',
      createdAt DATETIME,
      updatedAt DATETIME,
      device_id TEXT,
      user_id TEXT
    )`);
    db.run(`ALTER TABLE users ADD COLUMN user_code TEXT`, () => {});

    db.run(`CREATE TABLE IF NOT EXISTS roles (
      id TEXT PRIMARY KEY,
      shop_id TEXT,
      name TEXT,
      permissions TEXT,
      createdAt DATETIME,
      updatedAt DATETIME,
      device_id TEXT,
      user_id TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      name TEXT,
      phone TEXT,
      address TEXT,
      openingBalance REAL,
      balance REAL,
      creditLimit REAL,
      notes TEXT,
      createdAt DATETIME,
      updatedAt DATETIME,
      deletedAt DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS suppliers (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      name TEXT,
      phone TEXT,
      address TEXT,
      openingBalance REAL,
      balance REAL,
      creditLimit REAL,
      notes TEXT,
      createdAt DATETIME,
      updatedAt DATETIME,
      deletedAt DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      name TEXT,
      barcode TEXT,
      sku TEXT,
      buyPrice REAL,
      sellPrice REAL,
      quantity REAL,
      minQuantity REAL,
      category TEXT,
      unit TEXT,
      notes TEXT,
      supplierId TEXT,
      expiryDate DATETIME,
      createdAt DATETIME,
      updatedAt DATETIME,
      deletedAt DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS invoices (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      number TEXT,
      type TEXT,
      partyId TEXT,
      partyName TEXT,
      taxRate REAL,
      paidAmount REAL,
      paymentMethod TEXT,
      notes TEXT,
      createdAt DATETIME,
      updatedAt DATETIME,
      lines TEXT,
      deletedAt DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS expenses (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      name TEXT,
      category TEXT,
      amount REAL,
      notes TEXT,
      createdAt DATETIME,
      updatedAt DATETIME,
      deletedAt DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS vouchers (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      number TEXT,
      type TEXT,
      partyId TEXT,
      partyName TEXT,
      amount REAL,
      notes TEXT,
      createdAt DATETIME,
      updatedAt DATETIME,
      deletedAt DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS sync_queue (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      table_name TEXT,
      action TEXT,
      payload TEXT,
      status TEXT DEFAULT 'pending',
      createdAt DATETIME,
      updatedAt DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      entity TEXT,
      entity_id TEXT,
      action TEXT,
      details TEXT,
      createdAt DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS sync_conflicts (
      id TEXT PRIMARY KEY,
      table_name TEXT NOT NULL,
      record_id TEXT NOT NULL,
      incoming_device_id TEXT,
      existing_device_id TEXT,
      incoming_updatedAt DATETIME,
      existing_updatedAt DATETIME,
      resolution TEXT NOT NULL,
      createdAt DATETIME NOT NULL
    )`);
  });
}

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Cloud Sync backend is running',
    version: '2.6.0',
    database: dbPath,
    timestamp: new Date().toISOString(),
  });
});

app.get('/shops/resolve', requireSyncAuthorization, (req, res) => {
  const shopCode = String(req.query.shop_code || '').trim();
  if (!/^\d{6}$/.test(shopCode)) {
    return res.status(400).json({ error: 'shop_code يجب أن يتكون من 6 أرقام' });
  }
  db.get(
    'SELECT id, shop_code, name, owner_id, currency, country FROM shops WHERE shop_code = ? LIMIT 1',
    [shopCode],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(404).json({ error: 'المحل غير موجود' });
      res.json({
        shopId: row.id,
        shopCode: row.shop_code,
        shopName: row.name,
        currency: row.currency,
        country: row.country,
      });
    },
  );
});

app.get('/users/resolve', requireSyncAuthorization, (req, res) => {
  const userCode = String(req.query.user_code || '').trim();
  if (!/^\d{8}$/.test(userCode)) {
    return res.status(400).json({ error: 'user_code يجب أن يتكون من 8 أرقام' });
  }
  db.get(
    `SELECT users.id, users.shop_id, users.user_code, users.email, users.name,
            users.role, users.status, shops.shop_code
       FROM users
       LEFT JOIN shops ON shops.id = users.shop_id
      WHERE users.user_code = ? LIMIT 1`,
    [userCode],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(404).json({ error: 'حساب المستخدم غير موجود' });
      res.json({
        id: row.id,
        shopId: row.shop_id,
        shopCode: row.shop_code,
        userCode: row.user_code,
        email: row.email,
        name: row.name,
        role: row.role,
        status: row.status,
      });
    },
  );
});

app.get('/shops/:shopId/users', requireSyncAuthorization, (req, res) => {
  const shopId = String(req.params.shopId || '').trim();
  if (!shopId) return res.status(400).json({ error: 'shopId مطلوب' });
  db.all(
    `SELECT id, shop_id, user_code, email, name, role, status, createdAt, updatedAt
       FROM users WHERE shop_id = ? ORDER BY name COLLATE NOCASE`,
    [shopId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ users: (rows || []).map((row) => serializeRow(row)) });
    },
  );
});

app.get('/shops/:shopId/users/by-code/:userCode', requireSyncAuthorization, (req, res) => {
  const shopId = String(req.params.shopId || '').trim();
  const userCode = String(req.params.userCode || '').trim();
  if (!shopId || !/^\d{8}$/.test(userCode)) {
    return res.status(400).json({ error: 'بيانات المستخدم غير صحيحة' });
  }
  db.get(
    `SELECT id, shop_id, user_code, email, name, role, status, createdAt, updatedAt
       FROM users WHERE shop_id = ? AND user_code = ? LIMIT 1`,
    [shopId, userCode],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(404).json({ error: 'حساب المستخدم غير موجود' });
      res.json(serializeRow(row));
    },
  );
});

app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    message: 'DrarTech Smart Accountant Backend',
    version: '2.6.0',
    endpoints: ['/generate', '/verify', '/stats', '/sync', '/health'],
  });
});

app.get('/admin-check', requireAdminAuthorization, (req, res) => {
  res.json({ success: true, admin: true });
});

app.get('/stats', requireAdminAuthorization, (req, res) => {
  db.get(`SELECT COUNT(*) as total,
            SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN status='used' THEN 1 ELSE 0 END) as used,
            SUM(CASE WHEN status='banned' THEN 1 ELSE 0 END) as banned,
            SUM(CASE WHEN date(created_at)=date('now') THEN 1 ELSE 0 END) as today_created,
            SUM(CASE WHEN date(activated_at)=date('now') THEN 1 ELSE 0 END) as today_activated
            FROM licenses`, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row);
  });
});

app.get('/licenses', requireAdminAuthorization, (req, res) => {
  const search = String(req.query.search || '').trim();
  const status = String(req.query.status || 'all').trim();
  let query = 'SELECT * FROM licenses';
  const conditions = [];
  const params = [];
  if (status !== 'all') {
    conditions.push('status = ?');
    params.push(status);
  }
  if (search) {
    conditions.push('(key LIKE ? OR device_id LIKE ? OR client_name LIKE ?)');
    const term = `%${search}%`;
    params.push(term, term, term);
  }
  if (conditions.length) query += ` WHERE ${conditions.join(' AND ')}`;
  query += ' ORDER BY id DESC';
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ licenses: rows || [], total: (rows || []).length });
  });
});

app.post('/generate', requireAdminAuthorization, (req, res) => {
  const {
    device_id,
    client_name,
    notes,
    expires_at,
    allow_multiple_users,
    multi_user,
  } = req.body || {};
  if (!device_id || !String(device_id).trim()) {
    return res.status(400).json({ error: 'device_id مطلوب لإنشاء ترخيص مرتبط بالجهاز' });
  }
  const deviceId = String(device_id).trim();
  const multiUser = Boolean(allow_multiple_users ?? multi_user);

  db.get(
    `SELECT * FROM licenses WHERE device_id = ? AND status != 'banned' LIMIT 1`,
    [deviceId],
    (findErr, existing) => {
      if (findErr) return res.status(500).json({ error: findErr.message });
      if (existing) {
        return res.json({
          success: true,
          existing: true,
          key: existing.key,
          id: existing.id,
          device_id: existing.device_id,
          allow_multiple_users: Boolean(existing.allow_multiple_users),
          mode: existing.allow_multiple_users ? 'multi-user' : 'single-user',
        });
      }

      const newKey = `DRAR-${require('crypto').randomBytes(4).toString('hex').toUpperCase()}`;
      db.run(
        `INSERT INTO licenses
         (key, status, device_id, client_name, notes, allow_multiple_users, expires_at)
         VALUES (?, 'active', ?, ?, ?, ?, ?)`,
        [newKey, deviceId, client_name || null, notes || null, multiUser ? 1 : 0, expires_at || null],
        function (insertErr) {
          if (insertErr) {
            return res.status(500).json({ error: 'فشل في توليد المفتاح', details: insertErr.message });
          }
          res.json({
            success: true,
            existing: false,
            key: newKey,
            id: this.lastID,
            device_id: deviceId,
            allow_multiple_users: multiUser,
            mode: multiUser ? 'multi-user' : 'single-user',
          });
        },
      );
    },
  );
});

app.post('/verify', (req, res) => {
  const body = req.body || {};
  const key = String(body.key || body.licenseKey || '').trim().toUpperCase();
  const deviceId = String(body.device_id || body.deviceId || '').trim();
  const userId = body.user_id || body.userId || null;

  if (!key) return res.status(400).json({ valid: false, error: 'المفتاح مطلوب' });
  if (!deviceId) return res.status(400).json({ valid: false, error: 'معرف الجهاز مطلوب' });

  db.get(`SELECT * FROM licenses WHERE key = ?`, [key], (err, row) => {
    if (err) return res.status(500).json({ valid: false, error: 'خطأ في قاعدة البيانات' });
    if (!row) return res.json({ valid: false, message: 'المفتاح غير موجود' });
    if (row.status === 'banned') return res.json({ valid: false, message: 'الترخيص محظور', status: row.status });
    if (row.expires_at && Date.parse(row.expires_at) <= Date.now()) {
      db.run(`UPDATE licenses SET status='expired' WHERE id=?`, [row.id]);
      return res.json({ valid: false, message: 'الترخيص منتهي الصلاحية', status: 'expired' });
    }
    if (row.device_id && row.device_id !== deviceId) {
      return res.json({ valid: false, message: 'المفتاح مرتبط بجهاز آخر', requires_device: true, status: row.status });
    }
    if (!row.allow_multiple_users && row.bound_user_id && userId && row.bound_user_id !== userId) {
      return res.json({ valid: false, message: 'الترخيص مخصص لمستخدم واحد على هذا الجهاز', status: row.status });
    }

    const boundUser = row.bound_user_id || userId || null;
    db.run(
      `UPDATE licenses SET status='used', device_id=?, bound_user_id=?, activated_at=COALESCE(activated_at, CURRENT_TIMESTAMP) WHERE id=?`,
      [deviceId, boundUser, row.id],
      (updateErr) => {
        if (updateErr) return res.status(500).json({ valid: false, error: updateErr.message });
        res.json({
          valid: true,
          message: 'مفتاح الترخيص صالح وتم التفعيل بنجاح',
          status: 'used',
          device_id: deviceId,
          allow_multiple_users: Boolean(row.allow_multiple_users),
        });
      },
    );
  });
});

app.post('/reset-device', requireAdminAuthorization, (req, res) => {
  db.run(
    `UPDATE licenses SET status='active', device_id=NULL, bound_user_id=NULL, activated_at=NULL WHERE id=?`,
    [Number(req.body?.id)],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: this.changes > 0 });
    },
  );
});

app.post('/update-status', requireAdminAuthorization, (req, res) => {
  const allowed = ['active', 'used', 'banned', 'expired'];
  if (!allowed.includes(req.body?.status)) return res.status(400).json({ error: 'حالة غير صالحة' });
  db.run(`UPDATE licenses SET status=? WHERE id=?`, [req.body.status, Number(req.body.id)], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: this.changes > 0 });
  });
});

app.delete('/licenses/:id', requireAdminAuthorization, (req, res) => {
  db.run(`DELETE FROM licenses WHERE id=?`, [Number(req.params.id)], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: this.changes > 0 });
  });
});

app.post('/sync', requireSyncAuthorization, async (req, res) => {
  try {
    const { device_id, shop_id, user_id, last_sync, changes } = req.body;

    if (!device_id) {
      return res.status(400).json({ error: 'device_id مطلوب' });
    }

    const tablesToSync = [
      'customers',
      'suppliers',
      'products',
      'invoices',
      'expenses',
      'vouchers',
      'shops',
      'users',
      'roles',
      'audit_logs',
    ];

    const conflicts = [];
    if (changes && typeof changes === 'object') {
      for (const tableName of Object.keys(changes)) {
        if (!tablesToSync.includes(tableName)) continue;
        conflicts.push(...await upsertTable(tableName, changes[tableName], device_id, shop_id, user_id));
      }
    }

    const serverData = {};
    for (const tableName of tablesToSync) {
      serverData[tableName] = await fetchTable(tableName, shop_id, device_id, last_sync);
    }

    const response = {
      success: true,
      server_time: new Date().toISOString(),
      data: serverData,
      last_sync: last_sync || null,
      synced_tables: tablesToSync,
      conflict_policy: 'last_write_wins',
      conflicts,
    };

    res.json(response);
  } catch (error) {
    console.error('خطأ في مزامنة السحابة:', error);
    const status = error instanceof AuthorizationError ? 403 : 500;
    res.status(status).json({ success: false, error: error.message });
  }
});

app.post('/audit-log', requireSyncAuthorization, (req, res) => {
  const { device_id, shop_id, user_id, entity, entity_id, action, details } = req.body;

  if (!device_id || !entity || !action) {
    return res.status(400).json({ error: 'device_id و entity و action مطلوبة' });
  }

  const event = {
    id: uuidv4(),
    device_id,
    shop_id: shop_id || null,
    user_id: user_id || null,
    entity,
    entity_id: entity_id || null,
    action,
    details: details || null,
    createdAt: new Date().toISOString(),
  };

  db.run(
    `INSERT INTO audit_logs (id, device_id, shop_id, user_id, entity, entity_id, action, details, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [event.id, event.device_id, event.shop_id, event.user_id, event.entity, event.entity_id, event.action, JSON.stringify(event.details), event.createdAt],
    (err) => {
      if (err) {
        return res.status(500).json({ success: false, error: err.message });
      }
      res.json({ success: true, event });
    }
  );
});

createSchema();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 سيرفر Smart Accountant يعمل على المنفذ: ${PORT}`);
  console.log(`📁 قاعدة البيانات: ${dbPath}`);
});

app.post('/trial/register', requireSyncAuthorization, (req, res) => {
  const deviceId = String(req.body?.device_id || '').trim();
  if (!deviceId || deviceId === 'UNKNOWN-DEVICE') {
    return res.status(400).json({ error: 'معرف جهاز صالح مطلوب' });
  }

  db.get(
    'SELECT device_id, started_at, expires_at FROM trial_devices WHERE device_id = ? LIMIT 1',
    [deviceId],
    (findError, existing) => {
      if (findError) return res.status(500).json({ error: findError.message });
      if (existing) {
        return res.json({
          deviceId: existing.device_id,
          trialStart: existing.started_at,
          trialEnd: existing.expires_at,
          isNew: false,
        });
      }

      const startedAt = new Date();
      const expiresAt = new Date(startedAt.getTime() + 10 * 24 * 60 * 60 * 1000);
      db.run(
        'INSERT OR IGNORE INTO trial_devices (device_id, started_at, expires_at) VALUES (?, ?, ?)',
        [deviceId, startedAt.toISOString(), expiresAt.toISOString()],
        (insertError) => {
          if (insertError) return res.status(500).json({ error: insertError.message });
          db.get(
            'SELECT device_id, started_at, expires_at FROM trial_devices WHERE device_id = ? LIMIT 1',
            [deviceId],
            (readError, saved) => {
              if (readError || !saved) {
                return res.status(500).json({ error: readError?.message || 'تعذر حفظ التجربة' });
              }
              res.json({
                deviceId: saved.device_id,
                trialStart: saved.started_at,
                trialEnd: saved.expires_at,
                isNew: saved.started_at === startedAt.toISOString(),
              });
            },
          );
        },
      );
    },
  );
});

app.get('/shops/resolve-identity', requireSyncAuthorization, (req, res) => {
  const name = String(req.query.name || '').trim();
  const ownerName = String(req.query.owner_name || '').trim();
  const phone = String(req.query.phone || '').trim();
  if (!name || !ownerName || !phone) {
    return res.status(400).json({ error: 'اسم المحل واسم المالك والهاتف مطلوبة' });
  }
  db.get(
    `SELECT id, shop_code, name, owner_name, phone, currency, country
       FROM shops
      WHERE lower(trim(name)) = lower(trim(?))
        AND lower(trim(owner_name)) = lower(trim(?))
        AND trim(phone) = trim(?)
      ORDER BY updatedAt DESC
      LIMIT 1`,
    [name, ownerName, phone],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(404).json({ error: 'المحل غير موجود' });
      res.json({
        shopId: row.id,
        shopCode: row.shop_code,
        shopName: row.name,
        ownerName: row.owner_name,
        phone: row.phone,
        currency: row.currency,
        country: row.country,
      });
    },
  );
});