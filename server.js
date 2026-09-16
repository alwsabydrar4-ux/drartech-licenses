const express = require('express');
const dns = require('dns');
const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

dns.setDefaultResultOrder('ipv4first');

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = (process.env.DATABASE_URL || '').trim();
const SYNC_API_KEY = process.env.SYNC_API_KEY || '';
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
const requestBuckets = new Map();
let dbReady = false;
let dbHealthError = null;

console.log('DATABASE_URL exists:', Boolean(process.env.DATABASE_URL));
console.log('NODE_ENV:', process.env.NODE_ENV || '(not set)');

function toPostgresQuery(query, params = []) {
  const values = Array.isArray(params) ? [...params] : [];
  let text = query;
  let index = 1;

  text = text.replace(/INSERT\s+OR\s+REPLACE\s+INTO\s+([A-Za-z0-9_"`]+)\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)/gi, (_, table, columns, placeholderList) => {
    const normalizedColumns = columns.trim();
    const valuesList = placeholderList.trim();
    return `INSERT INTO ${table} (${normalizedColumns}) VALUES (${valuesList}) ON CONFLICT (id) DO UPDATE SET ${normalizedColumns.split(',').map((column) => `${column.trim()} = EXCLUDED.${column.trim()}`).join(', ')}`;
  });

  text = text.replace(/INSERT\s+OR\s+IGNORE\s+INTO\s+([A-Za-z0-9_"`]+)\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)/gi, (_, table, columns, placeholderList) => {
    return `INSERT INTO ${table} (${columns.trim()}) VALUES (${placeholderList.trim()}) ON CONFLICT DO NOTHING`;
  });

  text = text.replace(/\?/g, () => `$${index++}`);
  return { text, values };
}

function createPostgresDbAdapter() {
  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 10000,
    keepAlive: true,
  });

  const exec = (method, query, params, callback) => {
    const { text, values } = toPostgresQuery(query, params);
    pool.query(text, values)
      .then((result) => {
        if (callback) {
          const context = { lastID: null, changes: result.rowCount || 0 };
          if (Array.isArray(result.rows) && result.rows.length > 0 && result.rows[0]?.id) {
            context.lastID = result.rows[0].id;
          }
          callback.call(context, null, method === 'get' ? result.rows[0] || null : method === 'all' ? result.rows : result);
        }
      })
      .catch((err) => {
        if (callback) callback(err, null);
      });
  };

  return {
    get(query, params, callback) {
      if (typeof params === 'function') {
        callback = params;
        params = [];
      }
      exec('get', query, params || [], callback);
    },
    all(query, params, callback) {
      if (typeof params === 'function') {
        callback = params;
        params = [];
      }
      exec('all', query, params || [], callback);
    },
    run(query, params, callback) {
      if (typeof params === 'function') {
        callback = params;
        params = [];
      }
      exec('run', query, params || [], callback);
    },
    serialize(callback) {
      if (typeof callback === 'function') callback();
    },
    async close() {
      await pool.end();
    },
  };
}

function createSqliteDbAdapter() {
  const sqliteDb = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      console.error('خطأ في الاتصال بقاعدة البيانات:', err.message);
    } else {
      console.log(`تم الاتصال بقاعدة بيانات SQLite بنجاح: ${dbPath}`);
    }
  });
  return {
    get(query, params, callback) {
      if (typeof params === 'function') {
        callback = params;
        params = [];
      }
      sqliteDb.get(query, params || [], callback || (() => {}));
    },
    all(query, params, callback) {
      if (typeof params === 'function') {
        callback = params;
        params = [];
      }
      sqliteDb.all(query, params || [], callback || (() => {}));
    },
    run(query, params, callback) {
      if (typeof params === 'function') {
        callback = params;
        params = [];
      }
      sqliteDb.run(query, params || [], callback || (() => {}));
    },
    serialize(callback) {
      sqliteDb.serialize(callback);
    },
    close() {
      return new Promise((resolve, reject) => sqliteDb.close((err) => err ? reject(err) : resolve()));
    },
  };
}

let dbMode = DATABASE_URL ? 'postgres' : 'sqlite';

app.use(cors({
  origin(origin, callback) {
    if (!IS_PRODUCTION || !origin || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origin غير مسموح به'));
  },
}));
app.use(express.json({ limit: '10mb' }));

function productionRateLimit(req, res, next) {
  if (!IS_PRODUCTION) return next();
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const bucket = requestBuckets.get(key);
  if (!bucket || now - bucket.startedAt >= 60_000) {
    requestBuckets.set(key, { startedAt: now, count: 1 });
    return next();
  }
  bucket.count += 1;
  if (bucket.count > 120) {
    return res.status(429).json({ error: 'طلبات كثيرة، حاول بعد دقيقة' });
  }
  return next();
}

app.use(productionRateLimit);

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

function getRequestApiKey(req) {
  const directKey = req.get('x-sync-api-key') || req.get('x-api-key') || '';
  if (directKey) return directKey;

  const authHeader = req.get('authorization') || '';
  if (authHeader.toLowerCase().startsWith('bearer ')) {
    return authHeader.slice(7).trim();
  }

  return '';
}

function requireSyncAuthorization(req, res, next) {
  if (!SYNC_API_KEY) {
    if (IS_PRODUCTION) {
      return res.status(503).json({ error: 'SYNC_API_KEY غير مضبوط على الخادم' });
    }
    return next();
  }

  const receivedKey = getRequestApiKey(req);
  if (!secureKeyEquals(receivedKey, SYNC_API_KEY)) {
    return res.status(401).json({ error: 'طلب المزامنة غير مصرح به', expected_header: 'x-sync-api-key' });
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

function normalizeLicenseType(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === 'team' || raw === 'owner_team' || raw === 'multi_user' || raw === 'multi-user' || raw === 'owner-team') {
    return 'owner_team';
  }
  if (raw === 'single' || raw === 'owner_single' || raw === 'single_device' || raw === 'owner-single' || raw === 'owner_single_device') {
    return 'owner_single';
  }
  return 'owner_single';
}

function parseBoolean(value) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
    if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  }
  return Boolean(value);
}

function generateSessionToken() {
  return `sess_${crypto.randomBytes(32).toString('hex')}`;
}

function hashPin(pin, salt) {
  return crypto.createHash('sha256').update(`${salt}:${pin}`).digest('hex');
}

function requireAuth(req, res, next) {
  const token = req.get('x-auth-token');
  if (!token) {
    return res.status(401).json({ error: 'جلسة المستخدم غير مسجلة' });
  }

  db.get(
    `SELECT * FROM auth_sessions WHERE token = ? AND revokedAt IS NULL AND expiresAt > ? LIMIT 1`,
    [token, new Date().toISOString()],
    (err, session) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!session) return res.status(401).json({ error: 'انتهت صلاحية الجلسة أو تم إبطالها' });

      const requestDeviceId = req.get('x-device-id') || req.body?.device_id || null;
      if (requestDeviceId && session.device_id !== requestDeviceId) {
        return res.status(403).json({ error: 'الجهاز غير مصرح له بهذه الجلسة' });
      }

      req.user = {
        id: session.user_id,
        shopId: session.shop_id,
        role: session.role,
        deviceId: session.device_id,
      };
      return next();
    },
  );
}

const dbDir = process.env.DB_PATH ? path.dirname(process.env.DB_PATH) : './data';
const dbPath = process.env.DB_PATH || path.join(dbDir, 'smart_accountant.db');

if (!fs.existsSync(dbDir) && dbDir !== '.' && dbDir !== './') {
  fs.mkdirSync(dbDir, { recursive: true });
}

let db = DATABASE_URL ? createPostgresDbAdapter() : createSqliteDbAdapter();

function dbGet(query, params = []) {
  return new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => err ? reject(err) : resolve(row || null));
  });
}

function dbAll(query, params = []) {
  return new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => err ? reject(err) : resolve(rows || []));
  });
}

function dbRun(query, params = []) {
  return new Promise((resolve, reject) => {
    db.run(query, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this?.lastID ?? null, changes: this?.changes ?? 0 });
    });
  });
}

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
  if (copy.shop_code !== undefined) {
    copy.shopCode = copy.shop_code;
    delete copy.shop_code;
  }
  if (copy.owner_name !== undefined) {
    copy.ownerName = copy.owner_name;
    delete copy.owner_name;
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
  stock_movements: ['id', 'device_id', 'shop_id', 'user_id', 'productId', 'type', 'quantity', 'quantityBefore', 'quantityAfter', 'reason', 'referenceId', 'createdAt'],
  account_ledger: ['id', 'device_id', 'shop_id', 'user_id', 'customerName', 'amount', 'type', 'date', 'details', 'invoiceNumber', 'invoiceId', 'receiptNumber', 'source', 'currency'],
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
  delete item.client_tx_id;
  delete item.clientTxId;
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

function markProcessedClientTx(clientTxId, shopId, tableName) {
  if (!clientTxId) return Promise.resolve(false);
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT 1 FROM processed_client_txns WHERE client_tx_id = ? LIMIT 1',
      [clientTxId],
      (selectErr, existing) => {
        if (selectErr) return reject(selectErr);
        if (existing) return resolve(true);
        db.run(
          'INSERT INTO processed_client_txns (client_tx_id, shop_id, table_name, createdAt) VALUES (?, ?, ?, ?)',
          [clientTxId, shopId || null, tableName, new Date().toISOString()],
          (insertErr) => (insertErr ? reject(insertErr) : resolve(false)),
        );
      },
    );
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

  return Promise.all(records.map(async (record) => {
    const item = normalizeTableRecord(tableName, record, deviceId, shopId, userId);
    const clientTxId = item.client_tx_id || item.clientTxId || null;
    if (clientTxId) {
      const duplicate = await markProcessedClientTx(clientTxId, shopId, tableName);
      if (duplicate) {
        return null;
      }
    }

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
      let changedSince = '(updatedAt > ? OR createdAt > ?)';
      if (tableName === 'audit_logs') {
        changedSince = 'createdAt > ?';
      } else if (tableName === 'stock_movements') {
        changedSince = 'createdAt > ?';
      } else if (tableName === 'account_ledger') {
        changedSince = 'date > ?';
      } else if ([
        'customers',
        'suppliers',
        'products',
        'invoices',
        'expenses',
        'vouchers',
      ].includes(tableName)) {
        changedSince = '(updatedAt > ? OR createdAt > ? OR deletedAt > ?)';
      }
      query += query.includes(' WHERE ') ? ` AND ${changedSince}` : ` WHERE ${changedSince}`;
      if (['audit_logs', 'stock_movements', 'account_ledger'].includes(tableName)) {
        params.push(lastSync);
      } else if ([
        'customers',
        'suppliers',
        'products',
        'invoices',
        'expenses',
        'vouchers',
      ].includes(tableName)) {
        params.push(lastSync, lastSync, lastSync);
      } else {
        params.push(lastSync, lastSync);
      }
    }

    db.all(query, params, (err, rows) => {
      if (err) return reject(err);
      resolve((rows || []).map((row) => serializeRow(row)));
    });
  });
}

function createSchemaSqlite() {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS licenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      status TEXT DEFAULT 'active',
      license_type TEXT DEFAULT 'owner_single',
      device_id TEXT,
      shop_id TEXT,
      owner_user_id TEXT,
      client_name TEXT,
      notes TEXT,
      allow_multiple_users INTEGER DEFAULT 0,
      allow_staff_access INTEGER DEFAULT 0,
      max_staff_users INTEGER DEFAULT 0,
      bound_user_id TEXT,
      expires_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      activated_at DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS license_staff_users (
      id TEXT PRIMARY KEY,
      license_id INTEGER NOT NULL,
      user_id TEXT NOT NULL,
      shop_id TEXT NOT NULL,
      status TEXT DEFAULT 'active',
      granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(license_id, user_id, shop_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS trial_devices (
      device_id TEXT PRIMARY KEY,
      started_at DATETIME NOT NULL,
      expires_at DATETIME NOT NULL,
      createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`);

    for (const column of [
      ['license_type', 'TEXT DEFAULT "owner_single"'],
      ['client_name', 'TEXT'],
      ['notes', 'TEXT'],
      ['shop_id', 'TEXT'],
      ['owner_user_id', 'TEXT'],
      ['allow_multiple_users', 'INTEGER DEFAULT 0'],
      ['allow_staff_access', 'INTEGER DEFAULT 0'],
      ['max_staff_users', 'INTEGER DEFAULT 0'],
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
      user_id TEXT,
      pin_salt TEXT,
      pin_hash TEXT
    )`);
    db.run(`ALTER TABLE users ADD COLUMN user_code TEXT`, () => {});
    db.run(`ALTER TABLE users ADD COLUMN pin_salt TEXT`, () => {});
    db.run(`ALTER TABLE users ADD COLUMN pin_hash TEXT`, () => {});

    db.run(`CREATE TABLE IF NOT EXISTS auth_sessions (
      id TEXT PRIMARY KEY,
      token TEXT UNIQUE NOT NULL,
      user_id TEXT NOT NULL,
      shop_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      role TEXT NOT NULL,
      createdAt DATETIME NOT NULL,
      expiresAt DATETIME NOT NULL,
      revokedAt DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS user_devices (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      shop_id TEXT NOT NULL,
      last_seen DATETIME,
      createdAt DATETIME NOT NULL,
      UNIQUE(user_id, device_id)
    )`);

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
      category TEXT,
      amount REAL,
      paymentMethod TEXT,
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
      reference TEXT,
      amount REAL,
      status TEXT,
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
    db.run(`CREATE TABLE IF NOT EXISTS stock_movements (
      id TEXT PRIMARY KEY, device_id TEXT, shop_id TEXT, user_id TEXT,
      productId TEXT, type TEXT, quantity REAL, quantityBefore REAL,
      quantityAfter REAL, reason TEXT, referenceId TEXT, createdAt DATETIME
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS account_ledger (
      id TEXT PRIMARY KEY, device_id TEXT, shop_id TEXT, user_id TEXT,
      customerName TEXT, amount REAL, type TEXT, date DATETIME, details TEXT,
      invoiceNumber TEXT, invoiceId TEXT, receiptNumber TEXT, source TEXT,
      currency TEXT
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

    db.run(`CREATE TABLE IF NOT EXISTS processed_client_txns (
      client_tx_id TEXT PRIMARY KEY,
      shop_id TEXT,
      table_name TEXT,
      createdAt DATETIME NOT NULL
    )`);
  });
}

async function createSchemaPostgres() {
  const statements = [
    `CREATE TABLE IF NOT EXISTS licenses (
      id BIGSERIAL PRIMARY KEY,
      key TEXT UNIQUE NOT NULL,
      status TEXT DEFAULT 'active',
      license_type TEXT DEFAULT 'owner_single',
      device_id TEXT,
      shop_id TEXT,
      owner_user_id TEXT,
      client_name TEXT,
      notes TEXT,
      allow_multiple_users INTEGER DEFAULT 0,
      allow_staff_access INTEGER DEFAULT 0,
      max_staff_users INTEGER DEFAULT 0,
      bound_user_id TEXT,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      activated_at TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS license_staff_users (
      id TEXT PRIMARY KEY,
      license_id BIGINT NOT NULL,
      user_id TEXT NOT NULL,
      shop_id TEXT NOT NULL,
      status TEXT DEFAULT 'active',
      granted_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(license_id, user_id, shop_id)
    )`,
    `CREATE TABLE IF NOT EXISTS trial_devices (
      device_id TEXT PRIMARY KEY,
      started_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      createdAt TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`,
    `CREATE TABLE IF NOT EXISTS shops (
      id TEXT PRIMARY KEY,
      shop_code TEXT,
      name TEXT,
      owner_id TEXT,
      owner_name TEXT,
      phone TEXT,
      currency TEXT DEFAULT 'SAR',
      country TEXT DEFAULT 'SA',
      createdAt TIMESTAMPTZ,
      updatedAt TIMESTAMPTZ,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      shop_id TEXT,
      user_code TEXT,
      email TEXT,
      name TEXT,
      role TEXT DEFAULT 'owner',
      status TEXT DEFAULT 'active',
      createdAt TIMESTAMPTZ,
      updatedAt TIMESTAMPTZ,
      device_id TEXT,
      user_id TEXT,
      pin_salt TEXT,
      pin_hash TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS auth_sessions (
      id TEXT PRIMARY KEY,
      token TEXT UNIQUE NOT NULL,
      user_id TEXT NOT NULL,
      shop_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      role TEXT NOT NULL,
      createdAt TIMESTAMPTZ NOT NULL,
      expiresAt TIMESTAMPTZ NOT NULL,
      revokedAt TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS user_devices (
      id TEXT PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      last_seen TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, device_id)
    )`,
    `CREATE TABLE IF NOT EXISTS roles (
      id TEXT PRIMARY KEY,
      shop_id TEXT,
      name TEXT,
      permissions TEXT,
      createdAt TIMESTAMPTZ,
      updatedAt TIMESTAMPTZ,
      device_id TEXT,
      user_id TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      name TEXT,
      phone TEXT,
      address TEXT,
      openingBalance DOUBLE PRECISION,
      balance DOUBLE PRECISION,
      creditLimit DOUBLE PRECISION,
      notes TEXT,
      createdAt TIMESTAMPTZ,
      updatedAt TIMESTAMPTZ,
      deletedAt TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS suppliers (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      name TEXT,
      phone TEXT,
      address TEXT,
      openingBalance DOUBLE PRECISION,
      balance DOUBLE PRECISION,
      creditLimit DOUBLE PRECISION,
      notes TEXT,
      createdAt TIMESTAMPTZ,
      updatedAt TIMESTAMPTZ,
      deletedAt TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      name TEXT,
      barcode TEXT,
      sku TEXT,
      buyPrice DOUBLE PRECISION,
      sellPrice DOUBLE PRECISION,
      quantity DOUBLE PRECISION,
      minQuantity DOUBLE PRECISION,
      category TEXT,
      unit TEXT,
      notes TEXT,
      supplierId TEXT,
      expiryDate TIMESTAMPTZ,
      createdAt TIMESTAMPTZ,
      updatedAt TIMESTAMPTZ,
      deletedAt TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS invoices (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      number TEXT,
      type TEXT,
      partyId TEXT,
      partyName TEXT,
      taxRate DOUBLE PRECISION,
      paidAmount DOUBLE PRECISION,
      paymentMethod TEXT,
      notes TEXT,
      createdAt TIMESTAMPTZ,
      updatedAt TIMESTAMPTZ,
      lines TEXT,
      deletedAt TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS expenses (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      category TEXT,
      amount DOUBLE PRECISION,
      paymentMethod TEXT,
      notes TEXT,
      createdAt TIMESTAMPTZ,
      updatedAt TIMESTAMPTZ,
      deletedAt TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS vouchers (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      number TEXT,
      type TEXT,
      reference TEXT,
      amount DOUBLE PRECISION,
      status TEXT,
      notes TEXT,
      createdAt TIMESTAMPTZ,
      updatedAt TIMESTAMPTZ,
      deletedAt TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS sync_queue (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      table_name TEXT,
      action TEXT,
      payload TEXT,
      status TEXT DEFAULT 'pending',
      createdAt TIMESTAMPTZ,
      updatedAt TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      shop_id TEXT,
      user_id TEXT,
      entity TEXT,
      entity_id TEXT,
      action TEXT,
      details JSONB,
      createdAt TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS stock_movements (
      id TEXT PRIMARY KEY, device_id TEXT, shop_id TEXT, user_id TEXT,
      productId TEXT, type TEXT, quantity DOUBLE PRECISION,
      quantityBefore DOUBLE PRECISION, quantityAfter DOUBLE PRECISION,
      reason TEXT, referenceId TEXT, createdAt TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS account_ledger (
      id TEXT PRIMARY KEY, device_id TEXT, shop_id TEXT, user_id TEXT,
      customerName TEXT, amount DOUBLE PRECISION, type TEXT, date TIMESTAMPTZ,
      details TEXT, invoiceNumber TEXT, invoiceId TEXT, receiptNumber TEXT,
      source TEXT, currency TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS sync_conflicts (
      id TEXT PRIMARY KEY,
      table_name TEXT NOT NULL,
      record_id TEXT NOT NULL,
      incoming_device_id TEXT,
      existing_device_id TEXT,
      incoming_updatedAt TIMESTAMPTZ,
      existing_updatedAt TIMESTAMPTZ,
      resolution TEXT NOT NULL,
      createdAt TIMESTAMPTZ NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS processed_client_txns (
      client_tx_id TEXT PRIMARY KEY,
      shop_id TEXT,
      table_name TEXT,
      createdAt TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  ];

  for (const statement of statements) {
    await dbRun(statement);
  }

  const alterStatements = [
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS license_type TEXT DEFAULT 'owner_single'`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS client_name TEXT`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS notes TEXT`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS shop_id TEXT`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS owner_user_id TEXT`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS allow_multiple_users INTEGER DEFAULT 0`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS allow_staff_access INTEGER DEFAULT 0`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS max_staff_users INTEGER DEFAULT 0`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS bound_user_id TEXT`,
    `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`,
    `ALTER TABLE shops ADD COLUMN IF NOT EXISTS shop_code TEXT`,
    `ALTER TABLE shops ADD COLUMN IF NOT EXISTS owner_name TEXT`,
    `ALTER TABLE shops ADD COLUMN IF NOT EXISTS phone TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS user_code TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_salt TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_hash TEXT`
  ];

  for (const statement of alterStatements) {
    try {
      await dbRun(statement);
    } catch (error) {
      console.warn('Migration warning:', error.message);
    }
  }
}

async function initializeDatabase() {
  if (dbMode === 'postgres') {
    try {
      await dbGet('SELECT 1');
      await createSchemaPostgres();
      dbReady = true;
      dbHealthError = null;
      console.log('PostgreSQL connected and schema initialized');
      return;
    } catch (error) {
      dbReady = false;
      dbHealthError = error.code === 'ENETUNREACH'
        ? `${error.message}; Supabase direct host is IPv6-only from this network. Use the Supabase Transaction Pooler URL on port 6543.`
        : error.message;
      console.error('PostgreSQL connection/schema initialization failed:', error.message);
      return;
    }
  }

  createSchemaSqlite();
  dbReady = true;
  dbHealthError = null;
  console.log('📁 تم التشغيل باستخدام SQLite المحلي');
}

app.get('/health', (req, res) => {
  const response = {
    status: dbReady ? 'ok' : 'error',
    message: 'Cloud Sync backend is running',
    version: '2.7.0',
    database_mode: process.env.DATABASE_URL ? 'postgres' : 'sqlite',
    database: process.env.DATABASE_URL ? 'postgresql' : 'data/smart_accountant.db',
    timestamp: new Date().toISOString(),
  };
  if (dbHealthError) response.database_error = dbHealthError;
  return res.status(dbReady ? 200 : 503).json(response);
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
      FROM users WHERE shop_id = ? ORDER BY name`,
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

app.get('/shops/:shopId/sync', requireSyncAuthorization, async (req, res) => {
  const shopId = String(req.params.shopId || '').trim();
  const since = String(req.query.since || '').trim();

  if (!shopId) {
    return res.status(400).json({ error: 'shopId مطلوب' });
  }

  try {
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
      'stock_movements',
      'account_ledger',
    ];

    const data = {};
    for (const tableName of tablesToSync) {
      data[tableName] = await fetchTable(tableName, shopId, null, since);
    }

    res.json({
      success: true,
      server_time: new Date().toISOString(),
      since: since || null,
      data,
    });
  } catch (error) {
    console.error('delta sync failed:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/shops/:shopId/bootstrap', requireSyncAuthorization, async (req, res) => {
  const shopId = String(req.params.shopId || '').trim();
  if (!shopId) {
    return res.status(400).json({ error: 'shopId مطلوب' });
  }

  try {
    const [shop, users, customers, suppliers, products, invoices, expenses, vouchers, roles, auditLogs, stockMovements, accountLedger] = await Promise.all([
      new Promise((resolve, reject) => {
        db.get('SELECT * FROM shops WHERE id = ? LIMIT 1', [shopId], (err, row) => err ? reject(err) : resolve(row ? serializeRow(row) : null));
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM users WHERE shop_id = ? ORDER BY name', [shopId], (err, rows) => err ? reject(err) : resolve((rows || []).map((row) => serializeRow(row))));
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM customers WHERE shop_id = ? ORDER BY updatedAt DESC', [shopId], (err, rows) => err ? reject(err) : resolve((rows || []).map((row) => serializeRow(row))));
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM suppliers WHERE shop_id = ? ORDER BY updatedAt DESC', [shopId], (err, rows) => err ? reject(err) : resolve((rows || []).map((row) => serializeRow(row))));
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM products WHERE shop_id = ? ORDER BY updatedAt DESC', [shopId], (err, rows) => err ? reject(err) : resolve((rows || []).map((row) => serializeRow(row))));
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM invoices WHERE shop_id = ? ORDER BY updatedAt DESC', [shopId], (err, rows) => err ? reject(err) : resolve((rows || []).map((row) => serializeRow(row))));
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM expenses WHERE shop_id = ? ORDER BY updatedAt DESC', [shopId], (err, rows) => err ? reject(err) : resolve((rows || []).map((row) => serializeRow(row))));
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM vouchers WHERE shop_id = ? ORDER BY updatedAt DESC', [shopId], (err, rows) => err ? reject(err) : resolve((rows || []).map((row) => serializeRow(row))));
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM roles WHERE shop_id = ? ORDER BY updatedAt DESC', [shopId], (err, rows) => err ? reject(err) : resolve((rows || []).map((row) => serializeRow(row))));
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM audit_logs WHERE shop_id = ? ORDER BY createdAt DESC', [shopId], (err, rows) => err ? reject(err) : resolve((rows || []).map((row) => serializeRow(row))));
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM stock_movements WHERE shop_id = ? ORDER BY createdAt DESC', [shopId], (err, rows) => err ? reject(err) : resolve((rows || []).map((row) => serializeRow(row))));
      }),
      new Promise((resolve, reject) => {
        db.all('SELECT * FROM account_ledger WHERE shop_id = ? ORDER BY date DESC', [shopId], (err, rows) => err ? reject(err) : resolve((rows || []).map((row) => serializeRow(row))));
      }),
    ]);

    res.json({
      success: true,
      shop,
      users,
      customers,
      suppliers,
      products,
      invoices,
      expenses,
      vouchers,
      roles,
      audit_logs: auditLogs,
      stock_movements: stockMovements,
      account_ledger: accountLedger,
    });
  } catch (error) {
    console.error('bootstrap failed:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    message: 'DrarTech Smart Accountant Backend',
    version: '2.7.0',
    endpoints: ['/generate', '/verify', '/stats', '/sync', '/health'],
  });
});

app.get(['/admin', '/admin/'], (req, res) => {
  const dashboardFiles = [
    path.join(__dirname, 'Drartech-Secure-License-Manager.html'),
    path.join(__dirname, '..', 'Drartech-Secure-License-Manager.html'),
  ];
  const dashboardFile = dashboardFiles.find((file) => fs.existsSync(file));
  if (!dashboardFile) {
    return res.status(500).send('Admin dashboard file is missing from the deployment.');
  }
  return res.sendFile(dashboardFile);
});

app.get(['/admin/database', '/admin/database/'], (req, res) => {
  const databaseDashboard = [
    path.join(__dirname, 'public', 'admin', 'database.html'),
    path.join(__dirname, '..', 'public', 'admin', 'database.html'),
  ].find((file) => fs.existsSync(file));
  if (!databaseDashboard) {
    return res.status(500).send('Database dashboard file is missing from the deployment.');
  }
  return res.sendFile(databaseDashboard);
});

app.get('/admin-check', requireAdminAuthorization, (req, res) => {
  res.json({ success: true, admin: true });
});

const adminDatabaseTables = [
  'audit_logs', 'auth_sessions', 'customers', 'expenses', 'invoices',
  'license_staff_users', 'licenses', 'processed_client_txns', 'products',
  'roles', 'shops', 'suppliers', 'sync_conflicts', 'sync_queue',
  'trial_devices', 'user_devices', 'users', 'vouchers',
];

function requireDatabaseAdmin(req, res, next) {
  return requireAdminAuthorization(req, res, () => {
    if (req.get('x-auth-token')) {
      return requireAuth(req, res, () => {
        if (req.user?.role !== 'owner') {
          return res.status(403).json({ error: 'صلاحية المالك مطلوبة' });
        }
        return next();
      });
    }
    return next();
  });
}

function databaseQuery(query, params = []) {
  return new Promise((resolve, reject) => {
    db.all(query, params, (error, rows) => error ? reject(error) : resolve(rows || []));
  });
}

function databaseOne(query, params = []) {
  return new Promise((resolve, reject) => {
    db.get(query, params, (error, row) => error ? reject(error) : resolve(row || null));
  });
}

app.get('/admin/db/stats', requireDatabaseAdmin, async (req, res) => {
  try {
    const tables = [];
    for (const tableName of adminDatabaseTables) {
      let columns = 0;
      let rows = 0;
      let sizeBytes = null;

      if (dbMode === 'postgres') {
        const columnRow = await databaseOne(
          `SELECT COUNT(*)::int AS count FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = ?`,
          [tableName],
        );
        const countRow = await databaseOne(`SELECT COUNT(*)::bigint AS count FROM "${tableName}"`);
        const sizeRow = await databaseOne(
          `SELECT pg_total_relation_size('public."${tableName}"')::bigint AS bytes`,
        );
        columns = Number(columnRow?.count || 0);
        rows = Number(countRow?.count || 0);
        sizeBytes = Number(sizeRow?.bytes || 0);
      } else {
        const columnRows = await databaseQuery(`PRAGMA table_info("${tableName}")`);
        const countRow = await databaseOne(`SELECT COUNT(*) AS count FROM "${tableName}"`);
        columns = columnRows.length;
        rows = Number(countRow?.count || 0);
      }

      tables.push({ table: tableName, columns, rows_estimated: rows, size_bytes: sizeBytes });
    }
    return res.json({ database_mode: dbMode, tables });
  } catch (error) {
    console.error('admin database stats failed:', error.message);
    return res.status(500).json({ error: 'تعذر قراءة إحصاءات قاعدة البيانات' });
  }
});

app.get('/admin/db/users', requireDatabaseAdmin, async (req, res) => {
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const pageSize = Math.min(100, Math.max(1, Number.parseInt(req.query.page_size, 10) || 25));
  const search = String(req.query.search || '').trim();
  const offset = (page - 1) * pageSize;
  const searchParams = search ? [`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`] : [];
  const where = search ? 'WHERE users.name ILIKE ? OR shops.phone ILIKE ? OR users.email ILIKE ? OR users.user_code ILIKE ? OR users.user_id::text ILIKE ?' : '';
  const sqliteWhere = search ? 'WHERE users.name LIKE ? OR shops.phone LIKE ? OR users.email LIKE ? OR users.user_code LIKE ? OR users.user_id LIKE ?' : '';
  const queryWhere = dbMode === 'postgres' ? where : sqliteWhere;

  try {
    const countRow = await databaseOne(
      `SELECT COUNT(*) AS count FROM users LEFT JOIN shops ON shops.id = users.shop_id ${queryWhere}`,
      searchParams,
    );
    const users = await databaseQuery(
      `SELECT users.*, shops.phone AS shop_phone
         FROM users LEFT JOIN shops ON shops.id = users.shop_id
         ${queryWhere} ORDER BY users.createdAt DESC LIMIT ? OFFSET ?`,
      [...searchParams, pageSize, offset],
    );
    const safeUsers = users.map((user) => {
      const { pin_hash, pin_salt, password_hash, password, ...rest } = user;
      return {
        id: rest.id || '',
        name: rest.name || '',
        email: rest.email || '',
        phone: rest.shop_phone || rest.phone || '',
        user_number: rest.user_number || rest.number || rest.user_code || rest.code || '',
        role: rest.role || '',
        shop_id: rest.shop_id || '',
        user_id: rest.user_id || rest.id || '',
        createdat: rest.createdat || rest.created_at || rest.createdAt || '',
      };
    });
    return res.json({
      page,
      page_size: pageSize,
      total: Number(countRow?.count || 0),
      users: safeUsers,
    });
  } catch (error) {
    console.error('admin database users failed:', error.message);
    return res.status(500).json({ error: 'تعذر قراءة المستخدمين' });
  }
});

app.get('/admin/db/shops', requireDatabaseAdmin, async (req, res) => {
  try {
    const shops = await databaseQuery(
      `SELECT DISTINCT shops.id, shops.shop_code, shops.name, shops.owner_name, shops.phone
         FROM shops LEFT JOIN users ON users.shop_id = shops.id
        WHERE users.id IS NOT NULL OR shops.owner_id IS NOT NULL
        ORDER BY shops.name`,
    );
    return res.json({ shops });
  } catch (error) {
    console.error('admin database shops failed:', error.message);
    return res.status(500).json({ error: 'تعذر قراءة المحلات' });
  }
});

async function ensureInitialOwnerSeed({ shop_id, user_code, email, device_id, pin }) {
  const userCount = await dbGet('SELECT COUNT(*) AS total FROM users');
  if (!userCount || Number(userCount.total || 0) > 0) return null;

  const now = new Date().toISOString();
  const normalizedShopId = String(shop_id || '').trim() || uuidv4();
  const normalizedUserCode = String(user_code || '').trim() || String(Date.now()).slice(-8);
  const normalizedEmail = String(email || '').trim().toLowerCase() || 'owner@local.test';
  const normalizedName = String(email || '').split('@')[0] || 'Owner';
  const ownerId = uuidv4();
  const salt = crypto.randomBytes(16).toString('hex');

  const existingShop = await dbGet('SELECT id FROM shops WHERE id = ? LIMIT 1', [normalizedShopId]);
  if (!existingShop) {
    await dbRun(
      `INSERT INTO shops (id, shop_code, name, owner_id, owner_name, phone, currency, country, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [normalizedShopId, normalizedUserCode.slice(0, 6) || '000000', 'Primary Shop', ownerId, normalizedName, '', 'SAR', 'SA', now, now],
    );
  }

  const pinHash = pin && String(pin).trim() ? hashPin(String(pin).trim(), salt) : null;
  await dbRun(
    `INSERT INTO users (id, shop_id, user_code, email, name, role, status, createdAt, updatedAt, pin_salt, pin_hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [ownerId, normalizedShopId, normalizedUserCode, normalizedEmail, normalizedName, 'owner', 'active', now, now, salt, pinHash],
  );

  return {
    id: ownerId,
    shop_id: normalizedShopId,
    user_code: normalizedUserCode,
    email: normalizedEmail,
    name: normalizedName,
    role: 'owner',
    status: 'active',
  };
}

app.post('/auth/login', requireSyncAuthorization, async (req, res) => {
  const { shop_id, user_code, email, device_id, pin } = req.body || {};
  const normalizedShopId = String(shop_id || '').trim();
  const normalizedUserCode = String(user_code || '').trim();
  const normalizedEmail = String(email || '').trim().toLowerCase();
  const normalizedDeviceId = String(device_id || '').trim();

  if (!normalizedShopId || !normalizedUserCode || !normalizedEmail || !normalizedDeviceId) {
    return res.status(400).json({ success: false, error: 'shop_id و user_code و email و device_id مطلوبة' });
  }

  try {
    let user = await dbGet(
      `SELECT * FROM users WHERE shop_id = ? AND user_code = ? LIMIT 1`,
      [normalizedShopId, normalizedUserCode],
    );

    if (!user) {
      const userCount = await dbGet('SELECT COUNT(*) AS total FROM users');
      const isEmptyDatabase = !userCount || Number(userCount.total || 0) === 0;
      if (isEmptyDatabase) {
        user = await ensureInitialOwnerSeed({
          shop_id: normalizedShopId,
          user_code: normalizedUserCode,
          email: normalizedEmail,
          device_id: normalizedDeviceId,
          pin,
        });
      }
    }

    if (!user) {
      return res.status(401).json({ success: false, error: 'بيانات الدخول غير صحيحة' });
    }

    if ((user.email || '').trim().toLowerCase() !== normalizedEmail) {
      return res.status(401).json({ success: false, error: 'البريد الإلكتروني غير مطابق' });
    }
    if (user.status && user.status !== 'active') {
      return res.status(403).json({ success: false, error: 'هذا الحساب غير نشط' });
    }

    if (user.pin_hash && user.pin_salt) {
      if (!pin || !String(pin).trim()) {
        return res.status(400).json({ success: false, error: 'PIN مطلوب لهذا الحساب' });
      }
      const expectedHash = hashPin(String(pin).trim(), user.pin_salt);
      if (expectedHash !== user.pin_hash) {
        return res.status(401).json({ success: false, error: 'PIN غير صحيح' });
      }
    }

    const token = generateSessionToken();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString();
    const sessionId = uuidv4();

    await dbRun(
      `INSERT INTO auth_sessions (id, token, user_id, shop_id, device_id, role, createdAt, expiresAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [sessionId, token, user.id, user.shop_id || normalizedShopId, normalizedDeviceId, user.role, new Date().toISOString(), expiresAt],
    );

    const deviceSeenAt = new Date().toISOString();
    if (dbMode === 'postgres') {
      await dbRun(
        `INSERT INTO user_devices (user_id, device_id, last_seen, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (user_id, device_id) DO UPDATE
         SET last_seen = EXCLUDED.last_seen`,
        [user.id, normalizedDeviceId, deviceSeenAt, deviceSeenAt],
      );
    } else {
      await dbRun(
        `INSERT OR REPLACE INTO user_devices (id, user_id, device_id, shop_id, last_seen, createdAt)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [uuidv4(), user.id, normalizedDeviceId, normalizedShopId, deviceSeenAt, deviceSeenAt],
      );
    }

    return res.json({
      success: true,
      token,
      expiresAt,
      user: {
        id: user.id,
        shopId: user.shop_id || normalizedShopId,
        userCode: user.user_code,
        email: user.email,
        name: user.name,
        role: user.role,
        status: user.status || 'active',
      },
    });
  } catch (error) {
    console.error('auth login failed:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/auth/me', requireAuth, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.id,
      shopId: req.user.shopId,
      role: req.user.role,
      deviceId: req.user.deviceId,
    },
  });
});

app.post('/auth/logout', requireAuth, (req, res) => {
  db.run(
    `UPDATE auth_sessions SET revokedAt = ? WHERE token = ?`,
    [new Date().toISOString(), req.get('x-auth-token')],
    (err) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      res.json({ success: true });
    },
  );
});

app.get('/stats', requireAdminAuthorization, (req, res) => {
  const todayCreatedCondition = dbMode === 'postgres'
    ? 'DATE(created_at) = CURRENT_DATE'
    : "date(created_at)=date('now')";
  const todayActivatedCondition = dbMode === 'postgres'
    ? 'DATE(activated_at) = CURRENT_DATE'
    : "date(activated_at)=date('now')";

  db.get(`SELECT COUNT(*) as total,
            SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN status='used' THEN 1 ELSE 0 END) as used,
            SUM(CASE WHEN status='banned' THEN 1 ELSE 0 END) as banned,
            SUM(CASE WHEN status='suspended' THEN 1 ELSE 0 END) as suspended,
            SUM(CASE WHEN ${todayCreatedCondition} THEN 1 ELSE 0 END) as today_created,
            SUM(CASE WHEN ${todayActivatedCondition} THEN 1 ELSE 0 END) as today_activated
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

app.post('/generate', requireAdminAuthorization, async (req, res) => {
  const body = req.body || {};
  const deviceId = String(body.device_id || body.deviceId || '').trim();
  const clientName = String(body.client_name || body.clientName || '').trim() || null;
  const notes = String(body.notes || '').trim() || null;
  const expiresAt = String(body.expires_at || body.expiresAt || '').trim() || null;
  const licenseType = normalizeLicenseType(body.license_type || body.licenseType || body.type || (body.allow_multiple_users || body.multi_user ? 'owner_team' : 'owner_single'));
  const ownerUserId = String(body.owner_user_id || body.ownerUserId || '').trim() || null;
  const shopId = String(body.shop_id || body.shopId || '').trim() || null;
  const allowStaffAccess = parseBoolean(body.allow_staff_access ?? body.allowStaffAccess ?? body.allow_multiple_users ?? body.multi_user ?? false);
  const maxStaffUsers = Number(body.max_staff_users ?? body.maxStaffUsers ?? 0);

  if (!deviceId) {
    return res.status(400).json({ error: 'device_id مطلوب لإنشاء ترخيص مرتبط بالجهاز' });
  }

  const existing = await dbGet(
    `SELECT * FROM licenses WHERE device_id = ? AND status != 'banned' LIMIT 1`,
    [deviceId],
  );
  if (existing) {
    return res.json({
      success: true,
      existing: true,
      key: existing.key,
      id: existing.id,
      device_id: existing.device_id,
      license_type: existing.license_type || 'owner_single',
      allow_staff_access: Boolean(existing.allow_staff_access),
      mode: existing.license_type === 'owner_team' ? 'owner-team' : 'owner-single',
    });
  }

  const newKey = `DRAR-${require('crypto').randomBytes(4).toString('hex').toUpperCase()}`;
  const insertResult = await dbRun(
    `INSERT INTO licenses
     (key, status, license_type, device_id, shop_id, owner_user_id, client_name, notes, allow_multiple_users, allow_staff_access, max_staff_users, expires_at)
     VALUES (?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      newKey,
      licenseType,
      deviceId,
      shopId,
      ownerUserId,
      clientName,
      notes,
      licenseType === 'owner_team' ? 1 : 0,
      allowStaffAccess ? 1 : 0,
      Number.isFinite(maxStaffUsers) ? maxStaffUsers : 0,
      expiresAt,
    ],
  );

  return res.json({
    success: true,
    existing: false,
    id: insertResult.lastID,
    key: newKey,
    device_id: deviceId,
    license_type: licenseType,
    owner_user_id: ownerUserId,
    shop_id: shopId,
    allow_multiple_users: licenseType === 'owner_team',
    allow_staff_access: allowStaffAccess,
    max_staff_users: Number.isFinite(maxStaffUsers) ? maxStaffUsers : 0,
    mode: licenseType === 'owner_team' ? 'owner-team' : 'owner-single',
  });
});

app.post('/verify', async (req, res) => {
  const body = req.body || {};
  const key = String(body.key || body.licenseKey || '').trim().toUpperCase();
  const deviceId = String(body.device_id || body.deviceId || '').trim();
  const userId = String(body.user_id || body.userId || '').trim() || null;
  const shopId = String(body.shop_id || body.shopId || '').trim() || null;

  if (!key) return res.status(400).json({ valid: false, error: 'المفتاح مطلوب' });
  if (!deviceId) return res.status(400).json({ valid: false, error: 'معرف الجهاز مطلوب' });

  const row = await dbGet(`SELECT * FROM licenses WHERE key = ?`, [key]).catch(() => null);
  if (!row) return res.json({ valid: false, message: 'المفتاح غير موجود' });
  if (row.status === 'banned') return res.json({ valid: false, message: 'الترخيص محظور', status: row.status });
  if (row.status === 'suspended') return res.json({ valid: false, message: 'الترخيص موقوف مؤقتًا', status: row.status });
  if (row.expires_at && Date.parse(row.expires_at) <= Date.now()) {
    await dbRun(`UPDATE licenses SET status='expired' WHERE id=?`, [row.id]);
    return res.json({ valid: false, message: 'الترخيص منتهي الصلاحية', status: 'expired' });
  }
  if (row.device_id && row.device_id !== deviceId) {
    return res.json({ valid: false, message: 'المفتاح مرتبط بجهاز آخر', requires_device: true, status: row.status });
  }

  const licenseType = normalizeLicenseType(row.license_type || (row.allow_multiple_users ? 'owner_team' : 'owner_single'));
  const isOwner = !!row.owner_user_id && !!userId && row.owner_user_id === userId;
  const isStaffForSameShop = !!row.shop_id && !!shopId && row.shop_id === shopId && !!row.allow_staff_access && !!userId && userId !== row.owner_user_id;

  if (licenseType === 'owner_single') {
    if (row.bound_user_id && userId && row.bound_user_id !== userId) {
      return res.json({ valid: false, message: 'هذا الترخيص مخصص لمستخدم واحد فقط على هذا الجهاز', status: row.status });
    }
    if (row.owner_user_id && !!userId && !isOwner) {
      return res.json({ valid: false, message: 'هذا الترخيص مالك فقط ولا يفتح للمستخدمين الآخرين', status: row.status });
    }
  }

  if (licenseType === 'owner_team') {
    if (!isOwner && !isStaffForSameShop) {
      return res.json({ valid: false, message: 'هذا الترخيص مخصص لمالك المحل أو الموظفين المصرح لهم داخل نفس المحل', status: row.status });
    }

    if (isStaffForSameShop) {
      const maxSeats = Number(row.max_staff_users || 0);
      if (maxSeats > 0) {
        const usedSeats = await dbGet(
          `SELECT COUNT(*) AS total FROM license_staff_users WHERE license_id = ? AND shop_id = ? AND status = 'active'`,
          [row.id, shopId],
        );
        const currentTotal = Number(usedSeats?.total ?? 0);
        const userGranted = await dbGet(
          `SELECT 1 FROM license_staff_users WHERE license_id = ? AND user_id = ? AND shop_id = ? AND status = 'active' LIMIT 1`,
          [row.id, userId, shopId],
        );
        if (currentTotal >= maxSeats && !userGranted) {
          return res.json({ valid: false, message: 'تم الوصول إلى عدد الموظفين المصرح لهم لهذا الترخيص', status: row.status });
        }
        if (!userGranted) {
          await dbRun(
            `INSERT OR IGNORE INTO license_staff_users (id, license_id, user_id, shop_id, status, granted_at)
             VALUES (?, ?, ?, ?, 'active', ?)`,
            [uuidv4(), row.id, userId, shopId, new Date().toISOString()],
          );
        }
      }
    }
  }

  const boundUser = row.bound_user_id || userId || row.owner_user_id || null;
  await dbRun(
    `UPDATE licenses SET status='used', device_id=?, bound_user_id=?, activated_at=COALESCE(activated_at, CURRENT_TIMESTAMP) WHERE id=?`,
    [deviceId, boundUser, row.id],
  );

  return res.json({
    valid: true,
    message: 'مفتاح الترخيص صالح وتم التفعيل بنجاح',
    status: 'used',
    device_id: deviceId,
    license_type: licenseType,
    allow_multiple_users: Boolean(row.allow_multiple_users || (licenseType === 'owner_team')),
    allow_staff_access: Boolean(row.allow_staff_access),
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
  const allowed = ['active', 'used', 'banned', 'suspended', 'expired'];
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
      'stock_movements',
      'account_ledger',
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

initializeDatabase()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 سيرفر Smart Accountant يعمل على المنفذ: ${PORT}`);
      console.log(`🔐 وضع قاعدة البيانات: ${DATABASE_URL ? 'postgres' : 'sqlite'}`);
      console.log(`📁 قاعدة البيانات: ${DATABASE_URL ? 'postgresql' : dbPath}`);
    });
  })
  .catch((error) => {
    console.error('فشل بدء الخادم:', error.message);
    process.exit(1);
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