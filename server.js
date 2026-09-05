const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// === 1. الحماية: كلمة سر الأدمن ===
// غيرها من متغيرات البيئة في Render: ADMIN_SECRET
const ADMIN_SECRET = process.env.ADMIN_SECRET || "Drar@2026_Secure_736373343";

app.use(cors({
  origin: '*',
  methods: ['GET','POST','DELETE'],
  allowedHeaders: ['Content-Type','x-admin-secret','Authorization']
}));
app.use(express.json());

// === Middleware الحماية ===
function requireAdmin(req, res, next) {
  const secret = req.headers['x-admin-secret'] || req.body?.admin_secret || req.query?.admin_secret;
  if (!secret || secret !== ADMIN_SECRET) {
    return res.status(401).json({ 
      error: 'Unauthorized - Admin secret required',
      message: 'كلمة سر الأدمن غير صحيحة أو مفقودة. أضف Header: x-admin-secret'
    });
  }
  next();
}

// === قاعدة البيانات ===
const dbDir = process.env.DB_PATH ? path.dirname(process.env.DB_PATH) : './data';
const dbPath = process.env.DB_PATH || path.join(dbDir, 'licenses.db');

if (!fs.existsSync(dbDir) && dbDir !== '.' && dbDir !== './') {
    fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('خطأ DB:', err.message);
    else console.log(`✅ DB Connected: ${dbPath} | Admin Secret Set: ${ADMIN_SECRET ? 'YES' : 'NO'}`);
});

db.run(`CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'active',
    device_id TEXT,
    client_name TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    activated_at DATETIME
)`);

// === مسارات عامة (بدون حماية) ===
app.get('/', (req, res) => {
    res.json({ 
        status: 'ok', 
        message: 'DrarTech License Server Running v2.7.1 SECURE',
        version: '2.7.1',
        secure: true,
        endpoints: ['/verify (public)','/admin-check (protected)','/generate (protected)','/bulk-generate (protected)','/licenses (protected)','/stats (protected)']
    });
});

// فحص كلمة سر الأدمن
app.get('/admin-check', requireAdmin, (req, res) => {
    res.json({ success: true, message: 'Admin authenticated ✅' });
});

// === 2. إصلاح ثغرة deviceId vs device_id ===
// نقبل الاثنين معاً
function getDeviceId(body) {
  return body.device_id || body.deviceId || body.deviceID || body.device || null;
}

// مسار التحقق - عام (للتطبيق)
app.post('/verify', (req, res) => {
    const { key } = req.body;
    const device_id = getDeviceId(req.body); // يقبل device_id و deviceId
    
    if (!key) return res.status(400).json({ valid: false, error: 'المفتاح مطلوب' });

    db.get(`SELECT * FROM licenses WHERE key = ?`, [key], (err, row) => {
        if (err) return res.status(500).json({ valid: false, error: 'خطأ DB' });
        if (!row) return res.json({ valid: false, message: 'المفتاح غير موجود' });
        if (row.status === 'banned') return res.json({ valid: false, message: 'المفتاح محظور', status: row.status });
        if (row.status === 'used' && row.device_id && row.device_id !== device_id) {
            return res.json({ valid: false, message: 'المفتاح مستخدم على جهاز آخر', status: row.status, device_id: row.device_id });
        }
        if (row.status !== 'active' && row.status !== 'used') {
            return res.json({ valid: false, message: 'المفتاح غير نشط', status: row.status });
        }
        if (device_id && !row.device_id) {
            db.run(`UPDATE licenses SET status='used', device_id=?, activated_at=CURRENT_TIMESTAMP WHERE key=?`, [device_id, key]);
        } else if (device_id && row.device_id === device_id && row.status === 'active') {
            db.run(`UPDATE licenses SET status='used', activated_at=CURRENT_TIMESTAMP WHERE key=?`, [key]);
        }
        res.json({ valid: true, message: 'المفتاح صالح ✅', status: 'used' });
    });
});

// === مسارات محمية (تحتاج x-admin-secret) ===

// Stats
app.get('/stats', requireAdmin, (req, res) => {
    db.all(`SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as active,
        SUM(CASE WHEN status='used' THEN 1 ELSE 0 END) as used,
        SUM(CASE WHEN status='banned' THEN 1 ELSE 0 END) as banned,
        COUNT(CASE WHEN date(created_at)=date('now') THEN 1 END) as today_created,
        COUNT(CASE WHEN date(activated_at)=date('now') THEN 1 END) as today_activated
        FROM licenses`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const row = rows[0];
        db.all(`SELECT date(created_at) as date, COUNT(*) as count FROM licenses WHERE created_at >= date('now','-7 days') GROUP BY date(created_at) ORDER BY date`, (err2, daily) => {
            res.json({...row, daily: daily || []});
        });
    });
});

// List licenses
app.get('/licenses', requireAdmin, (req, res) => {
    const { search, status, limit = 100, offset = 0 } = req.query;
    let query = `SELECT * FROM licenses WHERE 1=1`;
    let params = [];
    if (search) {
        query += ` AND (key LIKE ? OR device_id LIKE ? OR client_name LIKE ?)`;
        const s = `%${search}%`;
        params.push(s, s, s);
    }
    if (status && status !== 'all') {
        query += ` AND status = ?`;
        params.push(status);
    }
    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    params.push(parseInt(limit), parseInt(offset));
    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        let countQuery = `SELECT COUNT(*) as count FROM licenses WHERE 1=1`;
        let countParams = [];
        if (search) {
            countQuery += ` AND (key LIKE ? OR device_id LIKE ? OR client_name LIKE ?)`;
            const s = `%${search}%`;
            countParams.push(s, s, s);
        }
        if (status && status !== 'all') {
            countQuery += ` AND status = ?`;
            countParams.push(status);
        }
        db.get(countQuery, countParams, (err2, countRow) => {
            res.json({ licenses: rows, total: countRow ? countRow.count : rows.length });
        });
    });
});

// Generate single - محمي
app.post('/generate', requireAdmin, (req, res) => {
    const { client_name, notes } = req.body;
    const newKey = 'DRAR-' + uuidv4().substring(0, 8).toUpperCase();
    db.run(`INSERT INTO licenses (key, client_name, notes) VALUES (?, ?, ?)`, [newKey, client_name || null, notes || null], function(err) {
        if (err) return res.status(500).json({ error: 'فشل توليد المفتاح', details: err.message });
        console.log(`🔑 Generated: ${newKey} for ${client_name || 'unknown'}`);
        res.json({ success: true, key: newKey, id: this.lastID });
    });
});

// Bulk generate - محمي
app.post('/bulk-generate', requireAdmin, (req, res) => {
    const count = Math.min(parseInt(req.body.count) || 5, 100);
    const client_name = req.body.client_name || null;
    let keys = [];
    let stmt = db.prepare(`INSERT INTO licenses (key, client_name) VALUES (?, ?)`);
    let completed = 0;
    let errors = [];
    for (let i = 0; i < count; i++) {
        const newKey = 'DRAR-' + uuidv4().substring(0, 8).toUpperCase();
        keys.push(newKey);
        stmt.run([newKey, client_name], (err) => {
            completed++;
            if (err) errors.push(err.message);
            if (completed === count) {
                stmt.finalize();
                console.log(`🔑 Bulk Generated ${count} keys`);
                res.json({ success: true, count, keys, errors: errors.length ? errors : undefined });
            }
        });
    }
});

// Delete
app.delete('/licenses/:id', requireAdmin, (req, res) => {
    db.run(`DELETE FROM licenses WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deleted: this.changes });
    });
});

app.post('/delete', requireAdmin, (req, res) => {
    const { key, id } = req.body;
    if (!key && !id) return res.status(400).json({ error: 'key or id required' });
    const q = id ? `DELETE FROM licenses WHERE id = ?` : `DELETE FROM licenses WHERE key = ?`;
    const p = id ? id : key;
    db.run(q, [p], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deleted: this.changes });
    });
});

// Update status
app.post('/update-status', requireAdmin, (req, res) => {
    const { id, key, status, client_name, notes } = req.body;
    const device_id = getDeviceId(req.body);
    if (!id && !key) return res.status(400).json({ error: 'id or key required' });
    let updates = [];
    let params = [];
    if (status) { updates.push('status = ?'); params.push(status); }
    if (client_name !== undefined) { updates.push('client_name = ?'); params.push(client_name); }
    if (notes !== undefined) { updates.push('notes = ?'); params.push(notes); }
    if (device_id !== undefined) { updates.push('device_id = ?'); params.push(device_id); }
    if (updates.length === 0) return res.status(400).json({ error: 'no fields to update' });
    let query = `UPDATE licenses SET ${updates.join(', ')} WHERE ${id ? 'id = ?' : 'key = ?'}`;
    params.push(id ? id : key);
    db.run(query, params, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, updated: this.changes });
    });
});

// Reset device
app.post('/reset-device', requireAdmin, (req, res) => {
    const { key, id } = req.body;
    if (!key && !id) return res.status(400).json({ error: 'key or id required' });
    const q = id ? `UPDATE licenses SET device_id = NULL, status='active', activated_at=NULL WHERE id=?` : `UPDATE licenses SET device_id = NULL, status='active', activated_at=NULL WHERE key=?`;
    db.run(q, [id || key], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, reset: this.changes });
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 DrarTech SECURE v2.7.1 running on ${PORT}`);
    console.log(`🔒 Admin Secret: ${ADMIN_SECRET.substring(0,4)}****`);
    console.log(`📁 DB: ${dbPath}`);
});
