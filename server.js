const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// إعدادات السيرفر
app.use(cors());
app.use(express.json());

// مسار قاعدة البيانات - يدعم Render Disk
const dbDir = process.env.DB_PATH ? path.dirname(process.env.DB_PATH) : './data';
const dbPath = process.env.DB_PATH || path.join(dbDir, 'licenses.db');

// إنشاء مجلد البيانات إذا لم يكن موجود
if (!fs.existsSync(dbDir) && dbDir !== '.' && dbDir !== './') {
    fs.mkdirSync(dbDir, { recursive: true });
}

// الاتصال بقاعدة بيانات SQLite
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('خطأ في الاتصال بقاعدة البيانات:', err.message);
    } else {
        console.log(`تم الاتصال بقاعدة بيانات SQLite بنجاح: ${dbPath}`);
    }
});

// إنشاء جدول التراخيص إذا لم يكن موجوداً
db.run(`CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'active',
    device_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    activated_at DATETIME
)`);

// مسار الصحة للتأكد السيرفر شغال (مطلوب لـ Render)
app.get('/', (req, res) => {
    res.json({ 
        status: 'ok', 
        message: 'DrarTech License Server Running v2.6.0',
        version: '2.6.0',
        endpoints: ['/generate', '/verify', '/stats']
    });
});

// مسار إحصائيات التراخيص
app.get('/stats', (req, res) => {
    db.get(`SELECT COUNT(*) as total, 
            SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN status='used' THEN 1 ELSE 0 END) as used 
            FROM licenses`, (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row);
    });
});

// مسار لتوليد مفتاح ترخيص جديد
app.post('/generate', (req, res) => {
    const newKey = 'DRAR-' + uuidv4().substring(0, 8).toUpperCase();
    
    db.run(`INSERT INTO licenses (key) VALUES (?)`, [newKey], function(err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'فشل في توليد المفتاح', details: err.message });
        }
        res.json({ success: true, key: newKey, id: this.lastID });
    });
});

// مسار للتحقق من صلاحية المفتاح
app.post('/verify', (req, res) => {
    const { key, device_id } = req.body;
    
    if (!key) {
        return res.status(400).json({ valid: false, error: 'المفتاح مطلوب' });
    }

    db.get(`SELECT * FROM licenses WHERE key = ?`, [key], (err, row) => {
        if (err) {
            return res.status(500).json({ valid: false, error: 'خطأ في قاعدة البيانات' });
        }
        if (!row) {
            return res.json({ valid: false, message: 'المفتاح غير موجود' });
        }
        if (row.status !== 'active') {
            return res.json({ valid: false, message: 'المفتاح مستخدم مسبقاً أو منتهي', status: row.status });
        }

        // تفعيل المفتاح وربطه بالجهاز
        if (device_id) {
            db.run(`UPDATE licenses SET status='used', device_id=?, activated_at=CURRENT_TIMESTAMP WHERE key=?`, [device_id, key]);
        }

        res.json({ valid: true, message: 'المفتاح صالح وتم التفعيل بنجاح ✅' });
    });
});

// تشغيل السيرفر - مهم لـ Render
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 سيرفر التراخيص يعمل على المنفذ: ${PORT}`);
    console.log(`📁 قاعدة البيانات: ${dbPath}`);
});