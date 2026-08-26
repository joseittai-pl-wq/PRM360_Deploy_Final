const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;
const DB_PATH = process.env.DATABASE_PATH || './prmdb.sqlite';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Database setup
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) console.error('Database error:', err);
  else console.log('Connected to SQLite database');
});

// Initialize database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nombre TEXT,
    email TEXT,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS expedientes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    folio TEXT UNIQUE NOT NULL,
    cliente TEXT NOT NULL,
    estado TEXT NOT NULL,
    monto REAL,
    moneda TEXT DEFAULT 'MXN',
    descripcion TEXT,
    emisor_razon TEXT,
    emisor_rfc TEXT,
    receptor_razon TEXT,
    receptor_rfc TEXT,
    cfdi_uuid TEXT,
    via TEXT,
    semaforo TEXT,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    actualizado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS auditoria (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    accion TEXT NOT NULL,
    tabla TEXT NOT NULL,
    registro_id INTEGER,
    detalles TEXT,
    ip TEXT,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Insert default admin user
  db.run(`INSERT OR IGNORE INTO usuarios (username, password, nombre, email) 
    VALUES (?, ?, ?, ?)`, 
    [process.env.ADMIN_USER || 'contador_principal', 
     process.env.ADMIN_PASS || 'P@ssw0rd$eguRA#2026!',
     'Administrador',
     process.env.ADMIN_EMAIL || 'admin@prm360.com']);
});

// Token storage (in-memory for simplicity)
const tokens = new Map();

// Helper functions
function generateToken() {
  return Math.random().toString(36).substring(2, 34);
}

function logAudit(userId, action, table, recordId, details, ip) {
  db.run(`INSERT INTO auditoria (usuario_id, accion, tabla, registro_id, detalles, ip) 
    VALUES (?, ?, ?, ?, ?, ?)`,
    [userId, action, table, recordId, details, ip]);
}

// Authentication endpoint
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM usuarios WHERE username = ? AND password = ?',
    [username, password],
    (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });

      const token = generateToken();
      tokens.set(token, user.id);
      logAudit(user.id, 'LOGIN', 'usuarios', user.id, 'User logged in', req.ip);
      res.json({ token, user: { id: user.id, username: user.username } });
    });
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-user-token'];
  if (token) tokens.delete(token);
  res.json({ message: 'Logged out' });
});

// Middleware to verify token
function verifyToken(req, res, next) {
  const token = req.headers['x-user-token'];
  if (!token || !tokens.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.userId = tokens.get(token);
  next();
}

// Expedientes endpoints
app.get('/api/expedientes', verifyToken, (req, res) => {
  db.all('SELECT * FROM expedientes WHERE usuario_id = ?', [req.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.post('/api/expedientes', verifyToken, (req, res) => {
  const { folio, cliente, estado, monto, moneda, descripcion } = req.body;
  db.run(
    `INSERT INTO expedientes (usuario_id, folio, cliente, estado, monto, moneda, descripcion) 
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [req.userId, folio, cliente, estado, monto || 0, moneda || 'MXN', descripcion || ''],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      logAudit(req.userId, 'CREATE', 'expedientes', this.lastID, `Created: ${folio}`, req.ip);
      res.json({ id: this.lastID, folio, cliente, estado });
    }
  );
});

app.get('/api/expedientes/:id', verifyToken, (req, res) => {
  db.get('SELECT * FROM expedientes WHERE id = ? AND usuario_id = ?', 
    [req.params.id, req.userId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

app.put('/api/expedientes/:id', verifyToken, (req, res) => {
  const { folio, cliente, estado, monto } = req.body;
  db.run(
    `UPDATE expedientes SET folio=?, cliente=?, estado=?, monto=?, actualizado_en=CURRENT_TIMESTAMP 
     WHERE id=? AND usuario_id=?`,
    [folio, cliente, estado, monto, req.params.id, req.userId],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      logAudit(req.userId, 'UPDATE', 'expedientes', req.params.id, `Updated: ${folio}`, req.ip);
      res.json({ message: 'Updated' });
    }
  );
});

app.delete('/api/expedientes/:id', verifyToken, (req, res) => {
  db.run('DELETE FROM expedientes WHERE id = ? AND usuario_id = ?',
    [req.params.id, req.userId],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      logAudit(req.userId, 'DELETE', 'expedientes', req.params.id, 'Deleted', req.ip);
      res.json({ message: 'Deleted' });
    }
  );
});

// Search and filter endpoints
app.get('/api/expedientes/buscar/folio/:folio', verifyToken, (req, res) => {
  db.get('SELECT * FROM expedientes WHERE folio = ? AND usuario_id = ?',
    [req.params.folio, req.userId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

app.get('/api/expedientes/filtro/estado/:estado', verifyToken, (req, res) => {
  db.all('SELECT * FROM expedientes WHERE estado = ? AND usuario_id = ?',
    [req.params.estado, req.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

// Statistics endpoint
app.get('/api/estadisticas', verifyToken, (req, res) => {
  db.all(
    `SELECT COUNT(*) as total, 
            SUM(CASE WHEN estado='Abierto' THEN 1 ELSE 0 END) as abiertos,
            SUM(CASE WHEN estado='En Revisión' THEN 1 ELSE 0 END) as revision,
            SUM(CASE WHEN estado='Entregado' THEN 1 ELSE 0 END) as entregados
     FROM expedientes WHERE usuario_id = ?`,
    [req.userId],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(row ? row[0] : { total: 0, abiertos: 0, revision: 0, entregados: 0 });
    }
  );
});

// Audit log endpoint
app.get('/api/auditoria', verifyToken, (req, res) => {
  db.all('SELECT * FROM auditoria WHERE usuario_id = ? ORDER BY creado_en DESC LIMIT 100',
    [req.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve web interface
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'consola_enhanced_v2.html'));
});

app.listen(PORT, () => {
  console.log(`PRM360 Server running on port ${PORT}`);
});
