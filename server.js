const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Database setup
const db = new sqlite3.Database(':memory:', (err) => {
  if (err) {
    console.error('Error opening database:', err);
    process.exit(1);
  }
  console.log('Database initialized successfully');
});

// Initialize database tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nombre TEXT,
    email TEXT,
    rol TEXT DEFAULT 'abogado',
    activo INTEGER DEFAULT 1,
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Expedientes table
  db.run(`CREATE TABLE IF NOT EXISTS expedientes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    numero_expediente TEXT UNIQUE NOT NULL,
    cliente_nombre TEXT NOT NULL,
    tipo_expediente TEXT,
    estado TEXT DEFAULT 'abierto',
    descripcion TEXT,
    fecha_apertura DATETIME DEFAULT CURRENT_TIMESTAMP,
    fecha_cierre DATETIME,
    fecha_actualizacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
  )`);

  // Tokens table
  db.run(`CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    fecha_expiracion DATETIME,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
  )`);

  // Auditoria table
  db.run(`CREATE TABLE IF NOT EXISTS auditoria (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    tipo_accion TEXT,
    tabla_afectada TEXT,
    descripcion TEXT,
    fecha_cambio DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
  )`);

  // Insert default admin user
  const adminPassword = 'P@ssw0rd$eguRA#2026!';
  db.run(`INSERT OR IGNORE INTO usuarios (usuario, password, nombre, rol)
    VALUES ('contador_principal', ?, 'Contador Principal', 'admin')`,
    [adminPassword],
    (err) => {
      if (err) {
        console.error('Error inserting admin user:', err);
      } else {
        console.log('Default admin user created/verified');
      }
    }
  );
});

// Token validation middleware
function validarToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Token required' });
  }

  db.get(
    'SELECT * FROM tokens WHERE token = ? AND fecha_expiracion > datetime("now")',
    [token],
    (err, row) => {
      if (err || !row) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
      req.usuarioId = row.usuario_id;
      next();
    }
  );
}

// API Routes

// 1. Login endpoint
app.post('/api/login', (req, res) => {
  const { usuario, password } = req.body;
  if (!usuario || !password) {
    return res.status(400).json({ error: 'Usuario and password required' });
  }

  db.get(
    'SELECT * FROM usuarios WHERE usuario = ? AND password = ?',
    [usuario, password],
    (err, row) => {
      if (err || !row) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = crypto.randomBytes(32).toString('hex');
      const expirationTime = new Date();
      expirationTime.setHours(expirationTime.getHours() + 24);

      db.run(
        'INSERT INTO tokens (usuario_id, token, fecha_expiracion) VALUES (?, ?, ?)',
        [row.id, token, expirationTime.toISOString()],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Error creating token' });
          }
          res.json({ token, usuario: row.usuario });
        }
      );
    }
  );
});

// 2. Logout endpoint
app.post('/api/logout', validarToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// 3. Create expediente
app.post('/api/expedientes', validarToken, (req, res) => {
  const { numero_expediente, cliente_nombre, tipo_expediente, descripcion } = req.body;

  db.run(
    `INSERT INTO expedientes (usuario_id, numero_expediente, cliente_nombre, tipo_expediente, descripcion)
     VALUES (?, ?, ?, ?, ?)`,
    [req.usuarioId, numero_expediente, cliente_nombre, tipo_expediente, descripcion],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ id: this.lastID, message: 'Expediente created' });
    }
  );
});

// 4. Get expedientes
app.get('/api/expedientes', validarToken, (req, res) => {
  db.all(
    'SELECT * FROM expedientes WHERE usuario_id = ? ORDER BY fecha_apertura DESC',
    [req.usuarioId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(rows || []);
    }
  );
});

// 5. Get expediente by ID
app.get('/api/expedientes/:id', validarToken, (req, res) => {
  db.get(
    'SELECT * FROM expedientes WHERE id = ? AND usuario_id = ?',
    [req.params.id, req.usuarioId],
    (err, row) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (!row) {
        return res.status(404).json({ error: 'Expediente not found' });
      }
      res.json(row);
    }
  );
});

// 6. Update expediente
app.put('/api/expedientes/:id', validarToken, (req, res) => {
  const { estado, descripcion } = req.body;

  db.run(
    `UPDATE expedientes SET estado = ?, descripcion = ?, fecha_actualizacion = datetime('now')
     WHERE id = ? AND usuario_id = ?`,
    [estado, descripcion, req.params.id, req.usuarioId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Expediente updated' });
    }
  );
});

// 7. Delete expediente
app.delete('/api/expedientes/:id', validarToken, (req, res) => {
  db.run(
    'DELETE FROM expedientes WHERE id = ? AND usuario_id = ?',
    [req.params.id, req.usuarioId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Expediente deleted' });
    }
  );
});

// 8. Get usuarios (admin only)
app.get('/api/usuarios', validarToken, (req, res) => {
  db.all(
    'SELECT id, usuario, nombre, rol, activo FROM usuarios',
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(rows || []);
    }
  );
});

// 9. Auditoria
app.get('/api/auditoria', validarToken, (req, res) => {
  db.all(
    `SELECT * FROM auditoria WHERE usuario_id = ? ORDER BY fecha_cambio DESC LIMIT 100`,
    [req.usuarioId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(rows || []);
    }
  );
});

// 10. Serve login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 11. Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});
