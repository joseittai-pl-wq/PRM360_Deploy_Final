const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Error handlers for uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

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
      if (err) {
        console.error('Token validation error:', err);
        return res.status(401).json({ error: 'Invalid token' });
      }
      if (!row) {
        return res.status(401).json({ error: 'Token expired or invalid' });
      }
      req.usuario_id = row.usuario_id;
      next();
    }
  );
}

// 1. Login endpoint
app.post('/api/login', (req, res) => {
  const { usuario, password } = req.body;

  db.get(
    'SELECT * FROM usuarios WHERE usuario = ? AND password = ?',
    [usuario, password],
    (err, row) => {
      if (err) {
        console.error('Login error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (!row) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const token = crypto.randomBytes(32).toString('hex');
      const expirationDate = new Date();
      expirationDate.setHours(expirationDate.getHours() + 24);

      db.run(
        'INSERT INTO tokens (usuario_id, token, fecha_expiracion) VALUES (?, ?, ?)',
        [row.id, token, expirationDate.toISOString()],
        (err) => {
          if (err) {
            console.error('Token creation error:', err);
            return res.status(500).json({ error: 'Failed to create token' });
          }

          res.json({
            success: true,
            token: token,
            rol: row.rol,
            usuario: row.usuario,
            nombre: row.nombre
          });
        }
      );
    }
  );
});

// 2. Logout endpoint
app.post('/api/logout', validarToken, (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  db.run(
    'DELETE FROM tokens WHERE token = ?',
    [token],
    (err) => {
      if (err) {
        console.error('Logout error:', err);
        return res.status(500).json({ error: 'Logout failed' });
      }
      res.json({ success: true, message: 'Logged out successfully' });
    }
  );
});

// 3. Create expediente
app.post('/api/expedientes', validarToken, (req, res) => {
  const { numero_expediente, cliente_nombre, tipo_expediente, descripcion } = req.body;

  db.run(
    `INSERT INTO expedientes (usuario_id, numero_expediente, cliente_nombre, tipo_expediente, descripcion)
     VALUES (?, ?, ?, ?, ?)`,
    [req.usuario_id, numero_expediente, cliente_nombre, tipo_expediente, descripcion],
    function(err) {
      if (err) {
        console.error('Create expediente error:', err);
        return res.status(500).json({ error: err.message });
      }
      res.json({ success: true, id: this.lastID });
    }
  );
});

// 4. Get expedientes
app.get('/api/expedientes', validarToken, (req, res) => {
  db.all(
    'SELECT * FROM expedientes WHERE usuario_id = ?',
    [req.usuario_id],
    (err, rows) => {
      if (err) {
        console.error('Get expedientes error:', err);
        return res.status(500).json({ error: err.message });
      }
      res.json(rows);
    }
  );
});

// 5. Get single expediente
app.get('/api/expedientes/:id', validarToken, (req, res) => {
  db.get(
    'SELECT * FROM expedientes WHERE id = ? AND usuario_id = ?',
    [req.params.id, req.usuario_id],
    (err, row) => {
      if (err) {
        console.error('Get expediente error:', err);
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
    [estado, descripcion, req.params.id, req.usuario_id],
    function(err) {
      if (err) {
        console.error('Update expediente error:', err);
        return res.status(500).json({ error: err.message });
      }
      res.json({ success: true, changes: this.changes });
    }
  );
});

// 7. Delete expediente
app.delete('/api/expedientes/:id', validarToken, (req, res) => {
  db.run(
    'DELETE FROM expedientes WHERE id = ? AND usuario_id = ?',
    [req.params.id, req.usuario_id],
    function(err) {
      if (err) {
        console.error('Delete expediente error:', err);
        return res.status(500).json({ error: err.message });
      }
      res.json({ success: true, deleted: this.changes });
    }
  );
});

// 8. Get usuarios
app.get('/api/usuarios', (req, res) => {
  db.all('SELECT id, usuario, nombre, rol FROM usuarios', (err, rows) => {
    if (err) {
      console.error('Get usuarios error:', err);
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// 9. Get auditoria
app.get('/api/auditoria', validarToken, (req, res) => {
  db.all(
    'SELECT * FROM auditoria WHERE usuario_id = ? ORDER BY fecha_cambio DESC LIMIT 100',
    [req.usuario_id],
    (err, rows) => {
      if (err) {
        console.error('Get auditoria error:', err);
        return res.status(500).json({ error: err.message });
      }
      res.json(rows);
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
const server = app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});

// Handle server errors
server.on('error', (err) => {
  console.error('Server error:', err);
  process.exit(1);
});
