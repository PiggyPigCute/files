require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3004;
const PASSWORD_HASH = process.env.PASSWORD_HASH;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

if (!PASSWORD_HASH) {
  console.error('PASSWORD_HASH manquant dans .env — génère-le avec : node hash-password.js tonMotDePasse');
  process.exit(1);
}

const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const DATA_FILE = path.join(DATA_DIR, 'files.json');

for (const dir of [DATA_DIR, UPLOADS_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]');

function readFilesDb() {
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
}
function writeFilesDb(list) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(list, null, 2));
}

const RESERVED_IDS = new Set(['login', 'logout', 'api', 'assets', 'favicon.ico', 'upload']);

app.set('trust proxy', 1); // le site tourne derrière nginx en HTTPS
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
    // maxAge défini dynamiquement à la connexion selon "rester connecté"
  }
}));

app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));

// --- Anti brute-force basique sur le login ---
const loginAttempts = new Map(); // ip -> { count, firstAttempt }
const MAX_ATTEMPTS = 6;
const WINDOW_MS = 15 * 60 * 1000;

function isRateLimited(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry) return false;
  if (Date.now() - entry.firstAttempt > WINDOW_MS) {
    loginAttempts.delete(ip);
    return false;
  }
  return entry.count >= MAX_ATTEMPTS;
}
function recordFailedAttempt(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry || Date.now() - entry.firstAttempt > WINDOW_MS) {
    loginAttempts.set(ip, { count: 1, firstAttempt: Date.now() });
  } else {
    entry.count++;
  }
}
function clearAttempts(ip) {
  loginAttempts.delete(ip);
}

function requireAuth(req, res, next) {
  if (req.session && req.session.loggedIn) return next();
  return res.status(401).json({ error: 'Non authentifié' });
}

// --- Authentification ---
app.post('/api/login', (req, res) => {
  const ip = req.ip;
  if (isRateLimited(ip)) {
    return res.status(429).json({ error: 'Trop de tentatives, réessaie dans quelques minutes' });
  }
  const { password, stayConnected } = req.body || {};
  if (!password || !bcrypt.compareSync(password, PASSWORD_HASH)) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Mot de passe incorrect' });
  }
  clearAttempts(ip);
  req.session.loggedIn = true;
  if (stayConnected) {
    req.session.cookie.maxAge = 365 * 24 * 60 * 60 * 1000; // 1 an
  } // sinon : cookie de session, expire à la fermeture du navigateur
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  res.json({ loggedIn: !!(req.session && req.session.loggedIn) });
});

// --- Liste des fichiers ---
app.get('/api/files', requireAuth, (req, res) => {
  const list = readFilesDb()
    .map(({ id, originalName, size, uploadedAt, mimetype }) => ({ id, originalName, size, uploadedAt, mimetype }))
    .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
  res.json(list);
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 } // 100 Mo
});

app.post('/api/upload', requireAuth, upload.single('file'), (req, res) => {
  try {
    const { id } = req.body;
    if (!id || !/^[a-zA-Z0-9_-]+$/.test(id)) {
      return res.status(400).json({ error: 'ID invalide (lettres, chiffres, - et _ uniquement)' });
    }
    if (RESERVED_IDS.has(id.toLowerCase())) {
      return res.status(400).json({ error: 'Cet ID est réservé, choisis-en un autre' });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'Aucun fichier envoyé' });
    }
    const list = readFilesDb();
    if (list.some(f => f.id === id)) {
      return res.status(409).json({ error: 'Cet ID est déjà utilisé' });
    }

    const ext = path.extname(req.file.originalname);
    const storedName = `${id}${ext}`;
    fs.writeFileSync(path.join(UPLOADS_DIR, storedName), req.file.buffer);

    const entry = {
      id,
      originalName: req.file.originalname,
      storedName,
      mimetype: req.file.mimetype,
      size: req.file.size,
      uploadedAt: new Date().toISOString()
    };
    list.push(entry);
    writeFilesDb(list);
    res.status(201).json({ id: entry.id, originalName: entry.originalName });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur lors de l\'upload' });
  }
});

app.delete('/api/files/:id', requireAuth, (req, res) => {
  const list = readFilesDb();
  const idx = list.findIndex(f => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Introuvable' });
  const [entry] = list.splice(idx, 1);
  writeFilesDb(list);
  const filePath = path.join(UPLOADS_DIR, entry.storedName);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  res.json({ ok: true });
});

// --- Page principale (login + liste, gérés côté client) ---
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Accès direct à un document par son ID : files.ernestie.fr/mon-id ---
app.get('/:id', (req, res) => {
  if (!(req.session && req.session.loggedIn)) {
    return res.redirect(`/?redirect=${encodeURIComponent('/' + req.params.id)}`);
  }
  const list = readFilesDb();
  const entry = list.find(f => f.id === req.params.id);
  if (!entry) return res.status(404).send('Document introuvable');

  const filePath = path.join(UPLOADS_DIR, entry.storedName);
  if (!fs.existsSync(filePath)) return res.status(404).send('Fichier manquant sur le serveur');

  res.setHeader('Content-Type', entry.mimetype || 'application/octet-stream');
  res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(entry.originalName)}"`);
  fs.createReadStream(filePath).pipe(res);
});

app.listen(PORT, () => {
  console.log(`files.ernestie.fr server running on port ${PORT}`);
});
