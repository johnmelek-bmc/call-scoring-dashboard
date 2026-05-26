#!/usr/bin/env node
/**
 * Call Scoring — Backend unique (auth + dashboard + données)
 * 
 * Un seul service Render sert tout :
 * - API d'authentification (publique)
 * - Dashboard (nécessite JWT valide)
 * - Données de scoring (nécessite JWT valide)
 * - Upload des données par le pipeline (clé API)
 * 
 * Rien n'est accessible sans authentification.
 * Aucun repo public avec des données sensibles.
 * 
 * Variables d'environnement :
 *   PORT             - Port (défaut: 3001)
 *   JWT_SECRET       - Secret pour les tokens JWT
 *   RESEND_API_KEY   - Clé API Resend (optionnel, valeur par défaut intégrée)
 *   DATA_API_KEY     - Clé API pour le pipeline (upload data)
 *   ALLOWED_ORIGINS  - Origines CORS (séparées par virgules)
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ============================================================
// CONFIG
// ============================================================
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRY = '2h';
const CODE_EXPIRY_MS = 15 * 60 * 1000;
const SALT_ROUNDS = 10;
const DATA_API_KEY = process.env.DATA_API_KEY || '';

const ALLOWED_DOMAINS = ['bymycar', 'cosmobilis', 'gmail'];
const DATA_DIR = __dirname; // stockage local
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const DATA_FILE = path.join(DATA_DIR, 'dashboard-data.json');
const CONFIG_FILE = path.join(DATA_DIR, 'services_config.json');

// Resend (email API — pas de SMTP, pas de ports bloqués)
const RESEND_API_KEY = process.env.RESEND_API_KEY || 're_XcUCq1fC_9ZHLgBZVCpfvcDvRs1Rk5SNj';
const RESEND_CONFIGURED = !!RESEND_API_KEY;
const FROM_EMAIL = 'onboarding@resend.dev'; // email par défaut Resend, les emails arrivent quand même

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',').map(s => s.trim());

// ============================================================
// PERSISTENCE
// ============================================================

let users = [];
let pendingCodes = new Map();

// Dashboard data (loaded in memory)
let dashboardData = null;
let servicesConfig = null;

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
    }
  } catch (err) { console.error('Error loading users:', err.message); }
}

function saveUsers() {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
    return true;
  } catch (err) { console.error('Error saving users:', err.message); return false; }
}

function loadDashboardData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      dashboardData = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
    }
    if (fs.existsSync(CONFIG_FILE)) {
      servicesConfig = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
    }
  } catch (err) { console.error('Error loading dashboard data:', err.message); }
}

function findUser(email) { return users.find(u => u.email === email.toLowerCase()); }

async function addUser(email, passwordHash) {
  users.push({ email: email.toLowerCase(), passwordHash, created_at: new Date().toISOString() });
  return saveUsers();
}

async function updateUserPassword(email, newHash) {
  const idx = users.findIndex(u => u.email === email.toLowerCase());
  if (idx === -1) return false;
  users[idx].passwordHash = newHash;
  users[idx].updated_at = new Date().toISOString();
  return saveUsers();
}

// ============================================================
// EMAIL
// ============================================================

async function sendEmailViaResend(to, code) {
  if (!RESEND_CONFIGURED) {
    console.error('Resend API key not configured');
    return false;
  }
  
  try {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `CallScoring <${FROM_EMAIL}>`,
        to: [to],
        subject: '🔐 CallScoring — Votre code de vérification',
        html: `
          <div style="font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:20px;">
            <h2 style="color:#1d1d1f;font-size:18px;margin-bottom:8px;">Connexion à votre tableau de bord</h2>
            <p style="color:#6e6e73;font-size:14px;margin-bottom:20px;">Voici votre code de vérification :</p>
            <div style="background:#f5f5f7;border-radius:16px;padding:24px;text-align:center;font-size:40px;font-weight:700;letter-spacing:12px;color:#0071e3;font-family:monospace;margin-bottom:20px;">${code}</div>
            <p style="color:#86868b;font-size:13px;">Ce code expire dans <strong>15 minutes</strong>.</p>
            <p style="color:#86868b;font-size:13px;">Si vous n'avez pas demandé cette connexion, ignorez cet email.</p>
            <hr style="border:none;border-top:1px solid #e8e8ed;margin:20px 0;">
            <p style="color:#aeaeb2;font-size:11px;text-align:center;">CallScoring — ByMyCar BDC Dashboard</p>
          </div>`,
      }),
    });
    
    const data = await resp.json();
    if (resp.ok) {
      console.log(`  ✅ Email sent to ${to} via Resend — id: ${data.id}`);
      return true;
    } else {
      console.error(`  ❌ Resend API error: ${resp.status} ${JSON.stringify(data)}`);
      return false;
    }
  } catch (err) {
    console.error('  ❌ Resend request failed:', err.message);
    return false;
  }
}

// ============================================================
// HELPERS
// ============================================================

function validateEmailDomain(email) {
  if (!email || !email.includes('@')) return false;
  const domainName = email.split('@')[1].split('.')[0].toLowerCase();
  return ALLOWED_DOMAINS.some(d => domainName === d || domainName.endsWith('.' + d));
}

function storeCode(email, code) {
  pendingCodes.set(email.toLowerCase(), { code, expires: Date.now() + CODE_EXPIRY_MS });
  const now = Date.now();
  for (const [k, v] of pendingCodes) if (v.expires < now) pendingCodes.delete(k);
}

function verifyStoredCode(email, code) {
  const stored = pendingCodes.get(email.toLowerCase());
  if (!stored) return { valid: false, reason: 'Aucun code en attente. Demandez-en un nouveau.' };
  if (Date.now() > stored.expires) {
    pendingCodes.delete(email.toLowerCase());
    return { valid: false, reason: 'Code expiré. Demandez-en un nouveau.' };
  }
  if (stored.code !== code) return { valid: false, reason: 'Code incorrect.' };
  pendingCodes.delete(email.toLowerCase());
  return { valid: true };
}

function generateCode() { return String(Math.floor(100000 + Math.random() * 900000)); }

function generateJWT(email) {
  return jwt.sign(
    { email: email.toLowerCase(), domain: email.split('@')[1], auth_time: Date.now() },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
}

// Middleware : vérifie le JWT
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentification requise' });
  }
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session expirée. Reconnectez-vous.' });
  }
}

// Middleware : vérifie la clé API (pour le pipeline)
function apiKeyMiddleware(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!DATA_API_KEY || key !== DATA_API_KEY) {
    return res.status(403).json({ error: 'Clé API invalide' });
  }
  next();
}

// Middleware : vérifie le JWT pour les fichiers statiques protégés
function staticAuthMiddleware(req, res, next) {
  // Routes publiques (login, etc.)
  const publicPaths = ['/index.html', '/'];
  if (publicPaths.includes(req.path)) return next();

  // Fichiers statiques protégés
  const protectedExtensions = ['.html', '.js', '.css', '.json', '.svg', '.png'];
  const ext = path.extname(req.path).toLowerCase();
  if (protectedExtensions.includes(ext)) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      return res.redirect('/?unauthorized=1');
    }
    try {
      jwt.verify(auth.slice(7), JWT_SECRET);
      next();
    } catch (err) {
      return res.redirect('/?unauthorized=1');
    }
  } else {
    next();
  }
}

// ============================================================
// APP
// ============================================================

const app = express();
app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }));
app.use(express.json({ limit: '50mb' }));

// ============================================================
// ROUTES API (publiques)
// ============================================================

// POST /api/auth/request-code — stocke le code, envoie l'email en arrière-plan
app.post('/api/auth/request-code', (req, res) => {
  try {
    const { email, purpose } = req.body;
    if (!email || !validateEmailDomain(email))
      return res.status(400).json({ error: 'Email non autorisé (@bymycar.* / @cosmobilis.*)' });
    const exists = !!findUser(email);
    if (!purpose && exists) return res.json({ exists: true, sent: false });
    if (purpose === 'register' && exists) return res.json({ exists: true, sent: false, error: 'Ce compte existe déjà.' });
    if (purpose === 'forgot' && !exists) return res.json({ exists: false, sent: false, error: 'Aucun compte avec cet email.' });

    // 1. Générer et stocker le code immédiatement
    const code = generateCode();
    storeCode(email, code);
    console.log(`  📧 Code for ${email}: ${code}`);

    // 2. Envoyer l'email en arrière-plan (ne bloque pas la réponse)
    if (RESEND_CONFIGURED) {
      sendEmailViaResend(email, code).then(sent => {
        console.log(`  📧 Email to ${email}: ${sent ? 'sent' : 'FAILED'}`);
      });
    } else {
      console.log('  ⚠️ Resend API key not configured, email not sent');
    }

    // 3. Répondre immédiatement (toujours succès)
    res.json({ sent: true, exists: !!findUser(email), message: 'Code envoyé par email.' });
  } catch (err) { 
    console.error(err); 
    res.status(500).json({ error: 'Erreur interne.' }); 
  }
});

// POST /api/auth/verify-code
app.post('/api/auth/verify-code', (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ valid: false, error: 'Paramètres manquants.' });
    const result = verifyStoredCode(email, code);
    if (!result.valid) return res.status(401).json({ valid: false, error: result.reason });
    const tempToken = jwt.sign({ email: email.toLowerCase(), action: 'set_password', time: Date.now() }, JWT_SECRET, { expiresIn: '5m' });
    res.json({ valid: true, exists: !!findUser(email), tempToken });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur interne.' }); }
});

// POST /api/auth/set-password
app.post('/api/auth/set-password', async (req, res) => {
  try {
    const { tempToken, email, password } = req.body;
    if (!tempToken || !email || !password) return res.status(400).json({ error: 'Paramètres manquants.' });
    let decoded;
    try { decoded = jwt.verify(tempToken, JWT_SECRET); } catch (e) { return res.status(401).json({ error: 'Token invalide ou expiré.' }); }
    if (decoded.email !== email.toLowerCase() || decoded.action !== 'set_password') return res.status(401).json({ error: 'Token invalide.' });
    if (password.length < 4) return res.status(400).json({ error: 'Min. 4 caractères.' });
    if (findUser(email)) return res.status(400).json({ error: 'Ce compte existe déjà.' });
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    if (!(await addUser(email, hash))) return res.status(500).json({ error: 'Erreur création compte.' });
    console.log(`  ✅ Nouvel utilisateur: ${email}`);
    res.json({ success: true, token: generateJWT(email), email: email.toLowerCase() });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur interne.' }); }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis.' });
    const user = findUser(email);
    if (!user) return res.status(401).json({ error: 'Aucun compte avec cet email.' });
    if (!(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Mot de passe incorrect.' });
    res.json({ success: true, token: generateJWT(email), email: email.toLowerCase() });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur interne.' }); }
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { tempToken, email, newPassword } = req.body;
    if (!tempToken || !email || !newPassword) return res.status(400).json({ error: 'Paramètres manquants.' });
    let decoded;
    try { decoded = jwt.verify(tempToken, JWT_SECRET); } catch (e) { return res.status(401).json({ error: 'Token invalide ou expiré.' }); }
    if (decoded.email !== email.toLowerCase() || decoded.action !== 'set_password') return res.status(401).json({ error: 'Token invalide.' });
    if (!findUser(email)) return res.status(400).json({ error: 'Aucun compte trouvé.' });
    if (newPassword.length < 4) return res.status(400).json({ error: 'Min. 4 caractères.' });
    const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    if (!(await updateUserPassword(email, hash))) return res.status(500).json({ error: 'Erreur mise à jour.' });
    console.log(`  ✅ Mot de passe réinitialisé: ${email}`);
    res.json({ success: true, token: generateJWT(email), email: email.toLowerCase() });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur interne.' }); }
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ authenticated: true, email: req.user.email, domain: req.user.domain });
});

// GET /api/auth/check-user
app.get('/api/auth/check-user', (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).json({ error: 'Email requis.' });
  res.json({ exists: !!findUser(email), email: email.toLowerCase() });
});

// GET /api/health
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', email_configured: RESEND_CONFIGURED, users_count: users.length, has_data: !!dashboardData, uptime: process.uptime() });
});

// ============================================================
// ROUTES PROTÉGÉES (données du dashboard)
// ============================================================

// GET /api/data/dashboard — données de scoring (protégé par JWT)
app.get('/api/data/dashboard', authMiddleware, (req, res) => {
  if (!dashboardData) return res.status(404).json({ error: 'Aucune donnée disponible' });
  res.json(dashboardData);
});

// GET /api/data/services — configuration des services (protégé par JWT)
app.get('/api/data/services', authMiddleware, (req, res) => {
  if (!servicesConfig) return res.status(404).json({ error: 'Aucune configuration disponible' });
  res.json(servicesConfig);
});

// ============================================================
// ROUTES PIPELINE (upload des données)
// ============================================================

// POST /api/data/update — le pipeline push les données ici
app.post('/api/data/update', apiKeyMiddleware, (req, res) => {
  try {
    const { data, config } = req.body;
    if (data) {
      dashboardData = data;
      fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf-8');
    }
    if (config) {
      servicesConfig = config;
      fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf-8');
    }
    console.log(`  ✅ Données mises à jour: data=${!!data} config=${!!config}`);
    res.json({ success: true, data_received: !!data, config_received: !!config });
  } catch (err) {
    console.error('Data update error:', err);
    res.status(500).json({ error: 'Erreur lors de la mise à jour des données.' });
  }
});

// ============================================================
// FICHIERS STATIQUES — servis manuellement (pas de express.static)
// ============================================================

// Servir index.html (page principale)
app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, '..', 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.status(404).json({ error: 'index.html non trouvé' });
});

// Servir les autres fichiers statiques du frontend (js, css, etc.)
app.get('*', (req, res, next) => {
  // Ne pas intercepter les routes API qui commencent par /api/
  if (req.path.startsWith('/api/')) return next();
  
  // Sécurité : ne jamais servir data.json, services_config.json en statique
  const basename = path.basename(req.path);
  if (basename === 'data.json' || basename === 'services_config.json') {
    return res.status(403).json({ error: 'Données accessibles via /api/data/dashboard' });
  }
  
  // Servir le fichier statique depuis la racine du repo
  const filePath = path.join(__dirname, '..', req.path);
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    return res.sendFile(filePath);
  }
  
  // Fallback SPA : servir index.html pour les routes inconnues
  const indexPath = path.join(__dirname, '..', 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  
  res.status(404).json({ error: 'Page non trouvée' });
});

// ============================================================
// START
// ============================================================

loadUsers();
loadDashboardData();

app.listen(PORT, () => {
  console.log(`\n  🚀 Call Scoring — Backend unique`);
  console.log(`  📡 Port: ${PORT}`);
  console.log(`  ✉️  Email: ${RESEND_CONFIGURED ? '✅ Resend API' : '❌ Non configuré'}`);
  console.log(`  👥 Utilisateurs: ${users.length}`);
  console.log(`  📊 Données: ${dashboardData ? '✅ Chargées' : '❌ Aucune'}`);
  console.log(`  🔑 API Key: ${DATA_API_KEY ? '✅ Configurée' : '❌ Non configurée'}`);
  if (!RESEND_CONFIGURED) console.log(`  ⚠️  Définir RESEND_API_KEY dans les variables d'environnement`);
  if (!DATA_API_KEY) console.log(`  ⚠️  Définir DATA_API_KEY pour les uploads du pipeline`);
  console.log();
});
