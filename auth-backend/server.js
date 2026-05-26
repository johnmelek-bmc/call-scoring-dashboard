#!/usr/bin/env node
/**
 * Call Scoring — Authentication Backend
 * 
 * Backend autonome — stockage local (users.json), aucun accès GitHub.
 * 
 * Flow :
 *   1. Email → validation domaine @bymycar.* / @cosmobilis.*
 *   2. Si compte existe → saisir mot de passe → connecté
 *   3. Si nouveau → code par email (Gmail SMTP) → créer mot de passe → connecté
 *   4. Mot de passe oublié → code par email → nouveau mot de passe
 * 
 * Variables d'environnement :
 *   PORT             - Port (défaut: 3001)
 *   JWT_SECRET       - Secret JWT (auto-généré si absent)
 *   SMTP_HOST        - Serveur SMTP (défaut: smtp.gmail.com)
 *   SMTP_PORT        - Port SMTP (défaut: 587)
 *   SMTP_USER        - Utilisateur SMTP (bymycar.reporting@gmail.com)
 *   SMTP_PASS        - Mot de passe d'application Gmail ⚠️ requis
 *   FROM_EMAIL       - Adresse d'envoi (défaut: SMTP_USER)
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
const ALLOWED_DOMAINS = ['bymycar', 'cosmobilis'];
const USERS_FILE = path.join(__dirname, 'users.json');

// SMTP
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587');
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const FROM_EMAIL = process.env.FROM_EMAIL || SMTP_USER || 'noreply@bymycar.fr';
const SMTP_CONFIGURED = !!(SMTP_HOST && SMTP_USER && SMTP_PASS);

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,https://johnmelek-bmc.github.io').split(',').map(s => s.trim());

// ============================================================
// USER STORAGE (JSON file)
// ============================================================

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const data = fs.readFileSync(USERS_FILE, 'utf-8');
      return JSON.parse(data);
    }
  } catch (err) {
    console.error('Error loading users:', err.message);
  }
  return [];
}

function saveUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
    return true;
  } catch (err) {
    console.error('Error saving users:', err.message);
    return false;
  }
}

let users = loadUsers();
const pendingCodes = new Map();

function findUser(email) {
  return users.find(u => u.email === email.toLowerCase());
}

async function addUser(email, passwordHash) {
  users.push({ email: email.toLowerCase(), passwordHash, created_at: new Date().toISOString() });
  return saveUsers(users);
}

async function updateUserPassword(email, newHash) {
  const idx = users.findIndex(u => u.email === email.toLowerCase());
  if (idx === -1) return false;
  users[idx].passwordHash = newHash;
  users[idx].updated_at = new Date().toISOString();
  return saveUsers(users);
}

// ============================================================
// EMAIL
// ============================================================

async function sendEmailSMTP(to, code) {
  if (!SMTP_CONFIGURED) return false;
  try {
    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: false,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
    await transporter.sendMail({
      from: `"CallScoring" <${FROM_EMAIL}>`,
      to,
      subject: '🔐 CallScoring — Votre code de vérification',
      html: `
        <div style="font-family: -apple-system, sans-serif; max-width:480px; margin:0 auto; padding:20px;">
          <div style="background:#1a1a1a; border-radius:16px; padding:24px; text-align:center; margin-bottom:24px;">
            <span style="color:#fff; font-size:20px; font-weight:700;">CallScoring</span>
          </div>
          <h2 style="color:#1d1d1f; font-size:18px; margin-bottom:8px;">Connexion à votre tableau de bord</h2>
          <p style="color:#6e6e73; font-size:14px; margin-bottom:20px;">Voici votre code de vérification :</p>
          <div style="background:#f5f5f7; border-radius:16px; padding:24px; text-align:center; font-size:40px; font-weight:700; letter-spacing:12px; color:#0071e3; font-family:monospace; margin-bottom:20px;">${code}</div>
          <p style="color:#86868b; font-size:13px;">Ce code expire dans <strong>15 minutes</strong>.</p>
          <p style="color:#86868b; font-size:13px;">Si vous n'avez pas demandé cette connexion, ignorez cet email.</p>
          <hr style="border:none; border-top:1px solid #e8e8ed; margin:20px 0;">
          <p style="color:#aeaeb2; font-size:11px; text-align:center;">CallScoring — ByMyCar BDC Dashboard</p>
        </div>`,
    });
    return true;
  } catch (err) {
    console.error('SMTP error:', err.message);
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

// ============================================================
// APP
// ============================================================

const app = express();
app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }));
app.use(express.json());

// ============================================================
// ROUTES
// ============================================================

// POST /api/auth/request-code — Envoie un code par email
app.post('/api/auth/request-code', async (req, res) => {
  try {
    const { email, purpose } = req.body;
    if (!email || !validateEmailDomain(email))
      return res.status(400).json({ error: 'Email non autorisé (@bymycar.* / @cosmobilis.*)' });

    const exists = !!findUser(email);

    if (!purpose && exists)
      return res.json({ exists: true, sent: false, message: 'Compte existant. Entrez votre mot de passe.' });
    if (purpose === 'register' && exists)
      return res.json({ exists: true, sent: false, error: 'Ce compte existe déjà. Connectez-vous avec votre mot de passe.' });
    if (purpose === 'forgot' && !exists)
      return res.json({ exists: false, sent: false, error: 'Aucun compte avec cet email.' });

    const code = generateCode();
    storeCode(email, code);
    const sent = SMTP_CONFIGURED ? await sendEmailSMTP(email, code) : false;
    console.log(`  Code for ${email}: ${code} [sent: ${sent}]`);

    if (!sent) return res.json({ sent: false, error: SMTP_CONFIGURED ? "Erreur d'envoi. Réessayez." : "SMTP non configuré." });
    res.json({ sent: true, exists: !!findUser(email), message: 'Code envoyé par email.' });
  } catch (err) {
    console.error('request-code error:', err);
    res.status(500).json({ error: 'Erreur interne.' });
  }
});

// POST /api/auth/verify-code — Vérifie le code, retourne un temp_token
app.post('/api/auth/verify-code', (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ valid: false, error: 'Paramètres manquants.' });

    const result = verifyStoredCode(email, code);
    if (!result.valid) return res.status(401).json({ valid: false, error: result.reason });

    const tempToken = jwt.sign(
      { email: email.toLowerCase(), action: 'set_password', time: Date.now() },
      JWT_SECRET,
      { expiresIn: '5m' }
    );
    res.json({ valid: true, exists: !!findUser(email), tempToken });
  } catch (err) {
    console.error('verify-code error:', err);
    res.status(500).json({ error: 'Erreur interne.' });
  }
});

// POST /api/auth/set-password — Crée un compte (nouvel utilisateur)
app.post('/api/auth/set-password', async (req, res) => {
  try {
    const { tempToken, email, password } = req.body;
    if (!tempToken || !email || !password)
      return res.status(400).json({ error: 'Paramètres manquants.' });

    let decoded;
    try { decoded = jwt.verify(tempToken, JWT_SECRET); } catch (e) {
      return res.status(401).json({ error: 'Token invalide ou expiré. Recommencez.' });
    }
    if (decoded.email !== email.toLowerCase() || decoded.action !== 'set_password')
      return res.status(401).json({ error: 'Token invalide.' });
    if (password.length < 4)
      return res.status(400).json({ error: 'Le mot de passe doit faire au moins 4 caractères.' });
    if (findUser(email))
      return res.status(400).json({ error: 'Ce compte existe déjà.' });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const saved = await addUser(email, hash);
    if (!saved) return res.status(500).json({ error: "Erreur lors de la création du compte." });

    const token = generateJWT(email);
    console.log(`  ✅ Nouvel utilisateur: ${email}`);
    res.json({ success: true, token, email: email.toLowerCase() });
  } catch (err) {
    console.error('set-password error:', err);
    res.status(500).json({ error: 'Erreur interne.' });
  }
});

// POST /api/auth/login — Connexion email + mot de passe
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis.' });

    const user = findUser(email);
    if (!user) return res.status(401).json({ error: 'Aucun compte avec cet email.' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Mot de passe incorrect.' });

    const token = generateJWT(email);
    res.json({ success: true, token, email: email.toLowerCase() });
  } catch (err) {
    console.error('login error:', err);
    res.status(500).json({ error: 'Erreur interne.' });
  }
});

// POST /api/auth/reset-password — Réinitialisation (forgot password)
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { tempToken, email, newPassword } = req.body;
    if (!tempToken || !email || !newPassword)
      return res.status(400).json({ error: 'Paramètres manquants.' });

    let decoded;
    try { decoded = jwt.verify(tempToken, JWT_SECRET); } catch (e) {
      return res.status(401).json({ error: 'Token invalide ou expiré.' });
    }
    if (decoded.email !== email.toLowerCase() || decoded.action !== 'set_password')
      return res.status(401).json({ error: 'Token invalide.' });
    if (!findUser(email))
      return res.status(400).json({ error: 'Aucun compte trouvé.' });
    if (newPassword.length < 4)
      return res.status(400).json({ error: 'Min. 4 caractères.' });

    const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    const saved = await updateUserPassword(email, hash);
    if (!saved) return res.status(500).json({ error: "Erreur lors de la mise à jour." });

    const token = generateJWT(email);
    console.log(`  ✅ Mot de passe réinitialisé: ${email}`);
    res.json({ success: true, token, email: email.toLowerCase() });
  } catch (err) {
    console.error('reset-password error:', err);
    res.status(500).json({ error: 'Erreur interne.' });
  }
});

// GET /api/auth/me — Vérifie le token JWT
app.get('/api/auth/me', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ authenticated: false });

  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    res.json({ authenticated: true, email: decoded.email, domain: decoded.domain, hasPassword: !!findUser(decoded.email) });
  } catch (err) {
    res.status(401).json({ authenticated: false });
  }
});

// GET /api/auth/check-user — Vérifie si un email a un compte
app.get('/api/auth/check-user', (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).json({ error: 'Email requis.' });
  res.json({ exists: !!findUser(email), email: email.toLowerCase() });
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => res.json({ success: true }));

// GET /api/health
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    smtp_configured: SMTP_CONFIGURED,
    users_count: users.length,
    uptime: process.uptime(),
  });
});

// Serve static (frontend) in dev mode
app.use(express.static(path.join(__dirname, '..')));

// ============================================================
// START
// ============================================================

app.listen(PORT, () => {
  console.log(`\n  🚀 Call Scoring Auth Backend`);
  console.log(`  📡 Port: ${PORT}`);
  console.log(`  ✉️  SMTP: ${SMTP_CONFIGURED ? '✅ Gmail configuré' : '❌ NON configuré'}`);
  console.log(`  👥 Utilisateurs: ${users.length}`);
  console.log(`  💾 Stockage: ${USERS_FILE}`);
  console.log(`  🌐 CORS: ${ALLOWED_ORIGINS.join(', ')}`);
  if (!SMTP_CONFIGURED) console.log(`  ⚠️  Définir SMTP_USER et SMTP_PASS dans les variables d'environnement`);
  console.log();
});
