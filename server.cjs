try {
  const fs = require('fs');
  const path = require('path');
  const envPath = path.resolve(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    process.loadEnvFile(envPath);
  }
} catch (e) {
  console.warn('Could not load .env file via loadEnvFile:', e.message);
}

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.BACKEND_PORT || process.env.PORT || 29001;
const JWT_SECRET = process.env.JWT_SECRET || 'kbs-cloud-sso-secret-key-12345';

// Generate RS256 key pair for Back-Channel SLO
const { generateKeyPairSync } = require('crypto');
let privateKeyPem;
let publicKeyPem;

try {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  privateKeyPem = privateKey;
  publicKeyPem = publicKey;
  console.log('Successfully generated RSA key pair for Back-Channel SLO.');
} catch (keyErr) {
  console.error('Failed to generate RSA key pair:', keyErr.message);
}

// ---- SSO master session lifetime ----
//
// The session slides: every request that reads it past the halfway point pushes
// it back to a full term, so this is how long someone may stay *away* before
// signing in again, not how long they may stay signed in. A fixed 24-hour term
// was signing people out mid-use, which is not what any consumer site does.
//
// Sliding is the whole point, so the term itself can stay modest: an
// unattended browser still lapses within the month.
const SSO_SESSION_TTL_MS = Number(process.env.KBS_AUTH_SESSION_TTL_MS) > 0
  ? Number(process.env.KBS_AUTH_SESSION_TTL_MS)
  : 30 * 24 * 60 * 60 * 1000;

/** Attributes every `sso_session_id` cookie must share, whether set or cleared. */
function ssoCookieOptions(req) {
  return {
    httpOnly: true,
    path: '/',
    sameSite: 'lax',
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https'
  };
}

/**
 * Issues or re-issues the session cookie.
 *
 * Renewal has to repeat every attribute of the original: a cookie that differed
 * in path or sameSite would sit alongside the first rather than replace it, and
 * the browser would go on sending the stale one.
 */
function setSSOSessionCookie(req, res, sessionId) {
  res.cookie('sso_session_id', sessionId, { ...ssoCookieOptions(req), maxAge: SSO_SESSION_TTL_MS });
}

// Database Connection. Overridable so a test run cannot open the live account
// database by accident, which is otherwise the only database this file knows.
const dbPath = process.env.KBS_AUTH_DB_PATH || path.join(__dirname, 'kbs_auth.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Failed to connect to SQLite database:', err.message);
  } else {
    console.log('Connected to SQLite database at:', dbPath);
    db.run('PRAGMA foreign_keys = ON', (pragmaErr) => {
      if (pragmaErr) console.error('Failed to enable foreign keys:', pragmaErr.message);
    });
    initializeTables();
  }
});

function initializeTables() {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password_hash TEXT,
        display_name TEXT,
        is_google_linked INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // SSO Master Sessions table
    db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        email TEXT,
        expires_at DATETIME,
        FOREIGN KEY(email) REFERENCES users(email) ON DELETE CASCADE
      )
    `);

    // Session Clients mapping table for SLO
    db.run(`
      CREATE TABLE IF NOT EXISTS session_clients (
        sso_session_id TEXT,
        client_id TEXT,
        PRIMARY KEY (sso_session_id, client_id),
        FOREIGN KEY(sso_session_id) REFERENCES sessions(id) ON DELETE CASCADE
      )
    `);

    // Temporary Authorization Codes table
    db.run(`
      CREATE TABLE IF NOT EXISTS auth_codes (
        code TEXT PRIMARY KEY,
        email TEXT,
        client_id TEXT,
        redirect_uri TEXT,
        expires_at DATETIME
      )
    `);

    // Per-app Google OAuth tokens (for apps requesting extra Google API scopes)
    db.run(`
      CREATE TABLE IF NOT EXISTS google_tokens (
        email TEXT NOT NULL,
        client_id TEXT NOT NULL,
        access_token TEXT NOT NULL,
        refresh_token TEXT,
        expires_at_unix INTEGER NOT NULL,
        scope TEXT NOT NULL,
        session_token TEXT NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (email, client_id)
      )
    `);
  });
}

// Clean up expired sessions and auth codes periodically
setInterval(() => {
  const now = new Date().toISOString();
  db.run('DELETE FROM sessions WHERE expires_at < ?', [now]);
  db.run('DELETE FROM auth_codes WHERE expires_at < ?', [now]);
}, 5 * 60 * 1000); // Every 5 minutes

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Enable CORS
app.use(cors({
  origin: function(origin, callback) {
    // Allow starswarm, ticker-clash and self
    if (!origin) return callback(null, true);
    const allowed = [
      'http://localhost:8080', 'http://127.0.0.1:8080',
      'http://localhost:8081', 'http://127.0.0.1:8081',
      'http://localhost:8082', 'http://127.0.0.1:8082',
      'http://localhost:19000', 'http://127.0.0.1:19000',
      'http://localhost:19001', 'http://127.0.0.1:19001',
      'http://localhost:19002', 'http://127.0.0.1:19002',
      'http://localhost:19003', 'http://127.0.0.1:19003',
      'http://auth.kbs-cloud.com:8080',
      'http://starswarm.kbs-cloud.com:8081',
      'http://tickerclash.kbs-cloud.com:8082',
      'https://auth.kbs-cloud.com', 'http://auth.kbs-cloud.com',
      'https://starswarm.kbs-cloud.com', 'http://starswarm.kbs-cloud.com',
      'https://tickerclash.kbs-cloud.com', 'http://tickerclash.kbs-cloud.com',
      'https://ticker-clash.kbs-cloud.com', 'http://ticker-clash.kbs-cloud.com',
      'https://hifigemini.kbs-cloud.com', 'http://hifigemini.kbs-cloud.com',
      'http://127.0.0.1:13015', 'http://localhost:13015'
    ];
    if (allowed.indexOf(origin) !== -1 || origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) {
      return callback(null, true);
    }
    callback(null, true);
  },
  credentials: true
}));

// Google Client setup
const getGoogleClient = (req) => {
  let callbackUrl = 'https://auth.kbs-cloud.com/api/auth/callback/google';
  
  if (process.env.GOOGLE_CALLBACK_URL && !process.env.GOOGLE_CALLBACK_URL.includes('star-swarm') && !process.env.GOOGLE_CALLBACK_URL.includes('starswarm')) {
    callbackUrl = process.env.GOOGLE_CALLBACK_URL;
  } else if (process.env.NODE_ENV === 'production') {
    callbackUrl = 'https://auth.kbs-cloud.com/api/auth/callback/google';
  } else if (req) {
    const proto = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    if (proto === 'https') {
      callbackUrl = 'https://auth.kbs-cloud.com/api/auth/callback/google';
    } else if (host) {
      callbackUrl = `http://${host}/api/auth/callback/google`;
    }
  }

  return new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    callbackUrl
  );
};

/**
 * Validates the SSO session, and renews it while it is being used.
 *
 * Every authenticated path in this service goes through here, which is exactly
 * why the renewal belongs here: a session is "in use" whenever something asked
 * about it, and no route has to remember to say so.
 *
 * Renewing only past the halfway point keeps this to one write per half-term
 * rather than one per request. `res` is optional so a caller with nothing to
 * write back — there are none today, but the shape invites one — still reads
 * correctly; the row is extended either way, only the cookie is skipped.
 */
function getSSOSessionUser(req, res, callback) {
  if (typeof res === 'function') {
    callback = res;
    res = null;
  }

  const sessionId = req.cookies['sso_session_id'];
  if (!sessionId) {
    return callback(null, null);
  }
  const now = Date.now();
  db.get(
    `SELECT u.email, u.display_name, u.is_google_linked, (u.password_hash IS NOT NULL) AS has_password,
            s.expires_at
     FROM sessions s
     JOIN users u ON s.email = u.email
     WHERE s.id = ? AND s.expires_at > ?`,
    [sessionId, new Date(now).toISOString()],
    (err, row) => {
      if (err || !row) {
        return callback(null, null);
      }

      const expiresAt = new Date(row.expires_at).getTime();
      if (Number.isFinite(expiresAt) && now >= expiresAt - SSO_SESSION_TTL_MS / 2) {
        const renewed = new Date(now + SSO_SESSION_TTL_MS).toISOString();
        db.run('UPDATE sessions SET expires_at = ? WHERE id = ?', [renewed, sessionId]);
        if (res) {
          setSSOSessionCookie(req, res, sessionId);
        }
      }

      callback(null, row);
    }
  );
}

// Generate single-use authorization code
function createAuthCode(email, clientId, redirectUri, callback) {
  const code = crypto.randomBytes(24).toString('hex');
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 minutes validity
  db.run(
    'INSERT INTO auth_codes (code, email, client_id, redirect_uri, expires_at) VALUES (?, ?, ?, ?, ?)',
    [code, email, clientId, redirectUri, expiresAt],
    (err) => {
      if (err) return callback(err);
      callback(null, code);
    }
  );
}

// ---- Redirect-URI trust check ----
// A game's officially registered URLs live in the Hub catalog (the same
// database every game's register_game.cjs writes to), so we reuse that as
// the allowlist instead of inventing a second registry. Any redirect_uri
// whose origin isn't in that list (e.g. someone's self-hosted world reached
// through a kbs-game-coordinator join code, on an arbitrary host/port) is
// untrusted: we still let it work, but only after an explicit user-visible
// consent screen naming the destination, instead of silently handing out a
// login code to whatever origin the request claims.
const HUB_DB_PATH = process.env.HUB_DB_PATH || '/servers/cloud/hub.db';
let hubDb = null;
try {
  if (fs.existsSync(HUB_DB_PATH)) {
    hubDb = new sqlite3.Database(HUB_DB_PATH, sqlite3.OPEN_READONLY, (err) => {
      if (err) {
        console.warn('[kbs-auth] Could not open Hub catalog for redirect_uri trust checks:', err.message);
        hubDb = null;
      }
    });
  } else {
    console.warn('[kbs-auth] Hub catalog not found at', HUB_DB_PATH, '- all redirect_uris will require consent.');
  }
} catch (e) {
  console.warn('[kbs-auth] Could not open Hub catalog:', e.message);
}

function originOf(urlString) {
  try {
    return new URL(urlString).origin;
  } catch {
    return null;
  }
}

function parseScopeList(raw) {
  if (!raw) return [];
  return String(raw)
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function normalizeScopeForCompare(scope) {
  if (scope === 'email') return 'https://www.googleapis.com/auth/userinfo.email';
  if (scope === 'profile') return 'https://www.googleapis.com/auth/userinfo.profile';
  return scope;
}

function getAppGoogleScopes(clientId, callback) {
  if (!clientId || !hubDb) {
    return callback([]);
  }
  hubDb.get('SELECT google_scopes FROM apps WHERE id = ?', [clientId], (err, row) => {
    if (err || !row || !row.google_scopes) {
      return callback([]);
    }
    callback(parseScopeList(row.google_scopes));
  });
}

function hasValidGoogleTokens(email, clientId, extraScopes, callback) {
  if (!extraScopes || extraScopes.length === 0) {
    return callback(null, true);
  }
  db.get(
    'SELECT scope, refresh_token FROM google_tokens WHERE email = ? AND client_id = ?',
    [email, clientId],
    (err, row) => {
      if (err) return callback(err, false);
      if (!row || !row.refresh_token || !String(row.refresh_token).trim()) {
        return callback(null, false);
      }
      const granted = new Set(parseScopeList(row.scope).map(normalizeScopeForCompare));
      const satisfied = extraScopes.every((s) => granted.has(normalizeScopeForCompare(s)));
      callback(null, satisfied);
    }
  );
}

function saveAppGoogleTokens(email, clientId, tokens, extraScopes, callback) {
  if (!clientId || !extraScopes || extraScopes.length === 0 || !tokens || !tokens.access_token) {
    return callback(null);
  }
  const expiresAtUnix = tokens.expiry_date
    ? Math.floor(tokens.expiry_date / 1000)
    : Math.floor(Date.now() / 1000) + 3600;
  const grantedScope = tokens.scope || Array.from(new Set([
    'https://www.googleapis.com/auth/userinfo.email',
    'profile',
    ...extraScopes
  ])).join(' ');
  const refreshToken = tokens.refresh_token ? String(tokens.refresh_token) : null;
  const sessionToken = crypto.randomBytes(32).toString('hex');

  db.run(
    `INSERT INTO google_tokens (
       email, client_id, access_token, refresh_token, expires_at_unix, scope, session_token, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(email, client_id) DO UPDATE SET
       access_token = excluded.access_token,
       refresh_token = COALESCE(NULLIF(excluded.refresh_token, ''), google_tokens.refresh_token),
       expires_at_unix = excluded.expires_at_unix,
       scope = excluded.scope,
       session_token = excluded.session_token,
       updated_at = CURRENT_TIMESTAMP`,
    [email, clientId, tokens.access_token, refreshToken, expiresAtUnix, grantedScope, sessionToken],
    (err) => callback(err)
  );
}

function isLoopbackHttpOrigin(urlString) {
  try {
    const u = new URL(urlString);
    return u.protocol === 'http:' &&
      (u.hostname === '127.0.0.1' || u.hostname === 'localhost') &&
      Boolean(u.port);
  } catch {
    return false;
  }
}

// Fails closed: any error, missing Hub db, or unregistered client_id means
// "no known-good origins" rather than silently trusting the request.
function isTrustedRedirect(clientId, redirectUri, callback) {
  const requestedOrigin = originOf(redirectUri);
  if (!requestedOrigin || !hubDb) return callback(false);
  hubDb.get('SELECT dev_url, prod_url FROM apps WHERE id = ?', [clientId], (err, row) => {
    if (err || !row) return callback(false);
    const registered = [row.dev_url, row.prod_url].map(originOf).filter(Boolean);
    if (registered.includes(requestedOrigin)) {
      return callback(true);
    }
    callback(isLoopbackHttpOrigin(redirectUri));
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function renderConsentPage(res, { email, clientId, redirectUri }) {
  const origin = originOf(redirectUri) || redirectUri;
  res.status(200).send(`<!doctype html>
<html><head><meta charset="utf-8"><title>Confirm sign-in - kbs-cloud</title>
<style>
  body { font-family: system-ui, sans-serif; background: #12160d; color: #ecf0f1; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { max-width: 480px; padding: 28px 32px; border: 2px solid rgba(230,126,34,0.6); border-radius: 12px; background: #1b232a; }
  h1 { font-size: 20px; margin: 0 0 12px; }
  .origin { color: #e67e22; font-weight: 700; word-break: break-all; }
  p { line-height: 1.5; color: #cfd8dc; }
  .actions { display: flex; gap: 10px; margin-top: 20px; }
  button, a.cancel { flex: 1; text-align: center; padding: 10px 16px; border-radius: 7px; font-size: 15px; cursor: pointer; text-decoration: none; }
  button { border: none; background: #e67e22; color: #12160d; font-weight: 700; }
  a.cancel { border: 1px solid rgba(255,255,255,0.25); color: #ecf0f1; }
</style></head>
<body>
  <div class="card">
    <h1>Confirm sign-in</h1>
    <p><strong>${escapeHtml(origin)}</strong> is asking to sign you in as <strong>${escapeHtml(email)}</strong>
      using your kbs-cloud account (app id "${escapeHtml(clientId)}").</p>
    <p>This is <span class="origin">not a registered kbs-cloud deployment</span> for this app -
      it may be someone's self-hosted server. Only continue if you trust it (for example,
      a friend invited you to their world).</p>
    <div class="actions">
      <a class="cancel" href="/">Cancel</a>
      <form method="POST" action="/api/auth/authorize/confirm" style="flex:1;margin:0;">
        <input type="hidden" name="client_id" value="${escapeHtml(clientId)}">
        <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
        <button type="submit" style="width:100%;">Continue</button>
      </form>
    </div>
  </div>
</body></html>`);
}

// 1. Authorize Endpoint (Standard SSO Entrypoint)
app.get('/api/auth/authorize', (req, res) => {
  const { client_id, redirect_uri, prompt } = req.query;

  if (!client_id || !redirect_uri) {
    return res.status(400).send('Missing client_id or redirect_uri parameters.');
  }

  getSSOSessionUser(req, res, (err, user) => {
    if (err || !user) {
      if (prompt === 'none') {
        const separator = redirect_uri.includes('?') ? '&' : '?';
        return res.redirect(`${redirect_uri}${separator}error=login_required`);
      }
      // Not logged in. Redirect to SSO Portal Login screen with redirect context
      const loginUrl = `/?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}`;
      return res.redirect(loginUrl);
    }

    // Register active client for this SSO session
    const sessionId = req.cookies['sso_session_id'];
    if (sessionId) {
      db.run('INSERT OR IGNORE INTO session_clients (sso_session_id, client_id) VALUES (?, ?)', [sessionId, client_id]);
    }

    getAppGoogleScopes(client_id, (extraScopes) => {
      hasValidGoogleTokens(user.email, client_id, extraScopes, (tokenErr, tokensOk) => {
        if (tokenErr) {
          return res.status(500).send('Internal database error checking Google authorization.');
        }
        if (extraScopes.length > 0 && !tokensOk) {
          if (prompt === 'none') {
            const separator = redirect_uri.includes('?') ? '&' : '?';
            return res.redirect(`${redirect_uri}${separator}error=consent_required`);
          }
          return res.redirect(`/api/auth/google?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}`);
        }

        isTrustedRedirect(client_id, redirect_uri, (trusted) => {
          if (!trusted) {
            if (prompt === 'none') {
              const separator = redirect_uri.includes('?') ? '&' : '?';
              return res.redirect(`${redirect_uri}${separator}error=consent_required`);
            }
            return renderConsentPage(res, { email: user.email, clientId: client_id, redirectUri: redirect_uri });
          }
          // Already logged in and this is a registered destination for this app!
          // Generate authorization code and redirect back instantly.
          createAuthCode(user.email, client_id, redirect_uri, (codeErr, code) => {
            if (codeErr) {
              return res.status(500).send('Internal database error creating login code.');
            }
            const separator = redirect_uri.includes('?') ? '&' : '?';
            res.redirect(`${redirect_uri}${separator}code=${code}`);
          });
        });
      });
    });
  });
});

// Confirms an untrusted (unregistered) redirect_uri that the user has
// explicitly agreed to on the consent page above, and issues the code.
app.post('/api/auth/authorize/confirm', (req, res) => {
  const { client_id, redirect_uri } = req.body || {};
  if (!client_id || !redirect_uri) {
    return res.status(400).send('Missing client_id or redirect_uri parameters.');
  }
  getSSOSessionUser(req, res, (err, user) => {
    if (err || !user) {
      return res.redirect(`/?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}`);
    }
    const sessionId = req.cookies['sso_session_id'];
    if (sessionId) {
      db.run('INSERT OR IGNORE INTO session_clients (sso_session_id, client_id) VALUES (?, ?)', [sessionId, client_id]);
    }
    createAuthCode(user.email, client_id, redirect_uri, (codeErr, code) => {
      if (codeErr) {
        return res.status(500).send('Internal database error creating login code.');
      }
      const separator = redirect_uri.includes('?') ? '&' : '?';
      res.redirect(`${redirect_uri}${separator}code=${code}`);
    });
  });
});

// 2. Token Exchange Endpoint (Game Servers invoke this backend-to-backend)
app.post('/api/auth/token', (req, res) => {
  const { code, client_id } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'Missing authorization code.' });
  }

  const now = new Date().toISOString();
  db.get(
    'SELECT * FROM auth_codes WHERE code = ? AND expires_at > ?',
    [code, now],
    (err, authCodeRow) => {
      if (err || !authCodeRow) {
        return res.status(400).json({ error: 'Invalid or expired authorization code.' });
      }

      // Single-use enforcement: delete the code immediately
      db.run('DELETE FROM auth_codes WHERE code = ?', [code]);

      if (client_id && authCodeRow.client_id !== client_id) {
        return res.status(400).json({ error: 'Client ID mismatch.' });
      }

      db.get('SELECT * FROM users WHERE email = ?', [authCodeRow.email], (userErr, user) => {
        if (userErr || !user) {
          return res.status(400).json({ error: 'User associated with code not found.' });
        }

        // Generate signed JWT token containing user identity
        const tokenPayload = {
          email: user.email,
          displayName: user.display_name || null,
          isGoogleLinked: user.is_google_linked === 1
        };

        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1h' });

        db.get(
          'SELECT access_token, expires_at_unix, scope, session_token, refresh_token FROM google_tokens WHERE email = ? AND client_id = ?',
          [user.email, authCodeRow.client_id],
          (gtErr, gt) => {
            const responseBody = {
              success: true,
              token,
              user: tokenPayload
            };
            if (gtErr) {
              console.error('Failed to read google_tokens during token exchange:', gtErr);
            } else if (gt) {
              responseBody.googleAuth = {
                accessToken: gt.access_token,
                expiresAtUnix: gt.expires_at_unix,
                scope: gt.scope,
                sessionToken: gt.session_token,
                hasRefreshToken: Boolean(gt.refresh_token)
              };
            }
            res.status(200).json(responseBody);
          }
        );
      });
    }
  );
});

// 3. Central Login
app.post('/api/auth/login', (req, res) => {
  const { email, password, client_id, redirect_uri } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Please enter email and password.' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  db.get('SELECT * FROM users WHERE email = ?', [normalizedEmail], (err, user) => {
    if (err || !user) {
      return res.status(400).json({ error: 'Account not found. Please register.' });
    }

    if (!user.password_hash) {
      return res.status(400).json({
        error: 'This account was created with Google Sign-in and does not have a password set yet. Click "Register Account" to set a password for this email.'
      });
    }

    const isMatch = bcrypt.compareSync(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect password.' });
    }

    // Initialize SSO master session
    const sessionId = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + SSO_SESSION_TTL_MS).toISOString();

    db.run(
      'INSERT INTO sessions (id, email, expires_at) VALUES (?, ?, ?)',
      [sessionId, normalizedEmail, expiresAt],
      (sessionErr) => {
        if (sessionErr) {
          return res.status(500).json({ error: 'Failed to create active session.' });
        }

        // Set HttpOnly Cookie scoped for SSO domain
        setSSOSessionCookie(req, res, sessionId);

        const responseData = {
          success: true,
          user: {
            email: user.email,
            displayName: user.display_name || null,
            isGoogleLinked: user.is_google_linked === 1,
            hasPassword: !!user.password_hash
          }
        };

        // If authorization parameters exist, generate redirect URI with code
        if (client_id && redirect_uri) {
          db.run('INSERT OR IGNORE INTO session_clients (sso_session_id, client_id) VALUES (?, ?)', [sessionId, client_id]);

          getAppGoogleScopes(client_id, (extraScopes) => {
            hasValidGoogleTokens(user.email, client_id, extraScopes, (tokenErr, tokensOk) => {
              if (tokenErr) {
                return res.status(500).json({ error: 'Failed to verify Google authorization status.' });
              }
              if (extraScopes.length > 0 && !tokensOk) {
                responseData.consentUrl = `/api/auth/authorize?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}`;
                return res.status(200).json(responseData);
              }
              isTrustedRedirect(client_id, redirect_uri, (trusted) => {
                if (!trusted) {
                  // Unregistered destination -- the SPA must navigate to a
                  // full-page consent screen (naming the destination) rather
                  // than being handed a code to redirect to silently. The
                  // freshly-set session cookie makes this a GET back through
                  // /api/auth/authorize, which renders the same consent page.
                  responseData.consentUrl = `/api/auth/authorize?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}`;
                  return res.status(200).json(responseData);
                }
                createAuthCode(user.email, client_id, redirect_uri, (codeErr, code) => {
                  if (codeErr) {
                    return res.status(500).json({ error: 'Failed to create login redirect code.' });
                  }
                  const separator = redirect_uri.includes('?') ? '&' : '?';
                  responseData.redirectUri = `${redirect_uri}${separator}code=${code}`;
                  res.status(200).json(responseData);
                });
              });
            });
          });
        } else {
          res.status(200).json(responseData);
        }
      }
    );
  });
});

// 4. Central Registration
app.post('/api/auth/register', (req, res) => {
  const { email, password, displayName } = req.body;

  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = bcrypt.hashSync(password, 10);

  db.get('SELECT * FROM users WHERE email = ?', [normalizedEmail], (getErr, existingUser) => {
    if (getErr) {
      return res.status(500).json({ error: 'Database error checking account.' });
    }

    if (existingUser) {
      if (!existingUser.password_hash) {
        // Account was created via Google Sign-In but has no password set yet -> set password!
        db.run(
          'UPDATE users SET password_hash = ?, display_name = COALESCE(display_name, ?) WHERE email = ?',
          [passwordHash, displayName || null, normalizedEmail],
          (updateErr) => {
            if (updateErr) {
              return res.status(500).json({ error: 'Failed to set account password.' });
            }
            res.status(200).json({ success: true, message: 'Password set successfully for your account! You can now log in.' });
          }
        );
      } else {
        return res.status(400).json({ error: 'An account with this email already exists.' });
      }
    } else {
      db.run(
        'INSERT INTO users (email, password_hash, display_name, is_google_linked) VALUES (?, ?, ?, 0)',
        [normalizedEmail, passwordHash, displayName || null],
        function (err) {
          if (err) {
            return res.status(500).json({ error: 'Database registration error.' });
          }
          res.status(201).json({ success: true, message: 'Account registered successfully.' });
        }
      );
    }
  });
});

// 5. Get current SSO User Details
app.get('/api/auth/me', (req, res) => {
  getSSOSessionUser(req, res, (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Unauthorized. No active SSO session.' });
    }
    res.status(200).json({
      success: true,
      user: {
        email: user.email,
        displayName: user.display_name,
        isGoogleLinked: user.is_google_linked === 1,
        hasPassword: user.has_password === 1
      }
    });
  });
});

// 5.0.1 Verify SSO Token
app.post('/api/auth/verify', (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ success: false, error: 'Missing token.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ success: false, error: 'Invalid or expired token.' });
    }
    res.status(200).json({
      success: true,
      user: {
        email: decoded.email,
        displayName: decoded.displayName
      }
    });
  });
});

// 5.1 Change/Set Password
app.post('/api/auth/change-password', (req, res) => {
  getSSOSessionUser(req, res, (err, sessionUser) => {
    if (err || !sessionUser) {
      return res.status(401).json({ error: 'Unauthorized. No active SSO session.' });
    }

    const { currentPassword, newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
    }

    // Retrieve user details from database to check for existing password_hash
    db.get('SELECT password_hash FROM users WHERE email = ?', [sessionUser.email], (userErr, user) => {
      if (userErr || !user) {
        return res.status(500).json({ error: 'User details not found.' });
      }

      // If they already have a password set, they must provide their correct current password
      if (user.password_hash) {
        if (!currentPassword) {
          return res.status(400).json({ error: 'Please enter your current password.' });
        }
        const isMatch = bcrypt.compareSync(currentPassword, user.password_hash);
        if (!isMatch) {
          return res.status(400).json({ error: 'Incorrect current password.' });
        }
      }

      // Hash and update the password
      const newHash = bcrypt.hashSync(newPassword, 10);
      db.run('UPDATE users SET password_hash = ? WHERE email = ?', [newHash, sessionUser.email], (updateErr) => {
        if (updateErr) {
          return res.status(500).json({ error: 'Failed to update password.' });
        }
        res.status(200).json({ success: true, message: 'Password updated successfully.' });
      });
    });
  });
});

// Helper: Resolve backend URL for SLO back-channel requests
function getAppLogoutUrl(clientId) {
  // If the auth server runs on port 20001 (or starts with 20), use the 2000x port range for back-channel calls.
  // Otherwise, default to the 2900x port range.
  const isProductionRange = (PORT === 20001 || String(PORT).startsWith('20'));
  const portOffset = isProductionRange ? 20000 : 29000;

  const clientConfigMap = {
    'kbs-cloud': 0,
    'starswarm': 2,
    'tickerclash': 3,
    'alchemist': 4,
    'gridlock-neon': 5,
    'wyrdmarch': 9
  };

  const offset = clientConfigMap[clientId];
  if (offset === undefined) return null;

  const port = portOffset + offset;
  return `http://localhost:${port}/api/auth/backchannel-logout`;
}


// Endpoint to retrieve public key for signature verification
app.get('/api/auth/certs', (req, res) => {
  if (!publicKeyPem) {
    return res.status(500).json({ error: 'RSA public key not initialized.' });
  }
  res.status(200).json({ keys: [{ kid: 'sso-key-1', pem: publicKeyPem }] });
});

// 6. Central Logout
app.all('/api/auth/logout', (req, res) => {
  const sessionId = req.cookies['sso_session_id'];

  const finishLogout = () => {
    res.clearCookie('sso_session_id', ssoCookieOptions(req));

    const redirectUri = req.query.redirect_uri || req.body.redirect_uri;
    if (redirectUri) {
      return res.redirect(redirectUri);
    }
    res.status(200).json({ success: true, message: 'Logged out from all systems.' });
  };

  if (!sessionId) {
    return finishLogout();
  }

  db.get('SELECT email FROM sessions WHERE id = ?', [sessionId], (err, sessionRow) => {
    if (err || !sessionRow) {
      db.run('DELETE FROM sessions WHERE id = ?', [sessionId]);
      return finishLogout();
    }

    const email = sessionRow.email;

    db.all('SELECT client_id FROM session_clients WHERE sso_session_id = ?', [sessionId], async (clientsErr, clientRows) => {
      if (clientsErr || !clientRows || clientRows.length === 0) {
        db.run('DELETE FROM sessions WHERE id = ?', [sessionId]);
        return finishLogout();
      }

      // Dispatch back-channel logout requests to all active clients
      const logoutPromises = clientRows.map(row => {
        return new Promise(async (resolve) => {
          const logoutUrl = getAppLogoutUrl(row.client_id);
          if (!logoutUrl) {
            console.error(`Failed to resolve logout URL for client ${row.client_id}`);
            return resolve();
          }

          if (!privateKeyPem) {
            console.error('RSA private key not initialized; cannot sign logout token.');
            return resolve();
          }

          try {
            // Generate signed JWT logout token
            const logoutTokenPayload = {
              iss: 'kbs-auth',
              sub: email,
              aud: row.client_id,
              iat: Math.floor(Date.now() / 1000),
              exp: Math.floor(Date.now() / 1000) + 5 * 60, // 5 minutes validity
              events: {
                'http://schemas.openid.net/event/backchannel-logout': {}
              }
            };

            const logoutToken = jwt.sign(logoutTokenPayload, privateKeyPem, { algorithm: 'RS256', keyid: 'sso-key-1' });

            console.log(`Sending asymmetric back-channel logout to ${row.client_id} at ${logoutUrl}`);
            const response = await fetch(logoutUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ logout_token: logoutToken })
            });

            if (!response.ok) {
              console.warn(`Back-channel logout for ${row.client_id} returned status ${response.status}`);
            }
          } catch (postErr) {
            console.error(`Error sending back-channel logout to ${row.client_id}:`, postErr.message);
          }
          resolve();
        });
      });

      await Promise.all(logoutPromises);

      db.run('DELETE FROM sessions WHERE id = ?', [sessionId], () => {
        finishLogout();
      });
    });
  });
});

// 7. Google OAuth Login redirection (supports client flow)
app.get('/api/auth/google', (req, res) => {
  const { client_id, redirect_uri } = req.query;

  // Preserve redirect context inside the state param
  const stateObj = { client_id, redirect_uri };
  const stateStr = Buffer.from(JSON.stringify(stateObj)).toString('base64');

  getAppGoogleScopes(client_id, (extraScopes) => {
    const scope = Array.from(new Set([
      'https://www.googleapis.com/auth/userinfo.email',
      'profile',
      ...extraScopes
    ]));
    const authUrlOptions = {
      access_type: 'offline',
      scope,
      state: stateStr
    };
    if (extraScopes.length > 0) {
      authUrlOptions.include_granted_scopes = true;
      authUrlOptions.prompt = 'consent';
    }

    const client = getGoogleClient(req);
    const url = client.generateAuthUrl(authUrlOptions);
    res.redirect(url);
  });
});

// 8. Google OAuth Callback
app.get('/api/auth/callback/google', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    console.error('Google OAuth Callback error parameter:', error);
    return res.redirect(`/?error=${encodeURIComponent(error)}`);
  }

  if (!code) {
    console.error('Google OAuth Callback missing code parameter');
    return res.redirect('/?error=missing_code');
  }

  let stateObj = {};
  try {
    if (state) {
      stateObj = JSON.parse(Buffer.from(state, 'base64').toString('utf8'));
    }
  } catch (err) {
    console.error('Failed to parse state parameter:', err);
  }

  const { client_id, redirect_uri } = stateObj;

  try {
    const client = getGoogleClient(req);
    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase();
    const displayName = payload.name;

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
      const handleSessionCreation = (finalUserEmail, finalDisplayName) => {
        const sessionId = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + SSO_SESSION_TTL_MS).toISOString();

        db.run(
          'INSERT INTO sessions (id, email, expires_at) VALUES (?, ?, ?)',
          [sessionId, finalUserEmail, expiresAt],
          (sessErr) => {
            if (sessErr) {
              return res.status(500).send('Session creation failed.');
            }

            setSSOSessionCookie(req, res, sessionId);

            getAppGoogleScopes(client_id, (extraScopes) => {
              saveAppGoogleTokens(finalUserEmail, client_id, tokens, extraScopes, (tokenSaveErr) => {
                if (tokenSaveErr) {
                  console.error('Failed to persist Google OAuth tokens:', tokenSaveErr);
                  return res.status(500).send('Failed to save Google authorization tokens.');
                }

                if (client_id && redirect_uri) {
                  db.run('INSERT OR IGNORE INTO session_clients (sso_session_id, client_id) VALUES (?, ?)', [sessionId, client_id]);

                  isTrustedRedirect(client_id, redirect_uri, (trusted) => {
                    if (!trusted) {
                      return renderConsentPage(res, { email: finalUserEmail, clientId: client_id, redirectUri: redirect_uri });
                    }
                    createAuthCode(finalUserEmail, client_id, redirect_uri, (codeErr, authCode) => {
                      if (codeErr) return res.status(500).send('Auth code creation failed.');
                      const separator = redirect_uri.includes('?') ? '&' : '?';
                      res.redirect(`${redirect_uri}${separator}code=${authCode}`);
                    });
                  });
                } else {
                  res.redirect('/');
                }
              });
            });
          }
        );
      };

      if (user) {
        if (user.is_google_linked === 0) {
          db.run('UPDATE users SET is_google_linked = 1 WHERE email = ?', [email]);
        }
        handleSessionCreation(user.email, user.display_name || displayName);
      } else {
        db.run(
          'INSERT INTO users (email, password_hash, is_google_linked, display_name) VALUES (?, NULL, 1, ?)',
          [email, displayName],
          function (insertErr) {
            if (insertErr) {
              return res.status(500).send('User registration failed.');
            }
            handleSessionCreation(email, displayName);
          }
        );
      }
    });
  } catch (error) {
    console.error('Google OAuth Error:', error);
    res.redirect('/?error=oauth_failed');
  }
});

// 8.1 Refresh per-app Google OAuth access token
app.post('/api/auth/google/refresh', (req, res) => {
  const { client_id, session_token } = req.body || {};
  if (!client_id || !session_token) {
    return res.status(400).json({ error: 'Missing client_id or session_token.' });
  }

  db.get(
    'SELECT email, client_id, refresh_token, scope FROM google_tokens WHERE client_id = ? AND session_token = ?',
    [client_id, session_token],
    async (err, row) => {
      if (err) {
        console.error('Database error reading google_tokens:', err);
        return res.status(500).json({ error: 'Database error.' });
      }
      if (!row || !row.refresh_token) {
        return res.status(401).json({ error: 'reauth_required' });
      }

      try {
        const client = getGoogleClient(req);
        client.setCredentials({ refresh_token: row.refresh_token });
        const { credentials } = await client.refreshAccessToken();

        if (!credentials || !credentials.access_token) {
          return res.status(401).json({ error: 'reauth_required' });
        }

        const accessToken = credentials.access_token;
        const expiresAtUnix = credentials.expiry_date
          ? Math.floor(credentials.expiry_date / 1000)
          : Math.floor(Date.now() / 1000) + 3600;
        const scope = credentials.scope || row.scope;

        db.run(
          `UPDATE google_tokens
           SET access_token = ?, expires_at_unix = ?, scope = ?, updated_at = CURRENT_TIMESTAMP
           WHERE email = ? AND client_id = ?`,
          [accessToken, expiresAtUnix, scope, row.email, row.client_id],
          (updateErr) => {
            if (updateErr) {
              console.error('Failed to update refreshed google_tokens:', updateErr);
              return res.status(500).json({ error: 'Failed to update refreshed token.' });
            }
            res.status(200).json({
              success: true,
              accessToken,
              expiresAtUnix,
              scope
            });
          }
        );
      } catch (refreshErr) {
        console.error('Google token refresh failed:', refreshErr.message);
        const oauthErrCode = refreshErr?.response?.data?.error;
        const status = refreshErr?.response?.status ?? refreshErr?.status;
        const isInvalidGrant = oauthErrCode === 'invalid_grant' || String(refreshErr?.message || '').includes('invalid_grant');
        if (isInvalidGrant || status === 400 || status === 401) {
          if (isInvalidGrant) {
            db.run('UPDATE google_tokens SET refresh_token = NULL, updated_at = CURRENT_TIMESTAMP WHERE email = ? AND client_id = ?', [row.email, row.client_id]);
          }
          return res.status(401).json({ error: 'reauth_required' });
        }
        res.status(502).json({ error: 'Failed to refresh Google access token.' });
      }
    }
  );
});

// 8.2 Disconnect / revoke per-app Google OAuth tokens
app.post('/api/auth/google/disconnect', (req, res) => {
  const { client_id, session_token } = req.body || {};
  if (!client_id || !session_token) {
    return res.status(400).json({ error: 'Missing client_id or session_token.' });
  }

  db.get(
    'SELECT access_token, refresh_token FROM google_tokens WHERE client_id = ? AND session_token = ?',
    [client_id, session_token],
    async (err, row) => {
      if (err) {
        console.error('Database error reading google_tokens for disconnect:', err);
        return res.status(500).json({ error: 'Database error.' });
      }

      if (row) {
        const tokenToRevoke = row.refresh_token || row.access_token;
        if (tokenToRevoke) {
          try {
            await fetch(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(tokenToRevoke)}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });
          } catch (revokeErr) {
            console.warn('Best-effort Google token revoke failed:', revokeErr.message);
          }
        }
      }

      db.run(
        'DELETE FROM google_tokens WHERE client_id = ? AND session_token = ?',
        [client_id, session_token],
        (delErr) => {
          if (delErr) {
            console.error('Failed to delete google_tokens on disconnect:', delErr);
            return res.status(500).json({ error: 'Failed to disconnect Google tokens.' });
          }
          res.status(200).json({ success: true });
        }
      );
    }
  );
});

// Helper to render custom 404 HTML page for missing resources
function send404Page(req, res) {
  res.status(404).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>404 - Page Not Found | KBS Auth</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: #0b0f19;
      color: #f3f4f6;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 24px;
    }
    .card {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 16px;
      padding: 48px 36px;
      max-width: 480px;
      width: 100%;
      text-align: center;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
    }
    .badge {
      display: inline-block;
      font-size: 14px;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: #818cf8;
      background: rgba(99, 102, 241, 0.15);
      border: 1px solid rgba(99, 102, 241, 0.3);
      padding: 4px 12px;
      border-radius: 9999px;
      margin-bottom: 20px;
    }
    h1 {
      font-size: 28px;
      font-weight: 800;
      color: #ffffff;
      margin-bottom: 12px;
    }
    p {
      color: #9ca3af;
      font-size: 15px;
      line-height: 1.6;
      margin-bottom: 28px;
    }
    code {
      background: #1f2937;
      color: #f43f5e;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 14px;
      font-family: monospace;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
      color: #ffffff;
      font-weight: 600;
      font-size: 15px;
      padding: 12px 24px;
      border-radius: 10px;
      text-decoration: none;
      box-shadow: 0 4px 14px 0 rgba(79, 70, 229, 0.4);
      transition: all 0.2s ease;
    }
    .btn:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 20px 0 rgba(79, 70, 229, 0.6);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">404 Error</div>
    <h1>Page Not Found</h1>
    <p>The page <code>${req.path}</code> is no longer hosted or has been moved.</p>
    <a href="/" class="btn">Return to Homepage</a>
  </div>
</body>
</html>`);
}

// Serves the client SPA files in production
app.use(express.static(path.join(__dirname, 'dist')));
app.get('*splat', (req, res) => {
  if (req.path === '/' || req.path === '/index.html') {
    return res.sendFile(path.join(__dirname, 'dist', 'index.html'));
  }
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: 'Not Found' });
  }
  send404Page(req, res);
});

app.listen(PORT, () => {
  console.log(`KBS-Auth service running on port ${PORT}`);
});

if (process.env.FRONTEND_PORT && String(process.env.FRONTEND_PORT) !== String(PORT)) {
  const frontendApp = express();
  const http = require('http');

  // Proxy API requests to the backend server
  frontendApp.all('/api/*splat', (req, res) => {
    const connector = http.request({
      host: 'localhost',
      port: PORT,
      path: req.originalUrl,
      method: req.method,
      headers: req.headers
    }, (connectorRes) => {
      res.writeHead(connectorRes.statusCode, connectorRes.headers);
      connectorRes.pipe(res);
    });

    req.pipe(connector);

    connector.on('error', (err) => {
      console.error('Auth frontend proxy error:', err);
      res.status(502).send('Bad Gateway');
    });
  });

  frontendApp.use(express.static(path.join(__dirname, 'dist')));
  frontendApp.get('*splat', (req, res) => {
    if (req.path === '/' || req.path === '/index.html') {
      return res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    }
    send404Page(req, res);
  });
  frontendApp.listen(process.env.FRONTEND_PORT, () => {
    console.log(`KBS-Auth static frontend server running on port ${process.env.FRONTEND_PORT}`);
  });
}
