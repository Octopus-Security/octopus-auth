const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { Op } = require('sequelize');
const { User, InviteCode, BannedIP, initDatabase } = require('./database');
const { createAuthMiddleware, requireRole } = require('@octopus-security/auth-client');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');

// TOTP window: allow 1 step before/after (30-second grace for clock drift)
authenticator.options = { window: 1 };

const app = express();
const PORT = process.env.PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || 'octopus-shared-secret-change-in-production';

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// Per-request CSP nonce so the central login page's inline script can run while
// keeping a strict script-src (no blanket 'unsafe-inline').
app.use((req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    next();
});
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            'script-src': ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
        },
    },
}));
app.use(cors({
    origin: (origin, cb) => {
        if (!origin) return cb(null, true);
        const ok = /^https:\/\/([a-z0-9-]+\.)?octopustechnology\.net$/.test(origin)
                || /^http:\/\/localhost:\d+$/.test(origin);
        cb(ok ? null : new Error('Not allowed by CORS'), ok);
    },
    credentials: true,
}));
app.use(express.json());

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { success: false, error: 'Too many requests, please try again later.' }
});

// In-memory failed-login counter (bans persist in SQLite)
const failedAttempts = new Map();
const MAX_FAILURES   = 5;

function getClientIP(req) {
    const fwd = req.headers['x-forwarded-for'];
    return (fwd ? fwd.split(',')[0].trim() : req.ip || '').replace('::ffff:', '');
}

async function recordFailure(ip) {
    const count = (failedAttempts.get(ip) || 0) + 1;
    failedAttempts.set(ip, count);
    if (count >= MAX_FAILURES) {
        await BannedIP.findOrCreate({ where: { ip }, defaults: { reason: `${MAX_FAILURES} failed login attempts` } });
        failedAttempts.delete(ip);
        return true;
    }
    return false;
}

const authenticate = createAuthMiddleware();

function validatePassword(password) {
    if (password.length < 12) return 'Password must be at least 12 characters';
    if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter';
    if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase letter';
    if (!/[0-9]/.test(password)) return 'Password must contain at least one number';
    if (!/[^A-Za-z0-9]/.test(password)) return 'Password must contain at least one symbol (!@#$% etc.)';
    return null;
}

// When true, every account must have TOTP 2FA. Accounts without it cannot get a
// session — login/register return an enrollment challenge instead. Enforced by
// default: only an explicit REQUIRE_2FA=false disables it. Accounts that already
// have 2FA (e.g. the admin) are unaffected; only 2FA-less accounts hit enrollment.
const REQUIRE_2FA = String(process.env.REQUIRE_2FA ?? 'true').toLowerCase() !== 'false';

function makeToken(user) {
    return jwt.sign(
        { userId: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

// Short-lived token that ONLY authorizes completing first-time TOTP enrollment —
// it is not a session and carries no role.
function makeEnrollToken(user) {
    return jwt.sign(
        { userId: user.id, username: user.username, purpose: 'totp-enroll' },
        JWT_SECRET,
        { expiresIn: '10m' }
    );
}

// Build the response sent when a 2FA-less account must enroll: a fresh secret +
// QR for the authenticator app, plus the enrollToken to complete via /totp/enroll.
async function buildEnrollmentResponse(user) {
    const secret     = authenticator.generateSecret(20);
    const otpauthUrl = authenticator.keyuri(user.username, 'OctopusTechnology', secret);
    const qrDataUrl  = await QRCode.toDataURL(otpauthUrl);
    return {
        success: false,
        requiresEnrollment: true,
        message: '2FA setup is required before you can sign in.',
        enrollToken: makeEnrollToken(user),
        secret, otpauthUrl, qrDataUrl,
    };
}

app.get('/health', (req, res) => res.json({ status: 'ok', service: 'octopus-auth' }));

// ── Register ──────────────────────────────────────────────────────────────────
app.post('/api/auth/register', authLimiter, async (req, res) => {
    try {
        const { username, password, email, inviteCode } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password are required' });
        }
        if (username.length < 3 || username.length > 30) {
            return res.status(400).json({ success: false, error: 'Username must be 3-30 characters' });
        }
        const pwError = validatePassword(password);
        if (pwError) return res.status(400).json({ success: false, error: pwError });
        if (!inviteCode) {
            return res.status(400).json({ success: false, error: 'An invite code is required to register' });
        }

        const invite = await InviteCode.findOne({ where: { code: inviteCode, used: false } });
        if (!invite) {
            return res.status(400).json({ success: false, error: 'Invalid or already used invite code' });
        }
        if (invite.expiresAt && new Date() > invite.expiresAt) {
            return res.status(400).json({ success: false, error: 'Invite code has expired' });
        }

        const existingUser = await User.findOne({ where: { username } });
        if (existingUser) {
            return res.status(409).json({ success: false, error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const user = await User.create({
            username,
            password: hashedPassword,
            email: email || null,
            role: 'user',
            isActive: true
        });

        invite.used = true;
        invite.usedBy = user.id;
        await invite.save();

        // Mandatory 2FA: new accounts must enroll before getting a session.
        if (REQUIRE_2FA) {
            return res.status(201).json(await buildEnrollmentResponse(user));
        }

        const token = makeToken(user);
        res.status(201).json({ success: true, message: 'User registered successfully', token, userId: user.id, username: user.username, role: user.role });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, error: 'Registration failed' });
    }
});

// ── Login ─────────────────────────────────────────────────────────────────────
// Always returns the same generic error for any failure — no enumeration of
// whether the username, password, or 2FA code was wrong.
const GENERIC_AUTH_ERROR = 'Credentials or 2FA incorrect';

app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { username, password, totpCode } = req.body;
        const ip = getClientIP(req);

        // IP ban check
        const ban = await BannedIP.findOne({ where: { ip } });
        if (ban) {
            return res.status(403).json({ success: false, error: 'Your IP is banned due to too many failed login attempts.' });
        }

        if (!username || !password) {
            return res.status(400).json({ success: false, error: GENERIC_AUTH_ERROR });
        }

        const user = await User.findOne({ where: { username } });
        const passwordOk = user && user.isActive && await bcrypt.compare(password, user.password);

        if (!passwordOk) {
            const nowBanned = await recordFailure(ip);
            if (nowBanned) return res.status(403).json({ success: false, error: 'Your IP has been banned after too many failed login attempts.' });
            return res.status(401).json({ success: false, error: GENERIC_AUTH_ERROR });
        }

        // If TOTP is enabled, verify the code — same generic error on failure.
        if (user.totpEnabled && user.totpSecret) {
            const codeStr = String(totpCode || '').replace(/\D/g, '');
            const totpOk  = codeStr.length > 0 && authenticator.verify({ token: codeStr, secret: user.totpSecret });
            if (!totpOk) {
                const nowBanned = await recordFailure(ip);
                if (nowBanned) return res.status(403).json({ success: false, error: 'Your IP has been banned after too many failed login attempts.' });
                return res.status(401).json({ success: false, error: GENERIC_AUTH_ERROR });
            }
        } else if (REQUIRE_2FA) {
            // Password is correct but the account has no 2FA — mandatory enrollment.
            // Issue an enroll challenge instead of a session.
            failedAttempts.delete(ip);
            return res.json(await buildEnrollmentResponse(user));
        }

        failedAttempts.delete(ip);
        user.lastLogin = new Date();
        await user.save();

        const token = makeToken(user);
        res.json({ success: true, message: 'Login successful', token, username: user.username, role: user.role });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Login failed' });
    }
});

// ── Verify ────────────────────────────────────────────────────────────────────
app.post('/api/auth/verify', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, valid: false, error: 'No token provided' });
        }
        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findByPk(decoded.userId);
        if (!user || !user.isActive) {
            return res.status(401).json({ success: false, valid: false, error: 'User not found or disabled' });
        }
        res.json({ success: true, valid: true, user: { userId: decoded.userId, username: decoded.username, role: decoded.role || 'user' } });
    } catch (error) {
        res.status(401).json({ success: false, valid: false, error: 'Invalid token' });
    }
});

// ── Refresh ───────────────────────────────────────────────────────────────────
app.post('/api/auth/refresh', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, error: 'No token provided' });
        }
        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findByPk(decoded.userId);
        if (!user || !user.isActive) {
            return res.status(401).json({ success: false, error: 'User not found or disabled' });
        }
        res.json({ success: true, token: makeToken(user) });
    } catch (error) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

// ── Invite codes (admin only) ─────────────────────────────────────────────────
app.post('/api/auth/invites', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const { expiresInDays, label } = req.body;
        const code = crypto.randomBytes(9).toString('base64url');
        const expiresAt = expiresInDays
            ? new Date(Date.now() + expiresInDays * 86400000)
            : null;
        const invite = await InviteCode.create({ code, createdBy: req.user.userId, label: label || null, expiresAt });
        res.status(201).json({ success: true, code: invite.code, label: invite.label, expiresAt: invite.expiresAt });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to create invite code' });
    }
});

app.get('/api/auth/invites', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const invites = await InviteCode.findAll({ order: [['createdAt', 'DESC']] });
        res.json({ success: true, invites });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch invites' });
    }
});

app.delete('/api/auth/invites/:id', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const invite = await InviteCode.findByPk(req.params.id);
        if (!invite) return res.status(404).json({ success: false, error: 'Invite not found' });
        if (invite.used) return res.status(400).json({ success: false, error: 'Cannot delete a used invite code' });
        await invite.destroy();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to delete invite' });
    }
});

// ── Admin: user management ────────────────────────────────────────────────────
app.get('/api/auth/users', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const users = await User.findAll({
            attributes: ['id', 'username', 'email', 'role', 'isActive', 'lastLogin', 'createdAt'],
            order: [['createdAt', 'DESC']]
        });
        res.json({ success: true, users });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch users' });
    }
});

app.patch('/api/auth/users/:id', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id);
        if (!user) return res.status(404).json({ success: false, error: 'User not found' });
        const { isActive, role } = req.body;
        if (isActive !== undefined) user.isActive = isActive;
        if (role !== undefined) user.role = role;
        await user.save();
        res.json({ success: true, user: { id: user.id, username: user.username, role: user.role, isActive: user.isActive } });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to update user' });
    }
});

app.post('/api/auth/users', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const { username, password, email, role } = req.body;
        if (!username || !password) return res.status(400).json({ success: false, error: 'Username and password are required' });
        if (username.length < 3 || username.length > 30) return res.status(400).json({ success: false, error: 'Username must be 3-30 characters' });
        const pwError = validatePassword(password);
        if (pwError) return res.status(400).json({ success: false, error: pwError });
        const existing = await User.findOne({ where: { username } });
        if (existing) return res.status(409).json({ success: false, error: 'Username already exists' });
        const hashedPassword = await bcrypt.hash(password, 12);
        const user = await User.create({ username, password: hashedPassword, email: email || null, role: role || 'user' });
        res.status(201).json({ success: true, user: { id: user.id, username: user.username, role: user.role, isActive: user.isActive } });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to create user' });
    }
});

app.delete('/api/auth/users/:id', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id);
        if (!user) return res.status(404).json({ success: false, error: 'User not found' });
        // Prevent deleting the only admin
        if (user.role === 'admin') {
            const adminCount = await User.count({ where: { role: 'admin' } });
            if (adminCount <= 1) return res.status(400).json({ success: false, error: 'Cannot delete the last admin account' });
        }
        await user.destroy();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to delete user' });
    }
});

app.post('/api/auth/users/:id/password-reset', authenticate, requireRole('admin'), async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id);
        if (!user) return res.status(404).json({ success: false, error: 'User not found' });
        const token = crypto.randomBytes(32).toString('hex');
        user.resetToken = token;
        user.resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
        await user.save();
        const baseUrl = process.env.AUTH_PUBLIC_URL || `http://localhost:${process.env.PORT || 3002}`;
        res.json({ success: true, resetUrl: `${baseUrl}/reset-password?token=${token}`, expiresAt: user.resetTokenExpiry });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to generate reset token' });
    }
});

// ── Public: password reset via token ─────────────────────────────────────────

app.post('/api/auth/password-reset/use', authLimiter, async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) return res.status(400).json({ success: false, error: 'Token and new password are required' });
        const pwError = validatePassword(newPassword);
        if (pwError) return res.status(400).json({ success: false, error: pwError });
        const user = await User.findOne({ where: { resetToken: token } });
        if (!user || !user.resetTokenExpiry || new Date() > user.resetTokenExpiry) {
            return res.status(400).json({ success: false, error: 'Reset link is invalid or has expired' });
        }
        user.password = await bcrypt.hash(newPassword, 12);
        user.resetToken = null;
        user.resetTokenExpiry = null;
        await user.save();
        res.json({ success: true, message: 'Password updated — you can now sign in' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to reset password' });
    }
});

app.get('/reset-password', (req, res) => {
    const { token } = req.query;
    res.type('html').send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reset password · OctopusTechnology</title>
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#0e1116;color:#e6edf3;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  .card{width:340px;max-width:92vw;background:#161b22;border:1px solid #30363d;border-radius:14px;padding:28px}
  h1{font-size:1.2rem;margin:0 0 4px;text-align:center}
  .sub{color:#8b949e;font-size:.85rem;text-align:center;margin-bottom:20px}
  label{display:block;font-size:.8rem;color:#8b949e;margin:12px 0 4px}
  input{width:100%;padding:10px;border:1px solid #30363d;border-radius:8px;background:#0d1117;color:#e6edf3;font-size:.95rem}
  button{width:100%;margin-top:18px;padding:11px;border:0;border-radius:8px;background:#2ea043;color:#fff;font-weight:600;font-size:.95rem;cursor:pointer}
  button:hover{background:#2c974b}
  .err{color:#f85149;font-size:.85rem;margin-top:12px;min-height:1em;text-align:center}
  .ok{color:#3fb950;font-size:.85rem;margin-top:12px;text-align:center}
</style></head><body>
<div class="card">
  <h1>🐙 OctopusTechnology</h1>
  <div class="sub">Set a new password</div>
  <form id="f">
    <label>New password</label><input name="pw" type="password" autocomplete="new-password" required autofocus>
    <label>Confirm password</label><input name="pw2" type="password" autocomplete="new-password" required>
    <button type="submit">Set password</button>
  </form>
  <div class="err" id="err"></div>
  <div class="ok hidden" id="ok"></div>
</div>
<script>
const TOKEN = ${JSON.stringify(token || '')};
document.querySelector('.hidden')?.classList?.remove('hidden');
document.getElementById('f').addEventListener('submit', async e => {
  e.preventDefault();
  const pw = e.target.pw.value, pw2 = e.target.pw2.value;
  document.getElementById('err').textContent = '';
  if (pw !== pw2) { document.getElementById('err').textContent = 'Passwords do not match'; return; }
  const r = await fetch('/api/auth/password-reset/use', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: TOKEN, newPassword: pw }),
  }).then(x => x.json());
  if (r.success) {
    document.getElementById('f').style.display = 'none';
    document.getElementById('ok').textContent = r.message + ' Redirecting to sign in…';
    setTimeout(() => window.location.href = '/login', 2500);
  } else {
    document.getElementById('err').textContent = r.error || 'Reset failed';
  }
});
</script>
</body></html>`);
});

// ── Password change ───────────────────────────────────────────────────────────
app.post('/api/auth/password', authenticate, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) {
            return res.status(400).json({ success: false, error: 'Old and new password required' });
        }
        const pwError = validatePassword(newPassword);
        if (pwError) return res.status(400).json({ success: false, error: pwError });
        const user = await User.findByPk(req.user.userId);
        if (!user || !await bcrypt.compare(oldPassword, user.password)) {
            return res.status(401).json({ success: false, error: 'Current password is incorrect' });
        }
        user.password = await bcrypt.hash(newPassword, 12);
        await user.save();
        res.json({ success: true, message: 'Password updated' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to update password' });
    }
});

// ── TOTP 2FA ──────────────────────────────────────────────────────────────────

// GET /api/auth/totp/status — is TOTP enabled for the current user?
app.get('/api/auth/totp/status', authenticate, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.userId);
        if (!user) return res.status(404).json({ success: false, error: 'User not found' });
        res.json({ success: true, enabled: !!user.totpEnabled });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Failed to get TOTP status' });
    }
});

// POST /api/auth/totp/setup — generate a new TOTP secret + QR code (does NOT save yet)
app.post('/api/auth/totp/setup', authenticate, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.userId);
        if (!user) return res.status(404).json({ success: false, error: 'User not found' });

        const secret = authenticator.generateSecret(20);
        const otpauthUrl = authenticator.keyuri(user.username, 'OctopusTechnology', secret);
        const qrDataUrl = await QRCode.toDataURL(otpauthUrl);

        res.json({ success: true, secret, otpauthUrl, qrDataUrl });
    } catch (err) {
        console.error('TOTP setup error:', err);
        res.status(500).json({ success: false, error: 'Failed to generate TOTP secret' });
    }
});

// POST /api/auth/totp/enable — verify a code against the generated secret, then save
// Body: { secret, code }
app.post('/api/auth/totp/enable', authenticate, async (req, res) => {
    try {
        const { secret, code } = req.body;
        if (!secret || !code) return res.status(400).json({ success: false, error: 'secret and code are required' });

        const valid = authenticator.verify({ token: String(code).replace(/\D/g, ''), secret });
        if (!valid) return res.status(400).json({ success: false, error: 'Invalid code — make sure your authenticator app is synced and try again' });

        const user = await User.findByPk(req.user.userId);
        user.totpSecret  = secret;
        user.totpEnabled = true;
        await user.save();

        res.json({ success: true, message: '2FA enabled successfully' });
    } catch (err) {
        console.error('TOTP enable error:', err);
        res.status(500).json({ success: false, error: 'Failed to enable TOTP' });
    }
});

// POST /api/auth/totp/enroll — complete MANDATORY first-time 2FA enrollment.
// Authed by the short-lived enrollToken from login/register (no session yet).
// Body: { enrollToken, secret, code }  (secret comes from the enrollment response)
app.post('/api/auth/totp/enroll', authLimiter, async (req, res) => {
    try {
        const { enrollToken, secret, code } = req.body;
        if (!enrollToken || !secret || !code) {
            return res.status(400).json({ success: false, error: 'enrollToken, secret and code are required' });
        }

        let decoded;
        try {
            decoded = jwt.verify(enrollToken, JWT_SECRET);
        } catch {
            return res.status(401).json({ success: false, error: 'Enrollment session expired. Please log in again.' });
        }
        if (decoded.purpose !== 'totp-enroll') {
            return res.status(401).json({ success: false, error: 'Invalid enrollment token' });
        }

        const user = await User.findByPk(decoded.userId);
        if (!user || !user.isActive) {
            return res.status(401).json({ success: false, error: 'User not found' });
        }

        const valid = authenticator.verify({ token: String(code).replace(/\D/g, ''), secret });
        if (!valid) {
            return res.status(400).json({ success: false, error: 'Invalid code — make sure your authenticator app is synced and try again' });
        }

        user.totpSecret  = secret;
        user.totpEnabled = true;
        user.lastLogin   = new Date();
        await user.save();

        // Enrollment complete — issue a real session token.
        const token = makeToken(user);
        res.json({ success: true, message: '2FA enabled', token, username: user.username, role: user.role });
    } catch (err) {
        console.error('TOTP enroll error:', err);
        res.status(500).json({ success: false, error: 'Enrollment failed' });
    }
});

// DELETE /api/auth/totp/disable — disable TOTP (requires current password + TOTP code)
// Body: { password, code }
app.delete('/api/auth/totp/disable', authenticate, async (req, res) => {
    try {
        if (REQUIRE_2FA) {
            return res.status(403).json({ success: false, error: '2FA is required and cannot be disabled.' });
        }
        const { password, code } = req.body;
        if (!password || !code) return res.status(400).json({ success: false, error: 'password and code are required' });

        const user = await User.findByPk(req.user.userId);
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ success: false, error: 'Incorrect password' });
        }
        if (user.totpEnabled && user.totpSecret) {
            const valid = authenticator.verify({ token: String(code).replace(/\D/g, ''), secret: user.totpSecret });
            if (!valid) return res.status(400).json({ success: false, error: 'Invalid 2FA code' });
        }

        user.totpSecret  = null;
        user.totpEnabled = false;
        await user.save();

        res.json({ success: true, message: '2FA disabled' });
    } catch (err) {
        console.error('TOTP disable error:', err);
        res.status(500).json({ success: false, error: 'Failed to disable TOTP' });
    }
});

// POST /api/auth/totp/verify — complete a 2FA challenge
// Body: { challengeToken, code }
app.post('/api/auth/totp/verify', authLimiter, async (req, res) => {
    try {
        const { challengeToken, code } = req.body;
        if (!challengeToken || !code) return res.status(400).json({ success: false, error: 'challengeToken and code are required' });

        let decoded;
        try {
            decoded = jwt.verify(challengeToken, JWT_SECRET);
        } catch {
            return res.status(401).json({ success: false, error: 'Challenge token expired or invalid. Please log in again.' });
        }
        if (decoded.purpose !== 'totp-challenge') {
            return res.status(401).json({ success: false, error: 'Invalid challenge token' });
        }

        const user = await User.findByPk(decoded.userId);
        if (!user || !user.isActive || !user.totpSecret) {
            return res.status(401).json({ success: false, error: 'User not found or 2FA not configured' });
        }

        const valid = authenticator.verify({ token: String(code).replace(/\D/g, ''), secret: user.totpSecret });
        if (!valid) {
            const ip = getClientIP(req);
            const nowBanned = await recordFailure(ip);
            if (nowBanned) return res.status(403).json({ success: false, error: 'Too many failed attempts. Your IP has been banned.' });
            return res.status(401).json({ success: false, error: 'Invalid 2FA code' });
        }

        // TOTP verified — clear failure counter, update lastLogin, issue real JWT
        const ip = getClientIP(req);
        failedAttempts.delete(ip);
        user.lastLogin = new Date();
        await user.save();

        const token = makeToken(user);
        res.json({ success: true, token, username: user.username, role: user.role });
    } catch (err) {
        console.error('TOTP verify error:', err);
        res.status(500).json({ success: false, error: 'Verification failed' });
    }
});

// ── Central SSO login ───────────────────────────────────────────────────────
// One login page for every octopustechnology.net app. On success it sets a JWT
// cookie scoped to the whole domain so the session is shared across subdomains.

const SSO_COOKIE = 'octopus_sso';

// Only ever redirect back to our own apps — block open redirects.
function safeRedirect(target) {
    try {
        const u = new URL(target);
        if (u.protocol === 'https:' && /(^|\.)octopustechnology\.net$/.test(u.hostname)) return u.toString();
    } catch { /* fall through */ }
    return 'https://octopustechnology.net';
}

// POST /api/auth/sso/session { token } — validate a session token and set the
// shared HttpOnly cookie. Rejects challenge/enroll tokens (they carry `purpose`).
app.post('/api/auth/sso/session', authLimiter, (req, res) => {
    try {
        const { token } = req.body;
        if (!token) return res.status(400).json({ success: false, error: 'token required' });
        let decoded;
        try { decoded = jwt.verify(token, JWT_SECRET); }
        catch { return res.status(401).json({ success: false, error: 'invalid token' }); }
        if (decoded.purpose) return res.status(401).json({ success: false, error: 'not a session token' });
        res.cookie(SSO_COOKIE, token, {
            domain: '.octopustechnology.net',
            httpOnly: true, secure: true, sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, error: 'session failed' });
    }
});

// GET /logout — clear the shared cookie and bounce back.
app.get('/logout', (req, res) => {
    res.clearCookie(SSO_COOKIE, { domain: '.octopustechnology.net' });
    res.redirect(safeRedirect(req.query.redirect));
});

// GET /login?redirect=<app-url> — the single login page.
app.get('/login', (req, res) => {
    const redirect = safeRedirect(req.query.redirect);
    res.type('html').send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in · OctopusTechnology</title>
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#0e1116;color:#e6edf3;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  .card{width:340px;max-width:92vw;background:#161b22;border:1px solid #30363d;border-radius:14px;padding:28px}
  h1{font-size:1.2rem;margin:0 0 4px;text-align:center}
  .sub{color:#8b949e;font-size:.85rem;text-align:center;margin-bottom:20px}
  label{display:block;font-size:.8rem;color:#8b949e;margin:12px 0 4px}
  input{width:100%;padding:10px;border:1px solid #30363d;border-radius:8px;background:#0d1117;color:#e6edf3;font-size:.95rem}
  button{width:100%;margin-top:18px;padding:11px;border:0;border-radius:8px;background:#2ea043;color:#fff;font-weight:600;font-size:.95rem;cursor:pointer}
  button:hover{background:#2c974b}
  .err{color:#f85149;font-size:.85rem;margin-top:12px;min-height:1em;text-align:center}
  .qr{display:block;margin:12px auto;width:180px;height:180px;background:#fff;border-radius:8px}
  .hint{color:#8b949e;font-size:.78rem;text-align:center;margin-top:8px}
  .hidden{display:none}
</style></head><body>
<div class="card">
  <h1>🐙 OctopusTechnology</h1>
  <div class="sub">Sign in to continue</div>

  <form id="loginForm">
    <label>Username</label><input name="username" autocomplete="username" required autofocus>
    <label>Password</label><input name="password" type="password" autocomplete="current-password" required>
    <label>2FA code</label><input name="totpCode" inputmode="numeric" autocomplete="one-time-code" placeholder="000 - 000" maxlength="9" style="text-align:center;letter-spacing:2px;font-variant-numeric:tabular-nums">
    <button type="submit">Sign in</button>
  </form>

  <form id="enrollForm" class="hidden">
    <div class="sub">Set up 2FA — scan this with your authenticator app, then enter the code.</div>
    <img id="qr" class="qr" alt="2FA QR code">
    <label>Authenticator code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="000 - 000" maxlength="9" required style="text-align:center;letter-spacing:2px;font-variant-numeric:tabular-nums">
    <button type="submit">Enable 2FA &amp; continue</button>
  </form>

  <div class="err" id="err"></div>
  <div class="hint" id="hint"></div>
</div>

<script nonce="${res.locals.cspNonce}">
const REDIRECT = ${JSON.stringify(redirect)};
const $ = s => document.querySelector(s);
const err = m => { $('#err').textContent = m || ''; };
let enroll = null; // { enrollToken, secret }

// Format 2FA inputs as "000 - 000" while typing (server strips non-digits).
function bindOtpFormat(input){
  input.addEventListener('input', () => {
    const d = input.value.replace(/\\D/g, '').slice(0, 6);
    input.value = d.length > 3 ? d.slice(0, 3) + ' - ' + d.slice(3) : d;
  });
}
document.querySelectorAll('input[autocomplete="one-time-code"]').forEach(bindOtpFormat);

async function post(url, body){
  const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'include', body: JSON.stringify(body) });
  return r.json();
}
async function setSessionAndGo(token){
  const s = await post('/api/auth/sso/session', { token });
  if (s.success) { window.location.href = REDIRECT; }
  else err(s.error || 'Could not start session');
}

$('#loginForm').addEventListener('submit', async e => {
  e.preventDefault(); err('');
  const f = e.target;
  const data = await post('/api/auth/login', {
    username: f.username.value, password: f.password.value, totpCode: f.totpCode.value,
  });
  if (data.success && data.token) return setSessionAndGo(data.token);
  if (data.requiresEnrollment) {
    enroll = { enrollToken: data.enrollToken, secret: data.secret };
    $('#qr').src = data.qrDataUrl;
    $('#loginForm').classList.add('hidden');
    $('#enrollForm').classList.remove('hidden');
    $('#hint').textContent = 'Secret: ' + data.secret;
    return;
  }
  err(data.error || 'Sign in failed');
});

$('#enrollForm').addEventListener('submit', async e => {
  e.preventDefault(); err('');
  const data = await post('/api/auth/totp/enroll', {
    enrollToken: enroll.enrollToken, secret: enroll.secret, code: e.target.code.value,
  });
  if (data.success && data.token) return setSessionAndGo(data.token);
  err(data.error || 'Enrollment failed');
});
</script>
</body></html>`);
});

if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'octopus-shared-secret-change-in-production') {
    console.error('FATAL: JWT_SECRET is unset in production. Refusing to start with the default secret.');
    process.exit(1);
}

initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Octopus Auth Service running on port ${PORT}`);
    });
});

module.exports = { app, JWT_SECRET };
