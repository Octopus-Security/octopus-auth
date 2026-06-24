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

app.use(helmet());
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

function makeToken(user) {
    return jwt.sign(
        { userId: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
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
            const codeStr = String(totpCode || '').replace(/\s/g, '');
            const totpOk  = codeStr.length > 0 && authenticator.verify({ token: codeStr, secret: user.totpSecret });
            if (!totpOk) {
                const nowBanned = await recordFailure(ip);
                if (nowBanned) return res.status(403).json({ success: false, error: 'Your IP has been banned after too many failed login attempts.' });
                return res.status(401).json({ success: false, error: GENERIC_AUTH_ERROR });
            }
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

        const valid = authenticator.verify({ token: String(code).replace(/\s/g, ''), secret });
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

// DELETE /api/auth/totp/disable — disable TOTP (requires current password + TOTP code)
// Body: { password, code }
app.delete('/api/auth/totp/disable', authenticate, async (req, res) => {
    try {
        const { password, code } = req.body;
        if (!password || !code) return res.status(400).json({ success: false, error: 'password and code are required' });

        const user = await User.findByPk(req.user.userId);
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ success: false, error: 'Incorrect password' });
        }
        if (user.totpEnabled && user.totpSecret) {
            const valid = authenticator.verify({ token: String(code).replace(/\s/g, ''), secret: user.totpSecret });
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

        const valid = authenticator.verify({ token: String(code).replace(/\s/g, ''), secret: user.totpSecret });
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
