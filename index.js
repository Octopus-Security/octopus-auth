const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { Op } = require('sequelize');
const { User, InviteCode, initDatabase } = require('./database');
const { createAuthMiddleware, requireRole } = require('@octopus-security/auth-client');
const fs = require('fs');
const path = require('path');

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
app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password are required' });
        }

        const user = await User.findOne({ where: { username } });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ success: false, error: 'Invalid username or password' });
        }

        if (!user.isActive) {
            return res.status(403).json({ success: false, error: 'Account is disabled' });
        }

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
        const { expiresInDays } = req.body;
        const code = crypto.randomBytes(9).toString('base64url');
        const expiresAt = expiresInDays
            ? new Date(Date.now() + expiresInDays * 86400000)
            : null;
        const invite = await InviteCode.create({ code, createdBy: req.user.userId, expiresAt });
        res.status(201).json({ success: true, code: invite.code, expiresAt: invite.expiresAt });
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
