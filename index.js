const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { User, initDatabase } = require('./database');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3002;

// JWT Secret - MUST be the same across all services
const JWT_SECRET = process.env.JWT_SECRET || 'octopus-shared-secret-change-in-production';

// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// Middleware
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

// Rate limiter
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20,
    message: { success: false, error: 'Too many requests, please try again later.' }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'octopus-auth' });
});

// Register endpoint
app.post('/api/auth/register', authLimiter, async (req, res) => {
    try {
        const { username, password, email } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password are required' });
        }

        if (username.length < 3 || username.length > 30) {
            return res.status(400).json({ success: false, error: 'Username must be 3-30 characters' });
        }

        if (password.length < 6) {
            return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
        }

        // Check if user exists
        const existingUser = await User.findOne({ where: { username } });
        if (existingUser) {
            return res.status(409).json({ success: false, error: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create user
        const user = await User.create({
            username,
            password: hashedPassword,
            email: email || null
        });

        // Generate token
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            token,
            userId: user.id,
            username: user.username
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, error: 'Registration failed' });
    }
});

// Login endpoint
app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password are required' });
        }

        // Find user
        const user = await User.findOne({ where: { username } });
        if (!user) {
            return res.status(401).json({ success: false, error: 'Invalid username or password' });
        }

        // Validate password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ success: false, error: 'Invalid username or password' });
        }

        // Generate token
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            message: 'Login successful',
            token,
            username: user.username
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Login failed' });
    }
});

// Verify token endpoint (for other services to validate tokens)
app.post('/api/auth/verify', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, valid: false, error: 'No token provided' });
        }

        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, JWT_SECRET);

        // Optionally verify user still exists
        const user = await User.findByPk(decoded.userId);
        if (!user) {
            return res.status(401).json({ success: false, valid: false, error: 'User not found' });
        }

        res.json({
            success: true,
            valid: true,
            user: {
                userId: decoded.userId,
                username: decoded.username
            }
        });
    } catch (error) {
        res.status(401).json({ success: false, valid: false, error: 'Invalid token' });
    }
});

// Refresh token endpoint
app.post('/api/auth/refresh', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, error: 'No token provided' });
        }

        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, JWT_SECRET);

        // Generate new token
        const newToken = jwt.sign(
            { userId: decoded.userId, username: decoded.username },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ success: true, token: newToken });
    } catch (error) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

// NOTE: The /api/auth/config endpoint that returned JWT_SECRET was removed —
// it leaked the signing secret to any caller. Services receive JWT_SECRET via
// their own environment (must match this service's JWT_SECRET).

// Fail fast if the shared secret was never configured in production
if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'octopus-shared-secret-change-in-production') {
    console.error('FATAL: JWT_SECRET is unset in production. Refusing to start with the default secret.');
    process.exit(1);
}

// Initialize and start
initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`🔐 Octopus Auth Service running on port ${PORT}`);
    });
});

module.exports = { app, JWT_SECRET };
