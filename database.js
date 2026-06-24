const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: path.join(__dirname, 'data', 'auth.db'),
    logging: false
});

const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING,
        allowNull: true,
        unique: true
    },
    role: {
        type: DataTypes.STRING,
        allowNull: false,
        defaultValue: 'user'
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    },
    lastLogin: {
        type: DataTypes.DATE,
        allowNull: true
    },
    totpSecret: {
        type: DataTypes.STRING,
        allowNull: true,
        defaultValue: null
    },
    totpEnabled: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    }
});

const InviteCode = sequelize.define('InviteCode', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    code: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    createdBy: {
        type: DataTypes.INTEGER,
        allowNull: false
    },
    usedBy: {
        type: DataTypes.INTEGER,
        allowNull: true
    },
    used: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    },
    label: {
        type: DataTypes.STRING,
        allowNull: true
    },
    expiresAt: {
        type: DataTypes.DATE,
        allowNull: true
    }
});

const BannedIP = sequelize.define('BannedIP', {
    id:       { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    ip:       { type: DataTypes.STRING, allowNull: false, unique: true },
    reason:   { type: DataTypes.STRING, defaultValue: '5 failed login attempts' },
    bannedAt: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
}, { timestamps: false });

const initDatabase = async () => {
    try {
        await sequelize.sync({ alter: true });
        console.log('Auth database initialized');
    } catch (error) {
        console.error('Database initialization error:', error);
    }
};

module.exports = { sequelize, User, InviteCode, BannedIP, initDatabase };
