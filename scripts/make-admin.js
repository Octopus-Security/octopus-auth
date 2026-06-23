const { User, initDatabase } = require('../database');

const username = process.argv[2];
if (!username) {
    console.error('Usage: node scripts/make-admin.js <username>');
    process.exit(1);
}

initDatabase().then(async () => {
    const user = await User.findOne({ where: { username } });
    if (!user) {
        console.error(`User "${username}" not found`);
        process.exit(1);
    }
    user.role = 'admin';
    await user.save();
    console.log(`✓ ${username} is now an admin`);
    process.exit(0);
});
