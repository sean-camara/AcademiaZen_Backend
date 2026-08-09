const { getAuth } = require('firebase-admin/auth');

async function seedAdminUser() {
  const adminEmail = 'admin123@admin.com';
  const adminPassword = 'Admin#123';
  try {
    let userRecord;
    try {
      userRecord = await getAuth().getUserByEmail(adminEmail);
    } catch (err) {
      if (err.code === 'auth/user-not-found') {
        userRecord = await getAuth().createUser({
          email: adminEmail,
          password: adminPassword,
          displayName: 'System Administrator',
          emailVerified: true,
        });
        console.log(`[AdminSeeder] Created Firebase user for ${adminEmail}`);
      } else {
        console.warn(`[AdminSeeder] getUserByEmail error: ${err.message}`);
        return;
      }
    }

    // Set custom claims for admin
    try {
      await getAuth().setCustomUserClaims(userRecord.uid, { admin: true, role: 'admin' });
    } catch (claimErr) {
      console.warn(`[AdminSeeder] Custom claims warning: ${claimErr.message}`);
    }

    // Seed in MongoDB
    const { User, getDefaultState } = require('../models/User');
    let dbUser = await User.findOne({ $or: [{ email: adminEmail }, { uid: userRecord.uid }] });
    if (!dbUser) {
      dbUser = await User.create({
        uid: userRecord.uid,
        email: adminEmail,
        role: 'admin',
        state: getDefaultState(),
        billing: { plan: 'premium', status: 'active', interval: 'yearly' },
      });
      console.log(`[AdminSeeder] Created MongoDB admin user for ${adminEmail}`);
    } else {
      let modified = false;
      if (dbUser.role !== 'admin') {
        dbUser.role = 'admin';
        modified = true;
      }
      if (dbUser.email !== adminEmail) {
        dbUser.email = adminEmail;
        modified = true;
      }
      if (modified) {
        await dbUser.save();
        console.log(`[AdminSeeder] Updated MongoDB user ${adminEmail} to role: admin`);
      }
    }
  } catch (err) {
    console.error('[AdminSeeder] Seeder error:', err.message);
  }
}

module.exports = {
  seedAdminUser,
};
