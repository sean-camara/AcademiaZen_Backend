const admin = require('firebase-admin');

function initFirebaseAdmin() {
  if (admin.apps.length > 0) return admin;

  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY
    ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    : undefined;

  let credential;
  if (serviceAccountJson) {
    credential = admin.credential.cert(JSON.parse(serviceAccountJson));
  } else if (projectId && clientEmail && privateKey) {
    credential = admin.credential.cert({ projectId, clientEmail, privateKey });
  } else {
    throw new Error('Firebase Admin credentials are missing.');
  }

  admin.initializeApp({ credential });
  return admin;
}

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing auth token' });

    const decoded = await admin.auth().verifyIdToken(token);
    req.user = {
      uid: decoded.uid,
      email: decoded.email || '',
      emailVerified: !!decoded.email_verified,
    };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid auth token' });
  }
}

function requireAdmin(req, res, next) {
  const adminList = (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);

  if (!adminList.length) return res.status(403).json({ error: 'Admin access not configured' });
  if (!req.user?.email || !adminList.includes(req.user.email.toLowerCase())) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

module.exports = {
  initFirebaseAdmin,
  requireAuth,
  requireAdmin,
};
