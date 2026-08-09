import { cert, getApps, initializeApp, type App, type ServiceAccount } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import type { NextFunction, Request, Response } from 'express';

function initFirebaseAdmin(): App {
  const existing = getApps()[0];
  if (existing) return existing;

  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');

  let credential;
  if (serviceAccountJson) {
    credential = cert(JSON.parse(serviceAccountJson) as ServiceAccount);
  } else if (projectId && clientEmail && privateKey) {
    credential = cert({ projectId, clientEmail, privateKey });
  } else {
    throw new Error('Firebase Admin credentials are missing.');
  }

  return initializeApp({ credential });
}

interface VerifiedIdentity {
  uid: string;
  email?: string;
  email_verified?: boolean;
  admin?: boolean;
  role?: string;
}

type VerifyIdToken = (token: string) => Promise<VerifiedIdentity>;

function createRequireAuth(
  verifyIdToken: VerifyIdToken = (token) => getAuth().verifyIdToken(token),
) {
  return async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<Response | void> {
    try {
      const header = req.headers.authorization || '';
      const token = header.startsWith('Bearer ') ? header.slice(7) : null;
      if (!token) return res.status(401).json({ error: 'Missing auth token' });

      const decoded = await verifyIdToken(token);
      const isAdmin = Boolean(decoded.admin || decoded.role === 'admin');
      req.user = {
        uid: decoded.uid,
        email: decoded.email || '',
        emailVerified: Boolean(decoded.email_verified),
        ...(isAdmin ? { isAdminClaim: true } : {}),
      };
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid auth token' });
    }
  };
}

const requireAuth = createRequireAuth();

function hasErrorCode(error: unknown): error is { code: string } {
  return typeof error === 'object' && error !== null && 'code' in error && typeof error.code === 'string';
}

async function deleteFirebaseUser(uid: string): Promise<void> {
  try {
    await getAuth().deleteUser(uid);
  } catch (error: unknown) {
    if (!hasErrorCode(error) || error.code !== 'auth/user-not-found') throw error;
  }
}

async function requireAdmin(req: Request, res: Response, next: NextFunction): Promise<Response | void> {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Missing auth token' });
    }

    const rawEnv = process.env.ADMIN_EMAILS;
    const adminList = (rawEnv || '')
      .split(',')
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean);

    const userEmail = (req.user.email || '').toLowerCase();
    const isDefaultAdmin = userEmail === 'admin123@admin.com';

    if (!adminList.length && !isDefaultAdmin && !req.user.isAdminClaim) {
      return res.status(403).json({ error: 'Admin access not configured' });
    }

    const isConfiguredAdmin = adminList.includes(userEmail) || isDefaultAdmin;

    if (isConfiguredAdmin || req.user.isAdminClaim) {
      return next();
    }

    if (req.user.uid) {
      try {
        const { User } = require('../models/User');
        const user = await User.findOne({ uid: req.user.uid }).lean();
        if (user && user.role === 'admin') {
          return next();
        }
      } catch (dbErr) {
        console.warn('[requireAdmin] DB check fallback warning:', dbErr);
      }
    }

    return res.status(403).json({ error: 'Forbidden' });
  } catch (err) {
    console.error('[requireAdmin] Auth verification error:', err);
    return res.status(500).json({ error: 'Internal server error verifying admin status' });
  }
}

export { initFirebaseAdmin, createRequireAuth, requireAuth, requireAdmin, deleteFirebaseUser };
