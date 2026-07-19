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
      req.user = {
        uid: decoded.uid,
        email: decoded.email || '',
        emailVerified: Boolean(decoded.email_verified),
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

function requireAdmin(req: Request, res: Response, next: NextFunction): Response | void {
  const adminList = (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);

  if (!adminList.length) return res.status(403).json({ error: 'Admin access not configured' });
  if (!req.user?.email || !adminList.includes(req.user.email.toLowerCase())) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

export { initFirebaseAdmin, createRequireAuth, requireAuth, requireAdmin, deleteFirebaseUser };
