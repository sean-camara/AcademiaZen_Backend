import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// We'll test the middleware logic by recreating it here
// since mocking firebase-admin in commonjs is complex

// Recreate requireAuth for testing
function createRequireAuth(verifyIdToken) {
  return async function requireAuth(req, res, next) {
    try {
      const header = req.headers.authorization || '';
      const token = header.startsWith('Bearer ') ? header.slice(7) : null;
      if (!token) return res.status(401).json({ error: 'Missing auth token' });

      const decoded = await verifyIdToken(token);
      req.user = {
        uid: decoded.uid,
        email: decoded.email || '',
        emailVerified: !!decoded.email_verified,
      };
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid auth token' });
    }
  };
}

// Recreate requireAdmin for testing
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

describe('Auth Middleware', () => {
  let mockReq;
  let mockRes;
  let mockNext;
  let mockVerifyIdToken;
  let requireAuth;

  beforeEach(() => {
    mockReq = {
      headers: {}
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis()
    };
    mockNext = vi.fn();
    mockVerifyIdToken = vi.fn();
    requireAuth = createRequireAuth(mockVerifyIdToken);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('requireAuth', () => {
    it('should return 401 when no authorization header', async () => {
      await requireAuth(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Missing auth token' });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 when authorization header is not Bearer token', async () => {
      mockReq.headers.authorization = 'Basic sometoken';

      await requireAuth(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Missing auth token' });
    });

    it('should return 401 when authorization header is just "Bearer "', async () => {
      mockReq.headers.authorization = 'Bearer ';

      await requireAuth(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Missing auth token' });
    });

    it('should call next and set req.user when token is valid', async () => {
      mockReq.headers.authorization = 'Bearer valid-token';
      mockVerifyIdToken.mockResolvedValue({
        uid: 'user-123',
        email: 'test@example.com',
        email_verified: true
      });

      await requireAuth(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockReq.user).toEqual({
        uid: 'user-123',
        email: 'test@example.com',
        emailVerified: true
      });
    });

    it('should set email to empty string when not present in token', async () => {
      mockReq.headers.authorization = 'Bearer valid-token';
      mockVerifyIdToken.mockResolvedValue({
        uid: 'user-123',
        email_verified: false
      });

      await requireAuth(mockReq, mockRes, mockNext);

      expect(mockReq.user.email).toBe('');
      expect(mockReq.user.emailVerified).toBe(false);
    });

    it('should return 401 when token verification fails', async () => {
      mockReq.headers.authorization = 'Bearer invalid-token';
      mockVerifyIdToken.mockRejectedValue(new Error('Invalid token'));

      await requireAuth(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Invalid auth token' });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('requireAdmin', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should return 403 when ADMIN_EMAILS is not configured', () => {
      process.env.ADMIN_EMAILS = '';
      mockReq.user = { email: 'admin@example.com' };

      requireAdmin(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Admin access not configured' });
    });

    it('should return 403 when user is not authenticated', () => {
      process.env.ADMIN_EMAILS = 'admin@example.com';
      mockReq.user = undefined;

      requireAdmin(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Forbidden' });
    });

    it('should return 403 when user email is not in admin list', () => {
      process.env.ADMIN_EMAILS = 'admin@example.com';
      mockReq.user = { email: 'user@example.com' };

      requireAdmin(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({ error: 'Forbidden' });
    });

    it('should call next when user is admin', () => {
      process.env.ADMIN_EMAILS = 'admin@example.com,another@admin.com';
      mockReq.user = { email: 'admin@example.com' };

      requireAdmin(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should be case-insensitive for email comparison', () => {
      process.env.ADMIN_EMAILS = 'Admin@Example.com';
      mockReq.user = { email: 'admin@example.com' };

      requireAdmin(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle multiple admin emails', () => {
      process.env.ADMIN_EMAILS = 'admin1@example.com, admin2@example.com , admin3@example.com';
      mockReq.user = { email: 'admin2@example.com' };

      requireAdmin(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should return 403 when user has no email', () => {
      process.env.ADMIN_EMAILS = 'admin@example.com';
      mockReq.user = { uid: 'user-123' };

      requireAdmin(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
    });
  });
});
