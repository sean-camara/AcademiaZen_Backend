const { createRequireAuth, requireAuth, requireAdmin } = require('../dist/middleware/auth');

function responseDouble() {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
}

describe('authentication middleware', () => {
  afterEach(() => {
    vi.clearAllMocks();
    delete process.env.ADMIN_EMAILS;
  });

  it('rejects missing and non-bearer credentials without calling Firebase', async () => {
    for (const authorization of [undefined, 'Basic token', 'Bearer ']) {
      const req = { headers: { authorization } };
      const res = responseDouble();
      const next = vi.fn();
      await requireAuth(req, res, next);
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'Missing auth token' });
      expect(next).not.toHaveBeenCalled();
    }
  });

  it('uses verified token claims as the only authenticated identity', async () => {
    const verifyIdToken = vi.fn().mockResolvedValue({
      uid: 'user-123',
      email: 'student@example.com',
      email_verified: true,
    });
    const verifyAuth = createRequireAuth(verifyIdToken);
    const req = { headers: { authorization: 'Bearer verified-token' } };
    const res = responseDouble();
    const next = vi.fn();

    await verifyAuth(req, res, next);

    expect(verifyIdToken).toHaveBeenCalledWith('verified-token');
    expect(req.user).toEqual({
      uid: 'user-123',
      email: 'student@example.com',
      emailVerified: true,
    });
    expect(next).toHaveBeenCalledOnce();
  });

  it('normalizes Firebase failures to an authentication error', async () => {
    const verifyAuth = createRequireAuth(vi.fn().mockRejectedValue(new Error('provider detail')));
    const res = responseDouble();
    const next = vi.fn();
    await verifyAuth({ headers: { authorization: 'Bearer invalid' } }, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid auth token' });
    expect(next).not.toHaveBeenCalled();
  });

  it('fails closed when the admin allowlist is absent', () => {
    const res = responseDouble();
    requireAdmin({ user: { email: 'admin@example.com' } }, res, vi.fn());
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'Admin access not configured' });
  });

  it('matches the admin allowlist case-insensitively', () => {
    process.env.ADMIN_EMAILS = 'first@example.com, Admin@Example.com';
    const next = vi.fn();
    requireAdmin({ user: { email: 'admin@example.com' } }, responseDouble(), next);
    expect(next).toHaveBeenCalledOnce();
  });

  it('rejects authenticated users outside the admin allowlist', () => {
    process.env.ADMIN_EMAILS = 'admin@example.com';
    const res = responseDouble();
    requireAdmin({ user: { email: 'student@example.com' } }, res, vi.fn());
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'Forbidden' });
  });
});
