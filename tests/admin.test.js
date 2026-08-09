const request = require('supertest');
const { app } = require('../dist/server');

describe('Admin RBAC API endpoints', () => {
  it('rejects unauthenticated requests to /api/admin/overview with 401', async () => {
    const response = await request(app)
      .get('/api/admin/overview')
      .expect(401);

    expect(response.body.error).toBe('Missing auth token');
  });

  it('rejects unauthenticated user search requests with 401', async () => {
    const response = await request(app)
      .get('/api/admin/users')
      .expect(401);

    expect(response.body.error).toBe('Missing auth token');
  });

  it('allows fetching active public announcements without auth', async () => {
    const response = await request(app)
      .get('/api/announcements/active')
      .expect(200);

    expect(Array.isArray(response.body.announcements)).toBe(true);
  });
});
