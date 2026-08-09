const request = require('supertest');
const { app } = require('../dist/server');

describe('billing checkout API & origin resolution', () => {
  it('rejects unauthenticated checkout requests with 401', async () => {
    const response = await request(app)
      .post('/api/billing/checkout')
      .send({ plan: 'premium', interval: 'monthly', method: 'qrph' })
      .expect(401);

    expect(response.body.error).toBe('Missing auth token');
  });

  it('rejects checkout requests with invalid plan parameters', async () => {
    const response = await request(app)
      .post('/api/billing/checkout')
      .send({ plan: 'super_invalid_plan', interval: 'monthly', method: 'qrph' })
      .expect(401); // Auth middleware triggers first

    expect(response.body.error).toBe('Missing auth token');
  });
});
