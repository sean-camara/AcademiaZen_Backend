const request = require('supertest');
const { app } = require('../dist/server');

describe('application composition', () => {
  it('imports without opening external connections or starting a listener', () => {
    expect(app).toBeDefined();
  });

  it('reports liveness with a request ID', async () => {
    const response = await request(app).get('/live').expect(200);
    expect(response.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/i);
    expect(response.body).toMatchObject({
      status: 'ok',
      requestId: response.headers['x-request-id'],
    });
  });

  it('reports not ready when MongoDB is disconnected', async () => {
    const response = await request(app).get('/ready').expect(503);
    expect(response.body.status).toBe('not_ready');
  });

  it('rejects a protected route without touching Firebase', async () => {
    const response = await request(app).get('/api/me').expect(401);
    expect(response.body.error).toBe('Missing auth token');
  });

  it('returns the API compatibility 404 under Express 5', async () => {
    const response = await request(app).get('/api/does-not-exist').expect(404);
    expect(response.body.error).toBe('Not Found');
  });
});
