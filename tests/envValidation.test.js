const { validateProductionEnvironment, assertProductionEnvironment } = require('../dist/services/envValidation');

const valid = {
  NODE_ENV: 'production',
  MONGODB_URI: 'mongodb://database.internal/academiazen',
  VAPID_PUBLIC_KEY: 'public',
  VAPID_PRIVATE_KEY: 'private',
  FRONTEND_URL: 'https://academiazen.app',
  FIREBASE_PROJECT_ID: 'project',
  FIREBASE_CLIENT_EMAIL: 'firebase@example.test',
  FIREBASE_PRIVATE_KEY: 'private',
};

describe('production environment validation', () => {
  it('accepts the minimum safe production configuration', () => {
    expect(validateProductionEnvironment(valid)).toEqual([]);
  });

  it('does not impose production requirements in test or development', () => {
    expect(validateProductionEnvironment({ NODE_ENV: 'test' })).toEqual([]);
  });

  it('rejects missing identity credentials and insecure public URLs', () => {
    const errors = validateProductionEnvironment({
      ...valid,
      FIREBASE_PROJECT_ID: '',
      FIREBASE_CLIENT_EMAIL: '',
      FIREBASE_PRIVATE_KEY: '',
      FRONTEND_URL: 'http://academiazen.app',
      ALLOW_NULL_ORIGIN: 'true',
      PAYMONGO_WEBHOOK_TOLERANCE_SECONDS: 'not-a-number',
    });
    expect(errors).toContain('Firebase Admin credentials are required');
    expect(errors).toContain('FRONTEND_URL must use HTTPS in production');
    expect(errors).toContain('ALLOW_NULL_ORIGIN must not be enabled in production');
    expect(errors).toContain('PAYMONGO_WEBHOOK_TOLERANCE_SECONDS must be a non-negative number');
  });

  it('reports variable names without leaking their values', () => {
    expect(() => assertProductionEnvironment({ NODE_ENV: 'production' }))
      .toThrow('MONGODB_URI is required');
  });
});
