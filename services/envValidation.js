function validateProductionEnvironment(env) {
  if (env.NODE_ENV !== 'production') return [];
  const errors = [];
  const required = ['MONGODB_URI', 'VAPID_PUBLIC_KEY', 'VAPID_PRIVATE_KEY', 'FRONTEND_URL'];
  for (const name of required) {
    if (!env[name]) errors.push(`${name} is required`);
  }

  const hasFirebaseJson = Boolean(env.FIREBASE_SERVICE_ACCOUNT_JSON);
  const hasFirebaseFields = Boolean(env.FIREBASE_PROJECT_ID && env.FIREBASE_CLIENT_EMAIL && env.FIREBASE_PRIVATE_KEY);
  if (!hasFirebaseJson && !hasFirebaseFields) {
    errors.push('Firebase Admin credentials are required');
  }

  for (const name of ['FRONTEND_URL', 'PAYMONGO_API_BASE', 'AI_BASE_URL', 'DEEPSEEK_REVIEWER_BASE_URL', 'R2_ENDPOINT']) {
    if (!env[name]) continue;
    try {
      const url = new URL(env[name]);
      if (url.protocol !== 'https:') errors.push(`${name} must use HTTPS in production`);
    } catch {
      errors.push(`${name} must be a valid URL`);
    }
  }

  if (env.ALLOW_NULL_ORIGIN === 'true') errors.push('ALLOW_NULL_ORIGIN must not be enabled in production');
  return errors;
}

function assertProductionEnvironment(env = process.env) {
  const errors = validateProductionEnvironment(env);
  if (errors.length) throw new Error(`Invalid production environment: ${errors.join('; ')}`);
}

module.exports = { validateProductionEnvironment, assertProductionEnvironment };
