/**
 * AcademiaZen API Server
 *
 * Responsibilities:
 * - Firebase Auth verification
 * - MongoDB persistence (Zen state + push subscriptions)
 * - Web Push notifications
 * - AI proxy endpoint (OpenRouter / DeepSeek)
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const webpush = require('web-push');
const crypto = require('crypto');
const { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const { requireAuth, requireAdmin, initFirebaseAdmin } = require('./middleware/auth');
const { User, getDefaultState } = require('./models/User');
const { FocusSession } = require('./models/FocusSession');
const PushSubscription = require('./models/PushSubscription');

const app = express();

// Trust proxy for rate limiting and correct IPs behind Nginx
app.set('trust proxy', 1);
app.disable('x-powered-by');

// ----- Security / middleware -----
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', apiLimiter);

const checkoutLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.json({
  limit: '15mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  },
}));

const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173',
  process.env.FRONTEND_URL,
  ...(process.env.FRONTEND_URLS ? process.env.FRONTEND_URLS.split(',').map(s => s.trim()).filter(Boolean) : []),
].filter(Boolean);

const allowVercelPreview = process.env.ALLOW_VERCEL_PREVIEW === 'true';
const allowNullOrigin = process.env.ALLOW_NULL_ORIGIN === 'true';

app.use(cors({
  origin: function(origin, callback) {
    if (!origin && allowNullOrigin) return callback(null, true);
    if (!origin) return callback(null, false);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    if (allowVercelPreview && origin.includes('.vercel.app')) return callback(null, true);
    return callback(null, false);
  },
  credentials: true,
}));

// ----- Firebase Admin -----
initFirebaseAdmin();

// ----- MongoDB -----
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('Missing MONGODB_URI in environment');
  process.exit(1);
}

mongoose.connect(MONGODB_URI, {
  autoIndex: true,
}).then(() => {
  console.log('MongoDB connected');
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// ----- Web Push -----
if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY) {
  console.error('VAPID keys not found. Set VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY.');
  process.exit(1);
}

webpush.setVapidDetails(
  process.env.VAPID_EMAIL || 'mailto:admin@academiazen.app',
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY
);

// ----- Helpers -----
async function getOrCreateUser(uid, email) {
  let user = await User.findOne({ uid });
  if (!user) {
    user = await User.create({
      uid,
      email: email || '',
      state: getDefaultState(),
    });
  } else if (!user.billing) {
    user.billing = {};
  }
  return user;
}

async function sendNotificationToUser(uid, payload, options = {}) {
  const subs = await PushSubscription.find({ uid }).lean();
  const results = await Promise.allSettled(subs.map(async (sub) => {
    try {
      await webpush.sendNotification(sub.subscription, payload, options);
      return { id: sub._id.toString(), success: true };
    } catch (error) {
      if (error.statusCode === 410) {
        await PushSubscription.deleteOne({ _id: sub._id });
      }
      return { id: sub._id.toString(), success: false, error: error.message };
    }
  }));
  return results;
}

function isValidState(state) {
  if (!state || typeof state !== 'object') return false;
  if (!Array.isArray(state.tasks)) return false;
  if (!Array.isArray(state.subjects)) return false;
  if (!Array.isArray(state.flashcards)) return false;
  if (!Array.isArray(state.folders)) return false;
  if (!state.profile || !state.settings) return false;
  return true;
}

const MAX_STATE_BYTES = Number(process.env.MAX_STATE_BYTES || 5 * 1024 * 1024);
const MAX_ATTACHMENT_BYTES = Number(process.env.MAX_ATTACHMENT_BYTES || 1 * 1024 * 1024);
const MAX_ATTACHMENT_BASE64_LEN = Math.ceil(MAX_ATTACHMENT_BYTES * 1.37);

function sanitizeStateForStorage(state) {
  const sanitized = JSON.parse(JSON.stringify(state));

  if (Array.isArray(sanitized.tasks)) {
    sanitized.tasks = sanitized.tasks.map(task => {
      if (task?.pdfAttachment) {
        if (task.pdfAttachment.data) delete task.pdfAttachment.data;
        if (task.pdfAttachment.url) delete task.pdfAttachment.url;
        if (task.pdfAttachment.text && task.pdfAttachment.text.length > MAX_PDF_TEXT_CHARS) {
          task.pdfAttachment.text = task.pdfAttachment.text.slice(0, MAX_PDF_TEXT_CHARS);
        }
      }
      return task;
    });
  }

  if (Array.isArray(sanitized.folders)) {
    sanitized.folders = sanitized.folders.map(folder => {
      if (Array.isArray(folder.items)) {
        folder.items = folder.items.map(item => {
          if (item?.type === 'pdf') {
            if (item.content && String(item.content).startsWith('data:application/pdf')) {
              item.content = '';
            }
            if (item.file) {
              if (item.file.data) delete item.file.data;
              if (item.file.url) delete item.file.url;
              if (item.file.text && item.file.text.length > MAX_PDF_TEXT_CHARS) {
                item.file.text = item.file.text.slice(0, MAX_PDF_TEXT_CHARS);
              }
            }
          }
          return item;
        });
      }
      return folder;
    });
  }

  const sizeBytes = Buffer.byteLength(JSON.stringify(sanitized), 'utf8');
  if (sizeBytes > MAX_STATE_BYTES) {
    if (Array.isArray(sanitized.tasks)) {
      sanitized.tasks = sanitized.tasks.map(task => {
        if (task?.pdfAttachment?.data) delete task.pdfAttachment.data;
        if (task?.pdfAttachment?.url) delete task.pdfAttachment.url;
        return task;
      });
    }
    if (Array.isArray(sanitized.folders)) {
      sanitized.folders = sanitized.folders.map(folder => {
        if (Array.isArray(folder.items)) {
          folder.items = folder.items.map(item => {
            if (item?.type === 'pdf') {
              if (item.content && String(item.content).startsWith('data:application/pdf')) {
                item.content = '';
              }
              if (item.file?.data) delete item.file.data;
              if (item.file?.url) delete item.file.url;
            }
            return item;
          });
        }
        return folder;
      });
    }
  }

  return sanitized;
}

// ----- Billing (PayMongo) -----
function resolveEnvRef(value) {
  if (!value) return '';
  const match = String(value).match(/^\$\{([^}]+)\}$/);
  if (match) {
    return process.env[match[1]] || '';
  }
  return value;
}

const PAYMONGO_SECRET_KEY = resolveEnvRef(process.env.PAYMONGO_SECRET_KEY);
const PAYMONGO_API_BASE = process.env.PAYMONGO_API_BASE || 'https://api.paymongo.com/v1';
const PAYMONGO_WEBHOOK_SECRET = resolveEnvRef(process.env.PAYMONGO_WEBHOOK_SECRET);

const AI_ACCESS_MODE = (process.env.AI_ACCESS_MODE || 'premium').toLowerCase();
const ALLOW_FREE_AI = AI_ACCESS_MODE === 'free' || process.env.ALLOW_FREE_AI === 'true';
const MAX_AI_PROMPT_CHARS = Number(process.env.MAX_AI_PROMPT_CHARS || 12000);
const AI_BASE_URL = process.env.AI_BASE_URL || 'https://openrouter.ai/api/v1';
const AI_MODEL_DEFAULT = process.env.AI_MODEL || 'deepseek/deepseek-r1-0528:free';
const AI_MODEL_FAST = process.env.AI_MODEL_FAST || 'deepseek/deepseek-chat';
const AI_MODEL_DEEP = process.env.AI_MODEL_DEEP || AI_MODEL_DEFAULT;
const AI_MAX_TOKENS_FAST = Number(process.env.AI_MAX_TOKENS_FAST || 1200);
const AI_MAX_TOKENS_DEEP = Number(process.env.AI_MAX_TOKENS_DEEP || 2400);
const OPENROUTER_API_KEY = resolveEnvRef(process.env.OPENROUTER_API_KEY || process.env.DEEPSEEK_API_KEY);
const OPENROUTER_SITE_URL = process.env.OPENROUTER_SITE_URL || process.env.FRONTEND_URL || 'https://academiazen.app';
const OPENROUTER_APP_TITLE = process.env.OPENROUTER_APP_TITLE || 'AcademiaZen';

const R2_ENDPOINT = process.env.R2_ENDPOINT || '';
const R2_BUCKET = process.env.R2_BUCKET || '';
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || '';
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || '';
const R2_PUBLIC_BASE_URL = process.env.R2_PUBLIC_BASE_URL || '';
const R2_SIGNED_URL_TTL = Number(process.env.R2_SIGNED_URL_TTL || 900);
const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_BYTES || 15 * 1024 * 1024);
const MAX_PDF_TEXT_CHARS = Number(process.env.MAX_PDF_TEXT_CHARS || 12000);

let r2Client;
function getR2Client() {
  if (!R2_ENDPOINT || !R2_BUCKET || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY) {
    return null;
  }
  if (!r2Client) {
    r2Client = new S3Client({
      region: 'auto',
      endpoint: R2_ENDPOINT,
      credentials: {
        accessKeyId: R2_ACCESS_KEY_ID,
        secretAccessKey: R2_SECRET_ACCESS_KEY,
      },
    });
  }
  return r2Client;
}

function ensureR2() {
  const client = getR2Client();
  if (!client) {
    throw new Error('R2 is not configured');
  }
  return client;
}

function isOwnedKey(key, uid) {
  return typeof key === 'string' && key.startsWith(`${uid}/`);
}

const BILLING_PLANS = {
  premium: {
    monthly: {
      amount: 14900,
      currency: 'PHP',
      label: 'Premium Monthly',
      description: 'AcademiaZen Premium (Monthly)',
      interval: 'monthly',
    },
    yearly: {
      amount: 149000,
      currency: 'PHP',
      label: 'Premium Yearly',
      description: 'AcademiaZen Premium (Yearly)',
      interval: 'yearly',
    },
  },
};

const PAYMENT_METHOD_MAP = {
  gcash: 'gcash',
  bank: 'qrph',
  qrph: 'qrph',
};

function getCheckoutUrls() {
  const base = process.env.PAYMONGO_SUCCESS_URL
    ? { success: process.env.PAYMONGO_SUCCESS_URL, cancel: process.env.PAYMONGO_CANCEL_URL }
    : null;

  if (base?.success && base?.cancel) return base;

  const frontend = process.env.FRONTEND_URL || 'http://localhost:5173';
  return {
    success: `${frontend.replace(/\/+$/, '')}/?billing=success`,
    cancel: `${frontend.replace(/\/+$/, '')}/?billing=cancel`,
  };
}

function addInterval(date, interval) {
  const next = new Date(date);
  if (interval === 'yearly') {
    next.setFullYear(next.getFullYear() + 1);
  } else {
    next.setMonth(next.getMonth() + 1);
  }
  return next;
}

function isBillingActive(billing) {
  if (!billing?.currentPeriodEnd) return false;
  const end = new Date(billing.currentPeriodEnd);
  const status = billing?.status;
  return (status === 'active' || status === 'canceled') && end.getTime() > Date.now();
}

function getBillingSnapshot(billing) {
  const active = isBillingActive(billing);
  const plan = billing?.plan || 'free';
  const autoRenew = plan === 'premium' ? (billing?.autoRenew ?? true) : false;
  let status = billing?.status || 'free';
  if ((status === 'active' || status === 'canceled') && !active) status = 'expired';
  if (status === 'pending' && !billing?.pendingCheckoutId) status = 'free';
  return {
    plan,
    interval: billing?.interval || 'none',
    status,
    currentPeriodEnd: billing?.currentPeriodEnd ? new Date(billing.currentPeriodEnd).toISOString() : null,
    autoRenew,
    isActive: active,
    effectivePlan: active ? plan : 'free',
    pendingCheckoutId: billing?.pendingCheckoutId || '',
  };
}

async function getFocusStreak(uid) {
  const sessions = await FocusSession.find({
    uid,
    status: { $in: ['completed', 'failed', 'abandoned'] },
    endedAt: { $ne: null },
  })
    .sort({ endedAt: -1 })
    .limit(50)
    .lean();

  let streak = 0;
  for (const session of sessions) {
    if (session.status === 'completed') {
      streak += 1;
    } else {
      break;
    }
  }
  return streak;
}

async function getTargetQuitCount(uid, targetType, targetId, days = 7) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return FocusSession.countDocuments({
    uid,
    targetType,
    targetId,
    status: { $in: ['failed', 'abandoned'] },
    endedAt: { $gte: since },
  });
}

function applyPaidSubscription(user, interval, details = {}) {
  if (!user.billing) user.billing = {};
  if (!user.billing.paymongo) user.billing.paymongo = {};
  const now = new Date();
  const currentEnd = user.billing?.currentPeriodEnd ? new Date(user.billing.currentPeriodEnd) : null;
  const base = currentEnd && currentEnd > now ? currentEnd : now;
  const nextEnd = addInterval(base, interval);

  user.billing.plan = 'premium';
  user.billing.interval = interval;
  user.billing.status = 'active';
  user.billing.currentPeriodEnd = nextEnd;
  user.billing.lastPaymentAt = now;
  user.billing.pendingCheckoutId = '';
  user.billing.pendingPlan = '';
  user.billing.pendingInterval = '';

  if (details.checkoutId) user.billing.paymongo.checkoutId = details.checkoutId;
  if (details.paymentId) user.billing.paymongo.paymentId = details.paymentId;
  if (details.paymentIntentId) user.billing.paymongo.paymentIntentId = details.paymentIntentId;
  if (details.sourceId) user.billing.paymongo.sourceId = details.sourceId;
  if (details.eventId) user.billing.paymongo.lastEventId = details.eventId;
  if (details.eventType) user.billing.paymongo.lastEventType = details.eventType;
}

function buildPaymongoAuthHeader() {
  const token = Buffer.from(`${PAYMONGO_SECRET_KEY}:`).toString('base64');
  return `Basic ${token}`;
}

async function paymongoRequest(path, { method = 'GET', body } = {}) {
  if (!PAYMONGO_SECRET_KEY) {
    throw new Error('PAYMONGO_SECRET_KEY is not configured');
  }

  const response = await fetch(`${PAYMONGO_API_BASE}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: buildPaymongoAuthHeader(),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data?.errors?.[0]?.detail || data?.errors?.[0]?.message || 'PayMongo request failed';
    const error = new Error(message);
    error.statusCode = response.status;
    error.payload = data;
    throw error;
  }
  return data;
}

async function openrouterRequest(path, { method = 'POST', body } = {}) {
  if (!OPENROUTER_API_KEY) {
    throw new Error('OPENROUTER_API_KEY is not configured');
  }

  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${OPENROUTER_API_KEY}`,
  };

  if (OPENROUTER_SITE_URL) {
    headers['HTTP-Referer'] = OPENROUTER_SITE_URL;
  }
  if (OPENROUTER_APP_TITLE) {
    headers['X-Title'] = OPENROUTER_APP_TITLE;
  }

  const response = await fetch(`${AI_BASE_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data?.error?.message || data?.error || data?.message || 'AI request failed';
    const error = new Error(message);
    error.statusCode = response.status;
    error.payload = data;
    throw error;
  }
  return data;
}

function verifyPaymongoSignature(req) {
  if (!PAYMONGO_WEBHOOK_SECRET) return true;
  const header = req.headers['paymongo-signature'];
  if (!header || !req.rawBody) return false;

  const raw = req.rawBody.toString('utf8');
  const parts = String(header).split(',').map(p => p.trim());
  let timestamp = null;
  const signatures = [];
  for (const part of parts) {
    if (part.startsWith('t=')) timestamp = part.slice(2);
    if (part.startsWith('v1=')) signatures.push(part.slice(3));
    if (part.startsWith('sig=')) signatures.push(part.slice(4));
  }
  if (!signatures.length && header) signatures.push(String(header).trim());

  const candidates = [];
  if (timestamp) {
    candidates.push(crypto.createHmac('sha256', PAYMONGO_WEBHOOK_SECRET).update(`${timestamp}.${raw}`).digest('hex'));
  }
  candidates.push(crypto.createHmac('sha256', PAYMONGO_WEBHOOK_SECRET).update(raw).digest('hex'));

  return signatures.some(sig => {
    try {
      const sigBuf = Buffer.from(String(sig).trim(), 'hex');
      return candidates.some(candidate => {
        const candBuf = Buffer.from(candidate, 'hex');
        return sigBuf.length === candBuf.length && crypto.timingSafeEqual(sigBuf, candBuf);
      });
    } catch (_) {
      return false;
    }
  });
}

function isCheckoutPaid(checkout) {
  const attrs = checkout?.data?.attributes;
  if (!attrs) return false;
  if (attrs.payment_status && String(attrs.payment_status).toLowerCase() === 'paid') return true;
  if (Array.isArray(attrs.payments)) {
    return attrs.payments.some(p => String(p?.attributes?.status || '').toLowerCase() === 'paid');
  }
  return false;
}

// ----- Routes -----
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/vapid-public-key', (req, res) => {
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

// ----- R2 Uploads -----
app.post('/api/uploads/presign', requireAuth, async (req, res) => {
  try {
    const { filename, contentType, size } = req.body || {};
    if (!filename || !contentType || !size) {
      return res.status(400).json({ error: 'filename, contentType, and size are required' });
    }
    if (!String(contentType).includes('pdf')) {
      return res.status(400).json({ error: 'Only PDF uploads are allowed' });
    }
    const sizeNum = Number(size);
    if (!Number.isFinite(sizeNum) || sizeNum <= 0) {
      return res.status(400).json({ error: 'Invalid size' });
    }
    if (sizeNum > MAX_UPLOAD_BYTES) {
      return res.status(413).json({ error: 'File exceeds upload limit' });
    }

    const client = ensureR2();
    const safeName = String(filename)
      .replace(/[^a-zA-Z0-9._-]/g, '_')
      .slice(-120);
    const key = `${req.user.uid}/${Date.now()}-${crypto.randomBytes(6).toString('hex')}-${safeName}`;

    const command = new PutObjectCommand({
      Bucket: R2_BUCKET,
      Key: key,
      ContentType: contentType,
      ContentLength: sizeNum,
    });
    const uploadUrl = await getSignedUrl(client, command, { expiresIn: R2_SIGNED_URL_TTL });
    const publicUrl = R2_PUBLIC_BASE_URL ? `${R2_PUBLIC_BASE_URL.replace(/\/$/, '')}/${key}` : '';
    res.json({ key, uploadUrl, publicUrl });
  } catch (err) {
    console.error('Presign upload failed:', err);
    res.status(500).json({ error: 'Failed to create upload URL' });
  }
});

app.post('/api/uploads/signed-url', requireAuth, async (req, res) => {
  try {
    const { key } = req.body || {};
    if (!key || typeof key !== 'string') {
      return res.status(400).json({ error: 'key is required' });
    }
    if (!isOwnedKey(key, req.user.uid)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const client = ensureR2();
    const command = new GetObjectCommand({ Bucket: R2_BUCKET, Key: key });
    const url = await getSignedUrl(client, command, { expiresIn: R2_SIGNED_URL_TTL });
    res.json({ url });
  } catch (err) {
    console.error('Signed URL failed:', err);
    res.status(500).json({ error: 'Failed to create download URL' });
  }
});

// ----- Billing (PayMongo) -----
app.get('/api/billing/plans', requireAuth, (req, res) => {
  res.json({
    plans: {
      free: { id: 'free', label: 'Freemium', amount: 0, currency: 'PHP', interval: 'none' },
      premium: BILLING_PLANS.premium,
    },
  });
});

app.get('/api/billing/status', requireAuth, async (req, res) => {
  try {
    const user = await getOrCreateUser(req.user.uid, req.user.email);
    res.json({ billing: getBillingSnapshot(user.billing || {}) });
  } catch (err) {
    console.error('Failed to get billing status:', err);
    res.status(500).json({ error: 'Failed to load billing status' });
  }
});

app.post('/api/billing/auto-renew', requireAuth, async (req, res) => {
  try {
    const { autoRenew } = req.body || {};
    if (typeof autoRenew !== 'boolean') {
      return res.status(400).json({ error: 'autoRenew must be a boolean' });
    }
    const user = await getOrCreateUser(req.user.uid, req.user.email);
    user.billing.autoRenew = autoRenew;
    await user.save();
    res.json({ success: true, autoRenew });
  } catch (err) {
    console.error('Failed to update auto-renew:', err);
    res.status(500).json({ error: 'Failed to update auto-renew' });
  }
});

app.post('/api/billing/cancel', requireAuth, async (req, res) => {
  try {
    const user = await getOrCreateUser(req.user.uid, req.user.email);
    if (!user.billing || user.billing.plan !== 'premium') {
      return res.status(400).json({ error: 'No active subscription to cancel' });
    }
    user.billing.status = 'canceled';
    user.billing.autoRenew = false;
    user.billing.canceledAt = new Date();
    await user.save();
    res.json({ success: true, billing: getBillingSnapshot(user.billing) });
  } catch (err) {
    console.error('Failed to cancel subscription:', err);
    res.status(500).json({ error: 'Failed to cancel subscription' });
  }
});

app.post('/api/billing/checkout', requireAuth, checkoutLimiter, async (req, res) => {
  try {
    const { plan = 'premium', interval = 'monthly', method = 'gcash' } = req.body || {};
    const planConfig = BILLING_PLANS[plan]?.[interval];
    const paymentMethod = PAYMENT_METHOD_MAP[method];

    if (!planConfig) {
      return res.status(400).json({ error: 'Invalid plan or interval' });
    }
    if (!paymentMethod) {
      return res.status(400).json({ error: 'Invalid payment method' });
    }

    // NEW: Prevent duplicate purchases for ACTIVE users
    const user = await getOrCreateUser(req.user.uid, req.user.email);
    if (isBillingActive(user.billing)) {
      return res.status(400).json({ 
        error: 'You already have an active subscription. Use Manage Subscription to change your plan or extend it.' 
      });
    }

    const { success, cancel } = getCheckoutUrls();

    const payload = {
      data: {
        attributes: {
          line_items: [
            {
              name: planConfig.label,
              amount: planConfig.amount,
              currency: planConfig.currency,
              quantity: 1,
              description: planConfig.description,
            },
          ],
          payment_method_types: [paymentMethod],
          success_url: success,
          cancel_url: cancel,
          description: planConfig.description,
          send_email_receipt: true,
          show_description: true,
          show_line_items: true,
          metadata: {
            uid: req.user.uid,
            email: req.user.email || '',
            plan,
            interval,
            method: paymentMethod,
          },
        },
      },
    };

    const response = await paymongoRequest('/checkout_sessions', { method: 'POST', body: payload });
    const checkoutUrl = response?.data?.attributes?.checkout_url;
    const checkoutId = response?.data?.id;

    if (!checkoutUrl || !checkoutId) {
      return res.status(502).json({ error: 'Invalid response from payment provider' });
    }

    // Reuse the user object fetched earlier
    user.billing.plan = plan;
    user.billing.interval = interval;
    user.billing.status = 'pending';
    user.billing.pendingCheckoutId = checkoutId;
    user.billing.pendingPlan = plan;
    user.billing.pendingInterval = interval;
    user.billing.paymongo.checkoutId = checkoutId;
    user.billing.paymongo.lastEventType = 'checkout.created';
    await user.save();

    res.json({ checkoutUrl, checkoutId });
  } catch (err) {
    console.error('Checkout creation failed:', err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// NEW: Manual subscription extension endpoint
app.post('/api/billing/extend', requireAuth, checkoutLimiter, async (req, res) => {
  try {
    const { interval = 'monthly', method = 'gcash' } = req.body || {};
    const user = await getOrCreateUser(req.user.uid, req.user.email);

    // Validate: Only ACTIVE users with auto-renew OFF and near expiry can extend
    if (!isBillingActive(user.billing)) {
      return res.status(400).json({ error: 'You do not have an active subscription to extend.' });
    }
    if (user.billing.autoRenew) {
      return res.status(400).json({ error: 'Disable auto-renew before manually extending your subscription.' });
    }

    // Check if near expiry (within 7 days)
    const expiryDate = new Date(user.billing.currentPeriodEnd);
    const now = new Date();
    const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    if (daysUntilExpiry > 7 || daysUntilExpiry < 0) {
      return res.status(400).json({ error: 'Extension is only available within 7 days of expiry.' });
    }

    const planConfig = BILLING_PLANS['premium']?.[interval];
    const paymentMethod = PAYMENT_METHOD_MAP[method];

    if (!planConfig) {
      return res.status(400).json({ error: 'Invalid interval' });
    }
    if (!paymentMethod) {
      return res.status(400).json({ error: 'Invalid payment method' });
    }

    const { success, cancel } = getCheckoutUrls();

    const payload = {
      data: {
        attributes: {
          line_items: [
            {
              name: `${planConfig.label} - Extension`,
              amount: planConfig.amount,
              currency: planConfig.currency,
              quantity: 1,
              description: `Extend your subscription by 1 month`,
            },
          ],
          payment_method_types: [paymentMethod],
          success_url: success,
          cancel_url: cancel,
          description: `Extension: ${planConfig.description}`,
          send_email_receipt: true,
          show_description: true,
          show_line_items: true,
          metadata: {
            uid: req.user.uid,
            email: req.user.email || '',
            plan: 'premium',
            interval,
            method: paymentMethod,
            isExtension: 'true',
          },
        },
      },
    };

    const response = await paymongoRequest('/checkout_sessions', { method: 'POST', body: payload });
    const checkoutUrl = response?.data?.attributes?.checkout_url;
    const checkoutId = response?.data?.id;

    if (!checkoutUrl || !checkoutId) {
      return res.status(502).json({ error: 'Invalid response from payment provider' });
    }

    // Mark as pending extension
    user.billing.pendingCheckoutId = checkoutId;
    user.billing.pendingInterval = interval;
    user.billing.paymongo.checkoutId = checkoutId;
    user.billing.paymongo.lastEventType = 'checkout.created';
    await user.save();

    res.json({ checkoutUrl, checkoutId });
  } catch (err) {
    console.error('Extension creation failed:', err);
    res.status(500).json({ error: 'Failed to create extension checkout' });
  }
});

app.post('/api/billing/refresh', requireAuth, async (req, res) => {
  try {
    const user = await getOrCreateUser(req.user.uid, req.user.email);
    const checkoutId = user.billing?.pendingCheckoutId;
    if (!checkoutId) {
      return res.json({ updated: false, billing: getBillingSnapshot(user.billing || {}) });
    }

    const checkout = await paymongoRequest(`/checkout_sessions/${checkoutId}`, { method: 'GET' });
    if (isCheckoutPaid(checkout)) {
      const interval = user.billing.pendingInterval || user.billing.interval || 'monthly';
      const paymentId = checkout?.data?.attributes?.payments?.[0]?.id;
      applyPaidSubscription(user, interval, { checkoutId, paymentId });
      await user.save();
      return res.json({ updated: true, billing: getBillingSnapshot(user.billing || {}) });
    }

    res.json({ updated: false, billing: getBillingSnapshot(user.billing || {}) });
  } catch (err) {
    console.error('Billing refresh failed:', err);
    res.status(500).json({ error: 'Failed to refresh billing' });
  }
});

// ----- Focus Sessions -----
app.get('/api/focus/summary', requireAuth, async (req, res) => {
  try {
    const { targetType, targetId } = req.query || {};
    if (!targetType || !targetId) {
      return res.status(400).json({ error: 'targetType and targetId are required' });
    }
    const sessions = await FocusSession.find({
      uid: req.user.uid,
      targetType,
      targetId,
      endedAt: { $ne: null },
    })
      .sort({ endedAt: -1 })
      .limit(10)
      .lean();

    const total = sessions.length;
    const completed = sessions.filter(s => s.status === 'completed').length;
    const successRate = total ? completed / total : 0;
    const lastSession = sessions[0]
      ? {
          status: sessions[0].status,
          plannedDurationMinutes: sessions[0].plannedDurationMinutes || 0,
        }
      : null;
    const streak = await getFocusStreak(req.user.uid);
    const quitCount7d = await getTargetQuitCount(req.user.uid, targetType, targetId, 7);

    res.json({
      successRate,
      totalSessions: total,
      completedSessions: completed,
      lastSession,
      streak,
      quitCount7d,
    });
  } catch (err) {
    console.error('Failed to load focus summary:', err);
    res.status(500).json({ error: 'Failed to load focus summary' });
  }
});

app.post('/api/focus/sessions/start', requireAuth, async (req, res) => {
  try {
    const {
      targetType,
      targetId,
      targetLabel = '',
      targetMeta = {},
      plannedDurationMinutes,
    } = req.body || {};

    if (!targetType || !targetId || !plannedDurationMinutes) {
      return res.status(400).json({ error: 'targetType, targetId and plannedDurationMinutes are required' });
    }

    await FocusSession.updateMany(
      { uid: req.user.uid, status: 'in_progress' },
      { status: 'abandoned', endedAt: new Date(), reflectionType: 'blocked', reflectionText: 'Session abandoned by new start.' }
    );

    const session = await FocusSession.create({
      uid: req.user.uid,
      status: 'in_progress',
      targetType,
      targetId,
      targetLabel,
      targetMeta,
      plannedDurationMinutes,
      startedAt: new Date(),
    });

    res.json({ sessionId: session._id.toString(), startedAt: session.startedAt });
  } catch (err) {
    console.error('Failed to start focus session:', err);
    res.status(500).json({ error: 'Failed to start focus session' });
  }
});

app.post('/api/focus/sessions/complete', requireAuth, async (req, res) => {
  try {
    const { sessionId, reflectionText } = req.body || {};
    if (!sessionId || !reflectionText) {
      return res.status(400).json({ error: 'sessionId and reflectionText are required' });
    }
    const session = await FocusSession.findOne({ _id: sessionId, uid: req.user.uid });
    if (!session) return res.status(404).json({ error: 'Session not found' });
    if (session.status !== 'in_progress') {
      return res.status(400).json({ error: 'Session is not active' });
    }

    const endedAt = new Date();
    session.status = 'completed';
    session.endedAt = endedAt;
    session.actualDurationSeconds = session.startedAt ? Math.max(1, Math.round((endedAt - session.startedAt) / 1000)) : 0;
    session.reflectionType = 'finished';
    session.reflectionText = reflectionText;
    await session.save();

    if (session.targetType === 'task') {
      const user = await getOrCreateUser(req.user.uid, req.user.email);
      user.state.tasks = (user.state.tasks || []).map(task =>
        task.id === session.targetId ? { ...task, completed: true } : task
      );
      await user.save();
    }

    const streak = await getFocusStreak(req.user.uid);
    res.json({ success: true, streak });
  } catch (err) {
    console.error('Failed to complete focus session:', err);
    res.status(500).json({ error: 'Failed to complete focus session' });
  }
});

app.post('/api/focus/sessions/abandon', requireAuth, async (req, res) => {
  try {
    const { sessionId, reflectionText } = req.body || {};
    if (!sessionId || !reflectionText) {
      return res.status(400).json({ error: 'sessionId and reflectionText are required' });
    }
    const session = await FocusSession.findOne({ _id: sessionId, uid: req.user.uid });
    if (!session) return res.status(404).json({ error: 'Session not found' });
    if (session.status !== 'in_progress') {
      return res.status(400).json({ error: 'Session is not active' });
    }

    const endedAt = new Date();
    session.status = 'abandoned';
    session.endedAt = endedAt;
    session.actualDurationSeconds = session.startedAt ? Math.max(1, Math.round((endedAt - session.startedAt) / 1000)) : 0;
    session.reflectionType = 'blocked';
    session.reflectionText = reflectionText;
    await session.save();

    const quitCount7d = await getTargetQuitCount(req.user.uid, session.targetType, session.targetId, 7);
    res.json({ success: true, quitCount7d, showQuitWarning: quitCount7d >= 3 });
  } catch (err) {
    console.error('Failed to abandon focus session:', err);
    res.status(500).json({ error: 'Failed to abandon focus session' });
  }
});

app.post('/api/billing/webhook/paymongo', async (req, res) => {
  try {
    if (!verifyPaymongoSignature(req)) {
      return res.status(400).json({ error: 'Invalid signature' });
    }

    const event = req.body?.data;
    const eventType = event?.attributes?.type;
    const eventId = event?.id;
    const resource = event?.attributes?.data;
    const checkoutId = resource?.id;

    if (!eventType || !checkoutId) {
      return res.json({ received: true });
    }

    const user = await User.findOne({ 'billing.pendingCheckoutId': checkoutId })
      || await User.findOne({ 'billing.paymongo.checkoutId': checkoutId });

    if (!user) {
      return res.json({ received: true });
    }
    if (!user.billing) user.billing = {};
    if (!user.billing.paymongo) user.billing.paymongo = {};

    if (String(eventType).includes('payment.paid')) {
      const interval = user.billing.pendingInterval || user.billing.interval || 'monthly';
      const paymentId = resource?.attributes?.payments?.[0]?.id;
      applyPaidSubscription(user, interval, { checkoutId, paymentId, eventId, eventType });
      await user.save();
    } else if (String(eventType).includes('payment.failed')) {
      user.billing.status = 'past_due';
      user.billing.paymongo.lastEventId = eventId || '';
      user.billing.paymongo.lastEventType = eventType || '';
      await user.save();
    }

    res.json({ received: true });
  } catch (err) {
    console.error('PayMongo webhook failed:', err);
    res.status(500).json({ error: 'Webhook handling failed' });
  }
});

// --- Auth-protected ---
app.get('/api/state', requireAuth, async (req, res) => {
  try {
    const user = await getOrCreateUser(req.user.uid, req.user.email);
    res.json({ state: user.state });
  } catch (err) {
    console.error('Failed to get state:', err);
    res.status(500).json({ error: 'Failed to load state' });
  }
});

app.put('/api/state', requireAuth, async (req, res) => {
  try {
    const { state } = req.body;
    if (!isValidState(state)) {
      return res.status(400).json({ error: 'Invalid state payload' });
    }
    const user = await getOrCreateUser(req.user.uid, req.user.email);
    user.state = sanitizeStateForStorage(state);
    user.email = req.user.email || user.email;
    await user.save();
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to save state:', err);
    res.status(500).json({ error: 'Failed to save state' });
  }
});

app.delete('/api/account', requireAuth, async (req, res) => {
  try {
    await Promise.all([
      User.deleteOne({ uid: req.user.uid }),
      PushSubscription.deleteMany({ uid: req.user.uid }),
      FocusSession.deleteMany({ uid: req.user.uid }),
    ]);
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to delete account data:', err);
    res.status(500).json({ error: 'Failed to delete account data' });
  }
});

app.post('/api/subscribe', requireAuth, async (req, res) => {
  try {
    const { subscription } = req.body;
    if (!subscription || !subscription.endpoint) {
      return res.status(400).json({ error: 'Invalid subscription object' });
    }

    await PushSubscription.findOneAndUpdate(
      { uid: req.user.uid, endpoint: subscription.endpoint },
      { uid: req.user.uid, endpoint: subscription.endpoint, subscription },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    res.status(201).json({ success: true, message: 'Subscription registered' });
  } catch (err) {
    console.error('Subscribe error:', err);
    res.status(500).json({ error: 'Failed to register subscription' });
  }
});

app.delete('/api/unsubscribe', requireAuth, async (req, res) => {
  try {
    const { endpoint } = req.body;
    if (!endpoint) {
      return res.status(400).json({ error: 'Endpoint is required' });
    }
    await PushSubscription.deleteOne({ uid: req.user.uid, endpoint });
    res.json({ success: true, message: 'Unsubscribed' });
  } catch (err) {
    console.error('Unsubscribe error:', err);
    res.status(500).json({ error: 'Failed to unsubscribe' });
  }
});

app.get('/api/subscriptions/count', requireAuth, requireAdmin, async (req, res) => {
  const count = await PushSubscription.countDocuments({});
  res.json({ count });
});

app.post('/api/send-notification', requireAuth, async (req, res) => {
  const { title, body, icon, url, data } = req.body;
  if (!title || !body) {
    return res.status(400).json({ error: 'Title and body are required' });
  }

  const payload = JSON.stringify({
    title,
    body,
    icon: icon || '/icons/icon-192x192.svg',
    badge: '/icons/icon-72x72.svg',
    url: url || '/',
    data: data || {},
    timestamp: Date.now(),
  });

  try {
    const results = await sendNotificationToUser(req.user.uid, payload, { TTL: 86400, urgency: 'normal' });
    const sent = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
    res.json({ success: true, message: `Notification sent to ${sent} device(s)` });
  } catch (err) {
    console.error('Push notification error:', err);
    res.status(500).json({ error: 'Failed to send notification' });
  }
});

app.post('/api/schedule-notification', requireAuth, (req, res) => {
  const { title, body, scheduledTime, icon, url } = req.body;
  if (!title || !body || !scheduledTime) {
    return res.status(400).json({ error: 'Title, body, and scheduledTime are required' });
  }

  const delay = new Date(scheduledTime).getTime() - Date.now();
  if (delay < 0) {
    return res.status(400).json({ error: 'Scheduled time must be in the future' });
  }

  setTimeout(async () => {
    const payload = JSON.stringify({
      title,
      body,
      icon: icon || '/icons/icon-192x192.svg',
      badge: '/icons/icon-72x72.svg',
      url: url || '/',
      timestamp: Date.now(),
    });
    await sendNotificationToUser(req.user.uid, payload);
  }, delay);

  res.json({ success: true, message: `Notification scheduled for ${scheduledTime}` });
});

app.post('/api/notify-new-task', requireAuth, async (req, res) => {
  const { task } = req.body;
  if (!task || !task.dueDate) {
    return res.status(400).json({ error: 'Task with dueDate is required' });
  }

  const now = new Date();
  const dueDate = new Date(task.dueDate);
  const threeDaysFromNow = new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000);

  if (dueDate <= now || dueDate > threeDaysFromNow) {
    return res.json({ success: true, message: 'Task not within 3-day window' });
  }

  const hoursUntilDue = Math.round((dueDate - now) / (1000 * 60 * 60));
  const daysUntilDue = Math.round(hoursUntilDue / 24);

  let urgencyEmoji = '[SOON]';
  let timeText = '';

  if (hoursUntilDue <= 24) {
    urgencyEmoji = '[SOON]';
    timeText = hoursUntilDue <= 1 ? 'in less than an hour!' : `in ${hoursUntilDue} hours!`;
  } else if (daysUntilDue <= 1) {
    urgencyEmoji = '[ALERT]';
    timeText = 'tomorrow!';
  } else if (daysUntilDue <= 2) {
    urgencyEmoji = '[DUE]';
    timeText = `in ${daysUntilDue} days`;
  } else {
    urgencyEmoji = '[DUE]';
    timeText = `in ${daysUntilDue} days`;
  }

  const dueDisplay = `${dueDate.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })} at ${dueDate.toLocaleTimeString('en-US', {
    hour: 'numeric',
    minute: '2-digit',
  })}`;
  const subjectParam = task.subjectId ? `&subject=${encodeURIComponent(task.subjectId)}` : '';
  const payload = JSON.stringify({
    title: task.title,
    body: `Is due ${timeText} (${dueDisplay})`,
    icon: '/icons/icon-192x192.svg',
    badge: '/icons/icon-72x72.svg',
    url: `/?page=home${subjectParam}`,
    tag: `new-task-${task.id}`,
    data: { taskId: task.id, subjectId: task.subjectId },
  });

  try {
    await sendNotificationToUser(req.user.uid, payload);
    res.json({ success: true, message: 'Notification sent', dueIn: timeText });
  } catch (err) {
    console.error('Immediate task notification failed:', err);
    res.status(500).json({ error: 'Failed to send notification' });
  }
});

app.post('/api/sync-tasks', requireAuth, async (req, res) => {
  const { tasks } = req.body;
  if (!Array.isArray(tasks)) {
    return res.status(400).json({ error: 'Tasks array is required' });
  }

  try {
    const user = await getOrCreateUser(req.user.uid, req.user.email);
    user.state.tasks = tasks;
    await user.save();
    res.json({ success: true, syncedTasks: tasks.length });
  } catch (err) {
    console.error('Sync tasks failed:', err);
    res.status(500).json({ error: 'Failed to sync tasks' });
  }
});

// AI proxy
const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/ai/chat', requireAuth, aiLimiter, async (req, res) => {
  try {
    const { prompt, mode } = req.body;
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt is required' });
    }
    if (prompt.length > MAX_AI_PROMPT_CHARS) {
      return res.status(413).json({ error: 'Prompt is too long' });
    }
    if (!ALLOW_FREE_AI) {
      const user = await getOrCreateUser(req.user.uid, req.user.email);
      const hasPremium = user.billing?.plan === 'premium' && isBillingActive(user.billing);
      if (!hasPremium) {
        return res.status(402).json({ error: 'Premium subscription required' });
      }
    }
    const isDeep = mode === 'deep';
    const selectedModel = isDeep ? AI_MODEL_DEEP : AI_MODEL_FAST;
    const maxTokens = isDeep ? AI_MAX_TOKENS_DEEP : AI_MAX_TOKENS_FAST;
    const payload = {
      model: selectedModel,
      max_tokens: Number.isFinite(maxTokens) ? maxTokens : 1200,
      temperature: isDeep ? 0.2 : 0.5,
      messages: [
        { role: 'user', content: prompt },
      ],
    };

    const data = await openrouterRequest('/chat/completions', { method: 'POST', body: payload });
    const text = data?.choices?.[0]?.message?.content || data?.choices?.[0]?.text || '';
    res.json({ text });
  } catch (err) {
    console.error('AI proxy error:', err);
    const status = err?.statusCode || 500;
    if (status === 402) {
      return res.status(402).json({ error: 'AI credits exhausted or token limit exceeded' });
    }
    res.status(500).json({ error: 'AI request failed' });
  }
});

// ----- AI Reviewer Generation -----
const MAX_AI_REVIEWERS = 10;
const AI_REVIEWER_MAX_TOKENS = 8000;

function buildReviewerPrompt(pdfText, config) {
  const { questionCount, difficulty, questionMode } = config;
  
  let questionTypeInstructions = '';
  if (questionMode === 'identification') {
    questionTypeInstructions = `Generate ONLY identification questions where the user must type the answer.`;
  } else if (questionMode === 'multiple_choice') {
    questionTypeInstructions = `Generate ONLY multiple choice questions with 4 options (A, B, C, D).`;
  } else if (questionMode === 'true_false') {
    questionTypeInstructions = `Generate ONLY true/false questions.`;
  } else if (questionMode === 'word_matching') {
    questionTypeInstructions = `Generate ONLY word matching questions with 4-5 pairs each where users match terms to their definitions/meanings.`;
  } else {
    // hybrid - random distribution
    questionTypeInstructions = `Generate a MIX of question types: identification (type answer), multiple choice (A/B/C/D), true/false, and word matching (match terms to definitions). Randomly distribute the types.`;
  }

  const difficultyInstructions = {
    easy: 'Questions should be straightforward and test basic recall and understanding.',
    medium: 'Questions should require moderate understanding and some application of concepts.',
    hard: 'Questions should be challenging, requiring deep understanding, analysis, and critical thinking.'
  };

  return `You are an expert quiz generator for educational content. Based on the following PDF content, generate exactly ${questionCount} quiz questions.

${questionTypeInstructions}

Difficulty Level: ${difficulty.toUpperCase()}
${difficultyInstructions[difficulty]}

IMPORTANT RULES:
1. Questions must be based ONLY on the provided content
2. Each question must have a clear, unambiguous correct answer
3. For identification questions, the answer should be a single word or short phrase
4. For multiple choice, always provide exactly 4 options labeled A, B, C, D
5. For true/false, the statement must be clearly true or false based on the content
6. For word matching, provide 4-5 pairs of terms and their matching definitions

OUTPUT FORMAT (JSON array):
[
  {
    "type": "identification",
    "question": "What is the term for...?",
    "correctAnswer": "answer"
  },
  {
    "type": "multiple_choice",
    "question": "Which of the following...?",
    "options": ["A. Option 1", "B. Option 2", "C. Option 3", "D. Option 4"],
    "correctAnswer": "A"
  },
  {
    "type": "true_false",
    "question": "Statement to evaluate as true or false",
    "correctAnswer": "true"
  },
  {
    "type": "word_matching",
    "question": "Match the following terms with their definitions:",
    "pairs": [
      {"id": "1", "left": "Term 1", "right": "Definition 1"},
      {"id": "2", "left": "Term 2", "right": "Definition 2"},
      {"id": "3", "left": "Term 3", "right": "Definition 3"},
      {"id": "4", "left": "Term 4", "right": "Definition 4"}
    ]
  }
]

Also, suggest a short name (2-4 words) for this reviewer based on the main topic of the content.

PDF CONTENT:
${pdfText.slice(0, 10000)}

Respond with ONLY valid JSON in this format:
{
  "suggestedName": "Topic Name",
  "questions": [array of questions as shown above]
}`;
}

app.post('/api/ai/generate-reviewer', requireAuth, aiLimiter, async (req, res) => {
  try {
    const { pdfText, config, reviewerId } = req.body;
    
    if (!pdfText || typeof pdfText !== 'string') {
      return res.status(400).json({ error: 'PDF text is required' });
    }
    
    if (!pdfText.trim() || pdfText.trim().length < 100) {
      return res.status(400).json({ error: "This PDF doesn't contain readable text. Please try a different PDF." });
    }
    
    if (!config || !config.questionCount || !config.difficulty || !config.questionMode) {
      return res.status(400).json({ error: 'Invalid configuration' });
    }

    // Check premium status
    const user = await getOrCreateUser(req.user.uid, req.user.email);
    const hasPremium = user.billing?.plan === 'premium' && isBillingActive(user.billing);
    if (!hasPremium) {
      return res.status(402).json({ error: 'Premium subscription required for AI Reviewers' });
    }

    // Check reviewer limit
    const existingReviewers = user.state?.aiReviewers || [];
    if (existingReviewers.length >= MAX_AI_REVIEWERS) {
      return res.status(400).json({ error: `You've reached the maximum of ${MAX_AI_REVIEWERS} reviewers. Please delete some to create new ones.` });
    }

    const prompt = buildReviewerPrompt(pdfText, config);
    
    // Use the chat model (not reasoning model) for quiz generation
    const reviewerModel = AI_MODEL_FAST; // deepseek-chat works better for structured JSON output
    
    console.log('[AI Reviewer] Starting generation with model:', reviewerModel);
    console.log('[AI Reviewer] PDF text length:', pdfText.length);
    console.log('[AI Reviewer] Config:', JSON.stringify(config));
    
    const payload = {
      model: reviewerModel,
      max_tokens: AI_REVIEWER_MAX_TOKENS,
      temperature: 0.3,
      messages: [
        { role: 'user', content: prompt },
      ],
    };

    let data;
    try {
      data = await openrouterRequest('/chat/completions', { method: 'POST', body: payload });
      console.log('[AI Reviewer] API response received, choices:', data?.choices?.length);
    } catch (apiErr) {
      console.error('[AI Reviewer] API call failed:', apiErr.message);
      console.error('[AI Reviewer] API error payload:', JSON.stringify(apiErr.payload || {}));
      return res.status(500).json({ error: "AI service temporarily unavailable. Please try again in a moment." });
    }
    
    const responseText = data?.choices?.[0]?.message?.content || '';
    console.log('[AI Reviewer] Response text length:', responseText.length);
    
    // Parse the JSON response
    let parsed;
    try {
      // Remove markdown code blocks if present
      let cleanedText = responseText.trim();
      
      // Remove ```json or ``` wrappers
      if (cleanedText.startsWith('```')) {
        cleanedText = cleanedText.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '');
      }
      
      // Try to extract JSON from the cleaned response
      const jsonMatch = cleanedText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        console.error('No JSON found in AI response:', responseText.substring(0, 500));
        throw new Error('No JSON found in response');
      }
      
      parsed = JSON.parse(jsonMatch[0]);
    } catch (parseErr) {
      console.error('Failed to parse AI response:', parseErr);
      console.error('Response text:', responseText.substring(0, 1000));
      return res.status(500).json({ error: "We're sorry, something went wrong while generating your reviewer. Please try again." });
    }

    if (!parsed.questions || !Array.isArray(parsed.questions)) {
      return res.status(500).json({ error: "We're sorry, the AI couldn't generate proper questions. Please try again." });
    }

    // Add IDs to questions
    const questions = parsed.questions.map((q, idx) => ({
      id: `q_${Date.now()}_${idx}`,
      ...q
    }));

    res.json({
      suggestedName: parsed.suggestedName || 'AI Reviewer',
      questions
    });

  } catch (err) {
    console.error('AI reviewer generation error:', err);
    const status = err?.statusCode || 500;
    if (status === 402) {
      return res.status(402).json({ error: 'AI credits exhausted. Please try again later.' });
    }
    res.status(500).json({ error: "We're sorry, something went wrong. Please try again in a moment." });
  }
});

// ----- Background job: deadline reminders -----
async function checkTaskDeadlines() {
  const now = new Date();
  const threeDaysFromNow = new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000);

  try {
    const users = await User.find({
      'state.settings.notifications': true,
      'state.settings.deadlineAlerts': true,
    }, { uid: 1, 'state.tasks': 1 }).lean();

    for (const user of users) {
      const tasks = (user.state?.tasks || []).filter(t => t && !t.completed && t.dueDate);
      for (const task of tasks) {
        const dueDate = new Date(task.dueDate);
        if (dueDate <= now || dueDate > threeDaysFromNow) continue;

        const hoursUntilDue = Math.round((dueDate - now) / (1000 * 60 * 60));
        const daysUntilDue = Math.round(hoursUntilDue / 24);
        let urgencyEmoji = '[SOON]';
        let timeText = '';

        if (hoursUntilDue <= 24) {
          urgencyEmoji = '[SOON]';
          timeText = hoursUntilDue <= 1 ? 'in less than an hour!' : `in ${hoursUntilDue} hours!`;
        } else if (daysUntilDue <= 1) {
          urgencyEmoji = '[ALERT]';
          timeText = 'tomorrow!';
        } else if (daysUntilDue <= 2) {
          urgencyEmoji = '[DUE]';
          timeText = `in ${daysUntilDue} days`;
        } else {
          urgencyEmoji = '[DUE]';
          timeText = `in ${daysUntilDue} days`;
        }

        const dueDisplay = `${dueDate.toLocaleDateString('en-US', {
          month: 'short',
          day: 'numeric',
          year: 'numeric',
        })} at ${dueDate.toLocaleTimeString('en-US', {
          hour: 'numeric',
          minute: '2-digit',
        })}`;
        const subjectParam = task.subjectId ? `&subject=${encodeURIComponent(task.subjectId)}` : '';
        const payload = JSON.stringify({
          title: task.title,
          body: `Is due ${timeText} (${dueDisplay})`,
          icon: '/icons/icon-192x192.svg',
          badge: '/icons/icon-72x72.svg',
          url: `/?page=home${subjectParam}`,
          tag: `task-reminder-${task.id}`,
          data: { taskId: task.id, subjectId: task.subjectId },
        });

        await sendNotificationToUser(user.uid, payload);
      }
    }
  } catch (err) {
    console.error('Deadline reminder job failed:', err);
  }
}

const TWO_HOURS = 2 * 60 * 60 * 1000;
setInterval(checkTaskDeadlines, TWO_HOURS);
setTimeout(checkTaskDeadlines, 30000);

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`AcademiaZen API listening on port ${PORT}`);
});
