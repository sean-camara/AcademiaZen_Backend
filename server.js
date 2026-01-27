/**
 * AcademiaZen API Server
 *
 * Responsibilities:
 * - Firebase Auth verification
 * - MongoDB persistence (Zen state + push subscriptions)
 * - Web Push notifications
 * - AI proxy endpoint (Gemini)
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const webpush = require('web-push');

const { requireAuth, requireAdmin, initFirebaseAdmin } = require('./middleware/auth');
const { User, getDefaultState } = require('./models/User');
const PushSubscription = require('./models/PushSubscription');

let GoogleGenerativeAI;
try {
  ({ GoogleGenerativeAI } = require('@google/generative-ai'));
} catch (_) {
  // Optional at runtime; handled when AI endpoint is called.
}

const app = express();

// Trust proxy for rate limiting and correct IPs behind Nginx
app.set('trust proxy', 1);

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

app.use(express.json({ limit: '15mb' }));

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
      if (task?.pdfAttachment?.data && task.pdfAttachment.data.length > MAX_ATTACHMENT_BASE64_LEN) {
        task.pdfAttachment.data = '';
      }
      return task;
    });
  }

  if (Array.isArray(sanitized.folders)) {
    sanitized.folders = sanitized.folders.map(folder => {
      if (Array.isArray(folder.items)) {
        folder.items = folder.items.map(item => {
          if (item?.type === 'pdf' && item.content && item.content.length > MAX_ATTACHMENT_BASE64_LEN) {
            item.content = '';
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
        if (task?.pdfAttachment?.data) {
          task.pdfAttachment.data = '';
        }
        return task;
      });
    }
    if (Array.isArray(sanitized.folders)) {
      sanitized.folders = sanitized.folders.map(folder => {
        if (Array.isArray(folder.items)) {
          folder.items = folder.items.map(item => {
            if (item?.type === 'pdf' && item.content) {
              item.content = '';
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

// ----- Routes -----
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/vapid-public-key', (req, res) => {
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
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

  const payload = JSON.stringify({
    title: `${urgencyEmoji} New Task Added`,
    body: `"${task.title}" is due ${timeText}`,
    icon: '/icons/icon-192x192.svg',
    badge: '/icons/icon-72x72.svg',
    url: '/?page=home',
    tag: `new-task-${task.id}`,
    data: { taskId: task.id },
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
    const { prompt } = req.body;
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'Prompt is required' });
    }
    if (!process.env.GEMINI_API_KEY) {
      return res.status(500).json({ error: 'AI API key is not configured' });
    }
    if (!GoogleGenerativeAI) {
      return res.status(500).json({ error: 'AI dependency is missing' });
    }

    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const modelName = process.env.GEMINI_MODEL || 'gemini-1.5-flash';
    const model = genAI.getGenerativeModel({ model: modelName });
    const result = await model.generateContent(prompt);
    const text = result?.response?.text?.() || '';
    res.json({ text });
  } catch (err) {
    console.error('AI proxy error:', err);
    res.status(500).json({ error: 'AI request failed' });
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

        const payload = JSON.stringify({
          title: `${urgencyEmoji} Task Reminder`,
          body: `"${task.title}" is due ${timeText}`,
          icon: '/icons/icon-192x192.svg',
          badge: '/icons/icon-72x72.svg',
          url: '/?page=home',
          tag: `task-reminder-${task.id}`,
          data: { taskId: task.id },
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
