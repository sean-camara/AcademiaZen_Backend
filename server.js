/**
 * AcademiaZen Push Notification Backend Server
 * 
 * This server handles:
 * 1. VAPID public key distribution
 * 2. Push subscription registration
 * 3. Sending push notifications to subscribed clients
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const webpush = require('web-push');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware - Allow multiple origins for development
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173',
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  credentials: true
}));
app.use(express.json());

// In-memory store for subscriptions (use a database in production)
// Structure: { oderId: subscription }
const subscriptions = new Map();

// Validate VAPID keys
if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY) {
  console.error('\n❌ Error: VAPID keys not found!');
  console.log('Please run: npm run generate-vapid');
  console.log('Then add the keys to your .env file\n');
  
  // Generate keys for convenience
  const keys = webpush.generateVAPIDKeys();
  console.log('Here are freshly generated keys:\n');
  console.log(`VAPID_PUBLIC_KEY=${keys.publicKey}`);
  console.log(`VAPID_PRIVATE_KEY=${keys.privateKey}`);
  console.log('\nAdd these to .env and restart the server.\n');
  process.exit(1);
}

// Configure web-push with VAPID details
webpush.setVapidDetails(
  process.env.VAPID_EMAIL || 'mailto:admin@academiazen.app',
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY
);

// ================== API Routes ==================

/**
 * GET /api/vapid-public-key
 * Returns the VAPID public key for client subscription
 */
app.get('/api/vapid-public-key', (req, res) => {
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

/**
 * POST /api/subscribe
 * Register a new push subscription
 * Body: { subscription: PushSubscription, userId?: string }
 */
app.post('/api/subscribe', (req, res) => {
  const { subscription, userId } = req.body;

  if (!subscription || !subscription.endpoint) {
    return res.status(400).json({ error: 'Invalid subscription object' });
  }

  // Store subscription (use endpoint as key if no userId)
  const id = userId || subscription.endpoint;
  subscriptions.set(id, subscription);

  console.log(`✅ New subscription registered: ${id.substring(0, 50)}...`);
  console.log(`   Total subscriptions: ${subscriptions.size}`);

  res.status(201).json({ 
    success: true, 
    message: 'Subscription registered successfully' 
  });
});

/**
 * DELETE /api/unsubscribe
 * Remove a push subscription
 * Body: { endpoint: string }
 */
app.delete('/api/unsubscribe', (req, res) => {
  const { endpoint, userId } = req.body;
  const id = userId || endpoint;

  if (subscriptions.has(id)) {
    subscriptions.delete(id);
    console.log(`🗑️  Subscription removed: ${id.substring(0, 50)}...`);
    res.json({ success: true, message: 'Unsubscribed successfully' });
  } else {
    res.status(404).json({ error: 'Subscription not found' });
  }
});

/**
 * POST /api/send-notification
 * Send a push notification to a specific subscription or all subscribers
 * Body: { 
 *   title: string, 
 *   body: string, 
 *   icon?: string,
 *   url?: string,
 *   userId?: string (if not provided, sends to all)
 * }
 */
app.post('/api/send-notification', async (req, res) => {
  const { title, body, icon, url, data, userId } = req.body;

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
    timestamp: Date.now()
  });

  const options = {
    TTL: 86400, // Time to live: 24 hours
    urgency: 'normal'
  };

  try {
    if (userId && subscriptions.has(userId)) {
      // Send to specific user
      await webpush.sendNotification(subscriptions.get(userId), payload, options);
      res.json({ success: true, message: 'Notification sent to user' });
    } else if (!userId) {
      // Send to all subscribers
      const results = await Promise.allSettled(
        Array.from(subscriptions.entries()).map(async ([id, sub]) => {
          try {
            await webpush.sendNotification(sub, payload, options);
            return { id, success: true };
          } catch (error) {
            // Remove invalid subscriptions (410 Gone means unsubscribed)
            if (error.statusCode === 410) {
              subscriptions.delete(id);
              console.log(`🗑️  Removed expired subscription: ${id.substring(0, 50)}...`);
            }
            return { id, success: false, error: error.message };
          }
        })
      );

      const sent = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
      res.json({ 
        success: true, 
        message: `Notification sent to ${sent}/${subscriptions.size} subscribers` 
      });
    } else {
      res.status(404).json({ error: 'User subscription not found' });
    }
  } catch (error) {
    console.error('❌ Push notification error:', error);
    res.status(500).json({ error: 'Failed to send notification' });
  }
});

/**
 * POST /api/schedule-notification
 * Schedule a notification to be sent at a specific time
 * Body: { 
 *   title: string, 
 *   body: string, 
 *   scheduledTime: ISO string,
 *   userId?: string
 * }
 */
app.post('/api/schedule-notification', (req, res) => {
  const { title, body, scheduledTime, userId, icon, url } = req.body;

  if (!title || !body || !scheduledTime) {
    return res.status(400).json({ error: 'Title, body, and scheduledTime are required' });
  }

  const delay = new Date(scheduledTime).getTime() - Date.now();
  
  if (delay < 0) {
    return res.status(400).json({ error: 'Scheduled time must be in the future' });
  }

  // Schedule the notification (in production, use a proper job queue)
  setTimeout(async () => {
    const payload = JSON.stringify({
      title,
      body,
      icon: icon || '/icons/icon-192x192.svg',
      badge: '/icons/icon-72x72.svg',
      url: url || '/',
      timestamp: Date.now()
    });

    const targets = userId && subscriptions.has(userId) 
      ? [[userId, subscriptions.get(userId)]]
      : Array.from(subscriptions.entries());

    for (const [id, sub] of targets) {
      try {
        await webpush.sendNotification(sub, payload);
        console.log(`📤 Scheduled notification sent to: ${id.substring(0, 50)}...`);
      } catch (error) {
        if (error.statusCode === 410) {
          subscriptions.delete(id);
        }
        console.error(`❌ Failed to send scheduled notification: ${error.message}`);
      }
    }
  }, delay);

  console.log(`⏰ Notification scheduled for: ${scheduledTime}`);
  res.json({ 
    success: true, 
    message: `Notification scheduled for ${scheduledTime}` 
  });
});

/**
 * GET /api/subscriptions/count
 * Get the count of active subscriptions (for admin/debug)
 */
app.get('/api/subscriptions/count', (req, res) => {
  res.json({ count: subscriptions.size });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`\n🚀 AcademiaZen Push Notification Server`);
  console.log(`   Running on http://localhost:${PORT}`);
  console.log(`   VAPID Public Key: ${process.env.VAPID_PUBLIC_KEY.substring(0, 30)}...`);
  console.log(`\n📡 Endpoints:`);
  console.log(`   GET  /api/vapid-public-key    - Get VAPID public key`);
  console.log(`   POST /api/subscribe           - Register subscription`);
  console.log(`   DELETE /api/unsubscribe       - Remove subscription`);
  console.log(`   POST /api/send-notification   - Send notification`);
  console.log(`   POST /api/schedule-notification - Schedule notification`);
  console.log(`   GET  /api/subscriptions/count - Get subscriber count\n`);
});
