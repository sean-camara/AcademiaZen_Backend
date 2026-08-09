/**
 * Push Notification Routes
 * Handles Web Push VAPID subscription management and push delivery triggers.
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const PushSubscription = require('../models/PushSubscription');

const router = express.Router();

// POST /api/push/subscribe - Register Web Push Subscription
router.post('/api/push/subscribe', requireAuth, async (req, res) => {
  try {
    const { subscription } = req.body;
    if (!subscription || !subscription.endpoint) {
      return res.status(400).json({ error: 'Invalid push subscription payload' });
    }

    const uid = req.user.uid;
    await PushSubscription.findOneAndUpdate(
      { uid, 'subscription.endpoint': subscription.endpoint },
      { uid, subscription, updatedAt: new Date() },
      { upsert: true, new: true }
    );

    return res.json({ success: true });
  } catch (err) {
    console.error('[POST /api/push/subscribe] Error:', err);
    return res.status(500).json({ error: 'Failed to save push subscription' });
  }
});

// POST /api/push/unsubscribe - Unregister Push Subscription
router.post('/api/push/unsubscribe', requireAuth, async (req, res) => {
  try {
    const { endpoint } = req.body;
    if (!endpoint) {
      return res.status(400).json({ error: 'Missing endpoint parameter' });
    }

    await PushSubscription.deleteOne({ uid: req.user.uid, 'subscription.endpoint': endpoint });
    return res.json({ success: true });
  } catch (err) {
    console.error('[POST /api/push/unsubscribe] Error:', err);
    return res.status(500).json({ error: 'Failed to remove push subscription' });
  }
});

module.exports = router;
