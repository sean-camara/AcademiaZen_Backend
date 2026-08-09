/**
 * State Sync & Account Identity Routes
 * Handles user Zen state persistence, optimistic concurrency revision checks, and account role queries.
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { User, getDefaultState } = require('../models/User');
const { buildStateRevisionFilter, hasValidRevision } = require('../services/stateRevision');

const router = express.Router();

// GET /api/me/role - Fetch user role
router.get('/api/me/role', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ uid: req.user.uid }).select('role').lean();
    return res.json({ role: user?.role || 'user' });
  } catch (err) {
    console.error('[GET /api/me/role] Error:', err);
    return res.status(500).json({ error: 'Failed to fetch user role' });
  }
});

// GET /api/me - Fetch authenticated user document snapshot
router.get('/api/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ uid: req.user.uid });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json(user);
  } catch (err) {
    console.error('[GET /api/me] Error:', err);
    return res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// GET /api/state - Retrieve Zen State with revision
router.get('/api/state', requireAuth, async (req, res) => {
  try {
    let user = await User.findOne({ uid: req.user.uid });
    if (!user) {
      user = await User.create({
        uid: req.user.uid,
        email: req.user.email || '',
        state: getDefaultState(),
      });
    }

    const state = user.state || getDefaultState();
    const revision = user.stateRevision || 1;

    return res.json({
      state,
      revision,
      updatedAt: user.updatedAt,
      billing: user.billing,
    });
  } catch (err) {
    console.error('[GET /api/state] Error:', err);
    return res.status(500).json({ error: 'Failed to fetch state' });
  }
});

// PUT /api/state - Sync/Save Zen State with revision concurrency lock
router.put('/api/state', requireAuth, async (req, res) => {
  try {
    const { state, expectedRevision } = req.body;
    if (!state || typeof state !== 'object') {
      return res.status(400).json({ error: 'Invalid state object' });
    }

    const uid = req.user.uid;
    const filter = buildStateRevisionFilter(uid, expectedRevision);

    let user = await User.findOne(filter);
    if (!user && expectedRevision !== undefined) {
      // Revision conflict — fetch current server state
      const current = await User.findOne({ uid });
      return res.status(409).json({
        error: 'state_conflict',
        message: 'State has been updated from another device',
        currentRevision: current?.stateRevision || 1,
        currentState: current?.state || getDefaultState(),
      });
    }

    if (!user) {
      user = await User.findOne({ uid });
    }

    if (!user) {
      user = new User({ uid, email: req.user.email || '' });
    }

    user.state = state;
    user.stateRevision = (user.stateRevision || 0) + 1;
    user.updatedAt = new Date();

    await user.save();

    return res.json({
      success: true,
      revision: user.stateRevision,
      updatedAt: user.updatedAt,
    });
  } catch (err) {
    console.error('[PUT /api/state] Error:', err);
    return res.status(500).json({ error: 'Failed to save state' });
  }
});

module.exports = router;
