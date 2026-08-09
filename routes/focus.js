/**
 * Focus Session Telemetry Routes
 * Handles Pomodoro session logging, historical stats, and study telemetry aggregation.
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { FocusSession } = require('../models/FocusSession');

const router = express.Router();

// GET /api/focus/sessions - List past focus sessions
router.get('/api/focus/sessions', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit || 50), 100);
    const sessions = await FocusSession.find({ uid: req.user.uid })
      .sort({ startTime: -1 })
      .limit(limit)
      .lean();

    return res.json({ sessions });
  } catch (err) {
    console.error('[GET /api/focus/sessions] Error:', err);
    return res.status(500).json({ error: 'Failed to fetch focus sessions' });
  }
});

// POST /api/focus/sessions - Log completed focus session
router.post('/api/focus/sessions', requireAuth, async (req, res) => {
  try {
    const { durationMinutes, mode, subject, taskTitle, completed } = req.body;

    const session = await FocusSession.create({
      uid: req.user.uid,
      durationMinutes: Number(durationMinutes) || 25,
      mode: mode || 'pomodoro',
      subject: subject || 'General',
      taskTitle: taskTitle || '',
      completed: completed !== false,
      startTime: new Date(),
    });

    return res.json({ success: true, session });
  } catch (err) {
    console.error('[POST /api/focus/sessions] Error:', err);
    return res.status(500).json({ error: 'Failed to log focus session' });
  }
});

module.exports = router;
