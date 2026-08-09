/**
 * Authentication & Self-Service Account Routes
 * Handles system ping health, account deletion, and security verification.
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { deleteAccount } = require('../services/accountDeletion');

const router = express.Router();

// GET /api/auth/ping - Authenticated Liveness Check
router.get('/api/auth/ping', requireAuth, (req, res) => {
  return res.json({
    status: 'ok',
    uid: req.user.uid,
    email: req.user.email || null,
    timestamp: new Date().toISOString(),
  });
});

// POST /api/auth/delete-account - Self-Service Account Erasure
router.post('/api/auth/delete-account', requireAuth, async (req, res) => {
  try {
    const result = await deleteAccount(req.user.uid);
    return res.json({
      success: true,
      message: 'Account successfully deleted from system',
      details: result,
    });
  } catch (err) {
    console.error('[POST /api/auth/delete-account] Error:', err);
    return res.status(500).json({ error: 'Failed to complete account erasure request' });
  }
});

module.exports = router;
