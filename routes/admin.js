const express = require('express');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { User } = require('../models/User');
const { FocusSession } = require('../models/FocusSession');
const { AILog } = require('../models/AILog');
const Announcement = require('../models/Announcement');
const Feedback = require('../models/Feedback');
const SystemSetting = require('../models/SystemSetting');
const router = express.Router();

// Public / Authenticated User helper routes
router.get('/api/me/role', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ uid: req.user.uid }).lean();
    const adminEmails = (process.env.ADMIN_EMAILS || 'admin123@admin.com')
      .split(',')
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean);

    const isEmailAdmin = adminEmails.includes((req.user.email || '').toLowerCase());
    const role = user?.role === 'admin' || isEmailAdmin || req.user.isAdminClaim ? 'admin' : 'user';

    res.json({ uid: req.user.uid, email: req.user.email, role });
  } catch (err) {
    console.error('Failed to get user role:', err);
    res.status(500).json({ error: 'Failed to load user role' });
  }
});

router.get('/api/announcements/active', async (req, res) => {
  try {
    const Announcement = require('../models/Announcement');
    const announcements = await Announcement.find({ isActive: true }).sort({ createdAt: -1 }).limit(3).lean();
    res.json({ announcements: announcements || [] });
  } catch (err) {
    console.error('Failed to load announcements:', err);
    res.json({ announcements: [] });
  }
});

router.post('/api/feedback', requireAuth, async (req, res) => {
  try {
    const { category, message } = req.body || {};
    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Feedback message is required' });
    }

    const item = await Feedback.create({
      uid: req.user.uid,
      email: req.user.email || '',
      category: ['bug', 'feature', 'general', 'billing'].includes(category) ? category : 'general',
      message: message.trim(),
    });

    res.json({ success: true, feedback: item });
  } catch (err) {
    console.error('Failed to submit feedback:', err);
    res.status(500).json({ error: 'Failed to submit feedback' });
  }
});

// Admin-only protected endpoints
router.use('/api/admin', requireAuth, requireAdmin);

// 1. Overview Dashboard Metrics
router.get('/api/admin/overview', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const todayStr = new Date().toISOString().split('T')[0];
    const monthStr = todayStr.substring(0, 7);

    const activeUsersToday = await User.countDocuments({
      'state.updatedAt': { $regex: `^${todayStr}` },
    });

    const premiumUsers = await User.countDocuments({ 'billing.plan': 'premium', 'billing.status': 'active' });
    const freeUsers = Math.max(0, totalUsers - premiumUsers);

    const promptsToday = await AILog.countDocuments({
      createdAt: { $gte: new Date(todayStr + 'T00:00:00Z') },
    });

    const promptsMonth = await AILog.countDocuments({
      createdAt: { $gte: new Date(monthStr + '-01T00:00:00Z') },
    });

    const focusAgg = await FocusSession.aggregate([
      { $match: { endedAt: { $ne: null } } },
      { $group: { _id: null, totalSeconds: { $sum: '$actualDurationSeconds' }, count: { $sum: 1 } } },
    ]);
    const totalFocusMinutes = Math.round((focusAgg[0]?.totalSeconds || 0) / 60);

    // Calculate approximate MRR
    const monthlySubs = await User.countDocuments({ 'billing.plan': 'premium', 'billing.interval': 'monthly', 'billing.status': 'active' });
    const weeklySubs = await User.countDocuments({ 'billing.plan': 'premium', 'billing.interval': 'weekly', 'billing.status': 'active' });
    const estimatedMRR = (monthlySubs * 149) + (weeklySubs * 196); // 49/wk ~ 196/mo

    res.json({
      totalUsers,
      activeUsersToday,
      premiumUsers,
      freeUsers,
      promptsToday,
      promptsMonth,
      totalFocusMinutes,
      totalFocusSessions: focusAgg[0]?.count || 0,
      estimatedMRR,
    });
  } catch (err) {
    console.error('Admin overview failed:', err);
    res.status(500).json({ error: 'Failed to generate admin overview' });
  }
});

// 2. User Directory & RBAC
router.get('/api/admin/users', async (req, res) => {
  try {
    const { q, role, plan, page = 1, limit = 20 } = req.query;
    const filter = {};

    if (q) {
      filter.$or = [
        { email: { $regex: String(q), $options: 'i' } },
        { uid: { $regex: String(q), $options: 'i' } },
        { 'state.profile.firstName': { $regex: String(q), $options: 'i' } },
        { 'state.profile.lastName': { $regex: String(q), $options: 'i' } },
      ];
    }
    if (role && ['user', 'admin'].includes(role)) {
      filter.role = role;
    }
    if (plan && ['free', 'premium'].includes(plan)) {
      filter['billing.plan'] = plan;
    }

    const skip = (Math.max(1, Number(page)) - 1) * Number(limit);
    const users = await User.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .select('uid email role billing aiUsage createdAt updatedAt state.profile')
      .lean();

    const total = await User.countDocuments(filter);

    const formattedUsers = users.map((u) => ({
      uid: u.uid,
      email: u.email || 'N/A',
      name: `${u.state?.profile?.firstName || ''} ${u.state?.profile?.lastName || ''}`.trim() || 'Student',
      role: u.role || 'user',
      plan: u.billing?.plan || 'free',
      billingStatus: u.billing?.status || 'free',
      dailyAiCount: u.aiUsage?.dailyCount || 0,
      totalAiRequests: u.aiUsage?.totalRequests || 0,
      createdAt: u.createdAt,
      lastActive: u.updatedAt,
    }));

    res.json({ users: formattedUsers, total, page: Number(page), totalPages: Math.ceil(total / Number(limit)) });
  } catch (err) {
    console.error('Failed to search users:', err);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

router.post('/api/admin/users/:uid/role', async (req, res) => {
  try {
    const { role } = req.body || {};
    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Role must be user or admin' });
    }

    const user = await User.findOne({ uid: req.params.uid });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.role = role;
    await user.save();
    res.json({ success: true, uid: user.uid, role: user.role });
  } catch (err) {
    console.error('Failed to set user role:', err);
    res.status(500).json({ error: 'Failed to set user role' });
  }
});

router.post('/api/admin/users/:uid/plan', async (req, res) => {
  try {
    const { plan, interval, days } = req.body || {};
    if (!['free', 'premium'].includes(plan)) {
      return res.status(400).json({ error: 'Plan must be free or premium' });
    }

    const user = await User.findOne({ uid: req.params.uid });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.billing) user.billing = {};

    if (plan === 'free') {
      user.billing.plan = 'free';
      user.billing.status = 'free';
      user.billing.currentPeriodEnd = null;
    } else {
      user.billing.plan = 'premium';
      user.billing.status = 'active';
      user.billing.interval = ['weekly', 'monthly', 'yearly'].includes(interval) ? interval : 'monthly';
      const durationDays = Number(days) || 30;
      const end = new Date();
      end.setDate(end.getDate() + durationDays);
      user.billing.currentPeriodEnd = end;
    }

    await user.save();
    res.json({ success: true, uid: user.uid, billing: user.billing });
  } catch (err) {
    console.error('Failed to set user plan:', err);
    res.status(500).json({ error: 'Failed to set user plan' });
  }
});

router.post('/api/admin/users/:uid/reset-ai', async (req, res) => {
  try {
    const user = await User.findOne({ uid: req.params.uid });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.aiUsage) user.aiUsage = {};
    user.aiUsage.dailyCount = 0;
    user.aiUsage.cooldownUntil = null;
    user.aiUsage.requestsThisMinute = 0;
    await user.save();

    res.json({ success: true, message: 'AI quotas successfully reset for user' });
  } catch (err) {
    console.error('Failed to reset AI quota:', err);
    res.status(500).json({ error: 'Failed to reset AI quota' });
  }
});

// 3. Academic Analytics
router.get('/api/admin/analytics/academics', async (req, res) => {
  try {
    const subjectsPipeline = await User.aggregate([
      { $unwind: '$state.subjects' },
      { $group: { _id: '$state.subjects.name', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]);

    const quizAgg = await User.aggregate([
      { $unwind: '$state.aiReviewers' },
      { $unwind: '$state.aiReviewers.attempts' },
      {
        $group: {
          _id: null,
          avgScore: { $avg: '$state.aiReviewers.attempts.score' },
          totalAttempts: { $sum: 1 },
        },
      },
    ]);

    res.json({
      topSubjects: subjectsPipeline.map((s) => ({ subject: s._id || 'General', count: s.count })),
      avgQuizScore: Math.round((quizAgg[0]?.avgScore || 0) * 10) / 10,
      totalQuizAttempts: quizAgg[0]?.totalAttempts || 0,
    });
  } catch (err) {
    console.error('Failed academic analytics:', err);
    res.status(500).json({ error: 'Failed academic analytics' });
  }
});

// 4. AI Request Logs
router.get('/api/admin/ai/logs', async (req, res) => {
  try {
    const { page = 1, limit = 30 } = req.query;
    const skip = (Math.max(1, Number(page)) - 1) * Number(limit);

    const logs = await AILog.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .lean();

    const total = await AILog.countDocuments();
    res.json({ logs, total, page: Number(page) });
  } catch (err) {
    console.error('Failed to load AI logs:', err);
    res.status(500).json({ error: 'Failed to load AI logs' });
  }
});

// 5. Billing Transactions & PayMongo Logs
router.get('/api/admin/payments', async (req, res) => {
  try {
    const usersWithBilling = await User.find({
      'billing.lastPaymentAt': { $exists: true, $ne: null },
    })
      .sort({ 'billing.lastPaymentAt': -1 })
      .limit(50)
      .select('uid email billing')
      .lean();

    const transactions = usersWithBilling.map((u) => ({
      uid: u.uid,
      email: u.email,
      plan: u.billing?.plan,
      interval: u.billing?.interval,
      status: u.billing?.status,
      lastPaymentAt: u.billing?.lastPaymentAt,
      paymentId: u.billing?.paymongo?.paymentId || u.billing?.paymongo?.checkoutId || 'N/A',
      amount: u.billing?.interval === 'weekly' ? 'PHP 49.00' : 'PHP 149.00',
    }));

    res.json({ transactions });
  } catch (err) {
    console.error('Failed to load payment logs:', err);
    res.status(500).json({ error: 'Failed to load payment logs' });
  }
});

// 6. Announcements / Broadcast Banners
router.get('/api/admin/announcements', async (req, res) => {
  try {
    const announcements = await Announcement.find().sort({ createdAt: -1 }).lean();
    res.json({ announcements });
  } catch (err) {
    console.error('Failed to load announcements:', err);
    res.status(500).json({ error: 'Failed to load announcements' });
  }
});

router.post('/api/admin/announcements', async (req, res) => {
  try {
    const { title, message, type = 'info' } = req.body || {};
    if (!title || !message) {
      return res.status(400).json({ error: 'Title and message are required' });
    }

    const announcement = await Announcement.create({
      title,
      message,
      type,
      createdBy: req.user.email || req.user.uid,
    });

    res.json({ success: true, announcement });
  } catch (err) {
    console.error('Failed to create announcement:', err);
    res.status(500).json({ error: 'Failed to create announcement' });
  }
});

router.delete('/api/admin/announcements/:id', async (req, res) => {
  try {
    await Announcement.deleteOne({ _id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to delete announcement:', err);
    res.status(500).json({ error: 'Failed to delete announcement' });
  }
});

// 7. Feedback Desk
router.get('/api/admin/feedback', async (req, res) => {
  try {
    const items = await Feedback.find().sort({ createdAt: -1 }).limit(100).lean();
    res.json({ feedback: items });
  } catch (err) {
    console.error('Failed to load feedback:', err);
    res.status(500).json({ error: 'Failed to load feedback' });
  }
});

router.post('/api/admin/feedback/:id/reply', async (req, res) => {
  try {
    const { reply, status = 'resolved' } = req.body || {};
    if (!reply) {
      return res.status(400).json({ error: 'Reply text is required' });
    }

    const item = await Feedback.findById(req.params.id);
    if (!item) {
      return res.status(404).json({ error: 'Feedback ticket not found' });
    }

    item.reply = reply;
    item.status = status;
    item.repliedAt = new Date();
    item.repliedBy = req.user.email || req.user.uid;
    await item.save();

    res.json({ success: true, feedback: item });
  } catch (err) {
    console.error('Failed to reply to feedback:', err);
    res.status(500).json({ error: 'Failed to reply to feedback' });
  }
});

// 8. System Health
router.get('/api/admin/health', async (req, res) => {
  try {
    const dbState = require('mongoose').connection.readyState;
    const dbStatusMap = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };

    const memUsage = process.memoryUsage();
    const formattedMem = {
      rssMb: Math.round(memUsage.rss / 1024 / 1024),
      heapTotalMb: Math.round(memUsage.heapTotal / 1024 / 1024),
      heapUsedMb: Math.round(memUsage.heapUsed / 1024 / 1024),
    };

    const maintenanceSetting = await SystemSetting.findOne({ key: 'maintenance_mode' }).lean();

    res.json({
      database: dbStatusMap[dbState] || 'unknown',
      memory: formattedMem,
      uptimeSeconds: Math.round(process.uptime()),
      maintenanceMode: Boolean(maintenanceSetting?.value),
      nodeVersion: process.version,
    });
  } catch (err) {
    console.error('Failed health check:', err);
    res.status(500).json({ error: 'Failed health check' });
  }
});

router.post('/api/admin/maintenance', async (req, res) => {
  try {
    const { enabled } = req.body || {};
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'enabled must be a boolean' });
    }

    await SystemSetting.findOneAndUpdate(
      { key: 'maintenance_mode' },
      { value: enabled, updatedBy: req.user.email || req.user.uid },
      { upsert: true, new: true }
    );

    res.json({ success: true, maintenanceMode: enabled });
  } catch (err) {
    console.error('Failed to update maintenance mode:', err);
    res.status(500).json({ error: 'Failed to update maintenance mode' });
  }
});

module.exports = router;
