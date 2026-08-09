const express = require('express');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { User } = require('../models/User');
const { FocusSession } = require('../models/FocusSession');
const { AILog } = require('../models/AILog');
const Announcement = require('../models/Announcement');
const Feedback = require('../models/Feedback');
const SystemSetting = require('../models/SystemSetting');
const { AdminAuditLog } = require('../models/AdminAuditLog');
const router = express.Router();

async function logAdminAction(req, action, targetUid = null, details = {}) {
  try {
    await AdminAuditLog.create({
      adminUid: req.user?.uid || 'system',
      adminEmail: req.user?.email || 'admin@academiazen.com',
      action,
      targetUid,
      details,
      ipAddress: req.ip || req.socket?.remoteAddress || '',
    });
  } catch (err) {
    console.warn('[logAdminAction] Warning: Failed to record audit log:', err);
  }
}

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

    // Calculate 7-day activity telemetry
    const now = new Date();
    const dailyStats = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(now.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      const dayName = d.toLocaleDateString('en-US', { weekday: 'short' });

      const dayActiveUsers = await User.countDocuments({ 'state.updatedAt': { $regex: `^${dateStr}` } });
      const dayAiRequests = await AILog.countDocuments({
        createdAt: {
          $gte: new Date(dateStr + 'T00:00:00Z'),
          $lte: new Date(dateStr + 'T23:59:59Z'),
        },
      });

      dailyStats.push({
        date: dateStr,
        dayName,
        activeUsers: dayActiveUsers,
        aiRequests: dayAiRequests,
      });
    }

    // Recent activity feed
    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select('email role billing createdAt')
      .lean();

    const recentActivity = recentUsers.map(u => ({
      id: u._id.toString(),
      type: 'signup',
      title: `New student registered: ${u.email || 'Anonymous'}`,
      timestamp: u.createdAt,
      badge: u.billing?.plan === 'premium' ? 'Pro' : 'Free',
    }));

    // Top subjects
    const subjectsPipeline = await User.aggregate([
      { $unwind: '$state.subjects' },
      { $group: { _id: '$state.subjects.name', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 4 },
    ]);

    const monthlySubs = await User.countDocuments({ 'billing.plan': 'premium', 'billing.interval': 'monthly', 'billing.status': 'active' });
    const weeklySubs = await User.countDocuments({ 'billing.plan': 'premium', 'billing.interval': 'weekly', 'billing.status': 'active' });
    const estimatedMRR = (monthlySubs * 149) + (weeklySubs * 196); // 49/wk ~ 196/mo

    const conversionRate = totalUsers > 0 ? Math.round((premiumUsers / totalUsers) * 1000) / 10 : 0;

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
      conversionRate,
      dailyStats,
      recentActivity,
      topSubjects: subjectsPipeline.map(s => ({ subject: s._id || 'General', count: s.count })),
    });
  } catch (err) {
    console.error('Admin overview failed:', err);
    res.status(500).json({ error: 'Failed to generate admin overview' });
  }
});

// 2. User Directory & RBAC
router.get('/api/admin/users', async (req, res) => {
  try {
    const { q, role, plan, status, page = 1, limit = 20 } = req.query;
    const filter = {};

    if (q) {
      filter.$or = [
        { email: { $regex: String(q), $options: 'i' } },
        { uid: { $regex: String(q), $options: 'i' } },
        { 'state.profile.firstName': { $regex: String(q), $options: 'i' } },
        { 'state.profile.lastName': { $regex: String(q), $options: 'i' } },
      ];
    }
    if (role && ['user', 'admin'].includes(String(role))) {
      filter.role = role;
    }
    if (plan && ['free', 'premium'].includes(String(plan))) {
      filter['billing.plan'] = plan;
    }
    if (status === 'suspended') {
      filter.isSuspended = true;
    } else if (status === 'active') {
      filter.isSuspended = { $ne: true };
    }

    const skip = (Math.max(1, Number(page)) - 1) * Number(limit);
    const users = await User.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .select('uid email role isSuspended billing aiUsage createdAt updatedAt state.profile state.subjects state.tasks')
      .lean();

    const total = await User.countDocuments(filter);

    const formattedUsers = users.map((u) => ({
      uid: u.uid,
      email: u.email || 'N/A',
      name: `${u.state?.profile?.firstName || ''} ${u.state?.profile?.lastName || ''}`.trim() || 'Student',
      role: u.role || 'user',
      isSuspended: Boolean(u.isSuspended),
      plan: u.billing?.plan || 'free',
      billingStatus: u.billing?.status || 'free',
      dailyAiCount: u.aiUsage?.dailyCount || 0,
      totalAiRequests: u.aiUsage?.totalRequests || 0,
      subjectCount: u.state?.subjects?.length || 0,
      taskCount: u.state?.tasks?.length || 0,
      createdAt: u.createdAt,
      lastActive: u.updatedAt,
    }));

    res.json({ users: formattedUsers, total, page: Number(page), totalPages: Math.ceil(total / Number(limit)) });
  } catch (err) {
    console.error('Failed to search users:', err);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

// CSV Export for Users
router.get('/api/admin/users/export', async (req, res) => {
  try {
    const users = await User.find()
      .sort({ createdAt: -1 })
      .select('uid email role isSuspended billing aiUsage createdAt')
      .lean();

    let csv = 'UID,Email,Role,Plan,Status,Suspended,DailyAICount,TotalAIRequests,JoinedDate\n';
    for (const u of users) {
      csv += `"${u.uid}","${u.email || ''}","${u.role || 'user'}","${u.billing?.plan || 'free'}","${u.billing?.status || 'free'}","${u.isSuspended ? 'YES' : 'NO'}",${u.aiUsage?.dailyCount || 0},${u.aiUsage?.totalRequests || 0},"${new Date(u.createdAt).toISOString()}"\n`;
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="academiazen_users.csv"');
    res.send(csv);
  } catch (err) {
    console.error('Failed to export users CSV:', err);
    res.status(500).json({ error: 'Failed to export users CSV' });
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

    const previousRole = user.role;
    user.role = role;
    await user.save();

    await logAdminAction(req, 'UPDATE_ROLE', user.uid, { previousRole, newRole: role });

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

    const previousPlan = user.billing.plan;
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
    await logAdminAction(req, 'UPDATE_PLAN', user.uid, { previousPlan, newPlan: plan, interval, days });

    res.json({ success: true, uid: user.uid, billing: user.billing });
  } catch (err) {
    console.error('Failed to set user plan:', err);
    res.status(500).json({ error: 'Failed to set user plan' });
  }
});

router.post('/api/admin/users/:uid/suspend', async (req, res) => {
  try {
    const { suspend } = req.body || {};
    if (typeof suspend !== 'boolean') {
      return res.status(400).json({ error: 'suspend parameter must be a boolean' });
    }

    const user = await User.findOne({ uid: req.params.uid });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.isSuspended = suspend;
    await user.save();

    await logAdminAction(req, suspend ? 'SUSPEND_USER' : 'UNSUSPEND_USER', user.uid, { email: user.email });

    res.json({ success: true, uid: user.uid, isSuspended: user.isSuspended });
  } catch (err) {
    console.error('Failed to suspend user:', err);
    res.status(500).json({ error: 'Failed to update user suspension status' });
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

    await logAdminAction(req, 'RESET_AI_QUOTA', user.uid, { email: user.email });

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
    const { status, endpoint, page = 1, limit = 30 } = req.query;
    const filter = {};
    if (status === 'success') filter.success = true;
    if (status === 'failed') filter.success = false;
    if (endpoint) filter.endpoint = String(endpoint);

    const skip = (Math.max(1, Number(page)) - 1) * Number(limit);

    const logs = await AILog.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .lean();

    const total = await AILog.countDocuments(filter);

    // Summary Telemetry
    const stats = await AILog.aggregate([
      { $match: filter },
      {
        $group: {
          _id: null,
          avgTokens: { $avg: '$totalTokens' },
          avgLatency: { $avg: '$responseTimeMs' },
          failedCount: { $sum: { $cond: [{ $eq: ['$success', false] }, 1, 0] } },
          totalCount: { $sum: 1 },
        },
      },
    ]);

    const avgLatency = Math.round(stats[0]?.avgLatency || 0);
    const avgTokens = Math.round(stats[0]?.avgTokens || 0);
    const errorRate = stats[0]?.totalCount ? Math.round((stats[0].failedCount / stats[0].totalCount) * 1000) / 10 : 0;

    res.json({ logs, total, page: Number(page), avgLatency, avgTokens, errorRate });
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

    await logAdminAction(req, 'CREATE_ANNOUNCEMENT', null, { title, type });

    res.json({ success: true, announcement });
  } catch (err) {
    console.error('Failed to create announcement:', err);
    res.status(500).json({ error: 'Failed to create announcement' });
  }
});

router.delete('/api/admin/announcements/:id', async (req, res) => {
  try {
    await Announcement.deleteOne({ _id: req.params.id });
    await logAdminAction(req, 'DELETE_ANNOUNCEMENT', null, { id: req.params.id });

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

    await logAdminAction(req, 'REPLY_FEEDBACK', item.uid, { ticketId: item._id, reply });

    res.json({ success: true, feedback: item });
  } catch (err) {
    console.error('Failed to reply to feedback:', err);
    res.status(500).json({ error: 'Failed to reply to feedback' });
  }
});

// 8. Admin Audit Trail Logs
router.get('/api/admin/audit-logs', async (req, res) => {
  try {
    const logs = await AdminAuditLog.find().sort({ createdAt: -1 }).limit(50).lean();
    res.json({ logs });
  } catch (err) {
    console.error('Failed to load audit logs:', err);
    res.status(500).json({ error: 'Failed to load audit logs' });
  }
});

// 9. System Health
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

    await logAdminAction(req, enabled ? 'ENABLE_MAINTENANCE' : 'DISABLE_MAINTENANCE', null, { enabled });

    res.json({ success: true, maintenanceMode: enabled });
  } catch (err) {
    console.error('Failed to update maintenance mode:', err);
    res.status(500).json({ error: 'Failed to update maintenance mode' });
  }
});

// Batch User Actions
router.post('/api/admin/users/batch', async (req, res) => {
  try {
    const { uids, action, value } = req.body || {};
    if (!Array.isArray(uids) || uids.length === 0) {
      return res.status(400).json({ error: 'uids array is required' });
    }

    if (action === 'grant_plan') {
      await User.updateMany(
        { uid: { $in: uids } },
        {
          $set: {
            'billing.plan': 'premium',
            'billing.status': 'active',
            'billing.interval': 'monthly',
            'billing.currentPeriodEnd': new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          },
        }
      );
    } else if (action === 'reset_ai') {
      await User.updateMany(
        { uid: { $in: uids } },
        { $set: { 'aiUsage.dailyCount': 0, 'aiUsage.cooldownUntil': null } }
      );
    } else if (action === 'suspend') {
      await User.updateMany({ uid: { $in: uids } }, { $set: { isSuspended: true } });
    } else if (action === 'unsuspend') {
      await User.updateMany({ uid: { $in: uids } }, { $set: { isSuspended: false } });
    } else {
      return res.status(400).json({ error: 'Invalid batch action' });
    }

    await logAdminAction(req, `BATCH_${action.toUpperCase()}`, null, { count: uids.length, uids });
    res.json({ success: true, count: uids.length });
  } catch (err) {
    console.error('Failed to run batch action:', err);
    res.status(500).json({ error: 'Failed to run batch action' });
  }
});

// System Health Diagnostics with Collection Counts
router.get('/api/admin/health/db-stats', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const focusCount = await FocusSession.countDocuments();
    const aiLogCount = await AILog.countDocuments();
    const annCount = await Announcement.countDocuments();
    const fbCount = await Feedback.countDocuments();
    const auditCount = await AdminAuditLog.countDocuments();

    res.json({
      collections: {
        users: userCount,
        focusSessions: focusCount,
        aiLogs: aiLogCount,
        announcements: annCount,
        feedback: fbCount,
        auditLogs: auditCount,
      },
    });
  } catch (err) {
    console.error('Failed db stats:', err);
    res.status(500).json({ error: 'Failed db stats' });
  }
});

module.exports = router;
