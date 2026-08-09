const mongoose = require('mongoose');

const AdminAuditLogSchema = new mongoose.Schema({
  adminUid: { type: String, required: true, index: true },
  adminEmail: { type: String, required: true },
  action: { type: String, required: true, index: true },
  targetUid: { type: String, default: null },
  details: { type: mongoose.Schema.Types.Mixed, default: {} },
  ipAddress: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now, index: true },
});

const AdminAuditLog = mongoose.models.AdminAuditLog || mongoose.model('AdminAuditLog', AdminAuditLogSchema);

module.exports = { AdminAuditLog };
