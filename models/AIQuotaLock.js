const mongoose = require('mongoose');

const AIQuotaLockSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  owner: { type: String, required: true },
  lockedUntil: { type: Date, required: true },
}, {
  versionKey: false,
  timestamps: true,
});

const AIQuotaLock = mongoose.models.AIQuotaLock
  || mongoose.model('AIQuotaLock', AIQuotaLockSchema);

module.exports = { AIQuotaLock };
