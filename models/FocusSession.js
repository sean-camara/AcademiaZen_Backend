const mongoose = require('mongoose');

const FocusSessionSchema = new mongoose.Schema({
  uid: { type: String, required: true, index: true },
  status: { type: String, enum: ['in_progress', 'completed', 'failed', 'abandoned'], default: 'in_progress' },
  targetType: { type: String, enum: ['task', 'subject', 'folderItem'], required: true },
  targetId: { type: String, required: true },
  targetLabel: { type: String, default: '' },
  targetMeta: { type: Object, default: {} },
  plannedDurationMinutes: { type: Number, default: 0 },
  actualDurationSeconds: { type: Number, default: 0 },
  startedAt: { type: Date, default: null },
  endedAt: { type: Date, default: null },
  reflectionType: { type: String, enum: ['finished', 'blocked'], default: '' },
  reflectionText: { type: String, default: '' },
}, { timestamps: true });

const FocusSession = mongoose.model('FocusSession', FocusSessionSchema);

module.exports = { FocusSession };
