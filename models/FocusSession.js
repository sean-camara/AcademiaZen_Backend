const mongoose = require('mongoose');

const FocusSessionSchema = new mongoose.Schema({
  uid: { type: String, required: true, index: true },
  status: { type: String, enum: ['in_progress', 'completed', 'partial', 'not_finished', 'abandoned'], default: 'in_progress' },
  targetType: { type: String, enum: ['task', 'subject', 'folderItem'], required: true },
  targetId: { type: String, required: true },
  targetLabel: { type: String, default: '' },
  targetMeta: { type: Object, default: {} },
  plannedDurationMinutes: { type: Number, default: 0 },
  actualDurationSeconds: { type: Number, default: 0 },
  startedAt: { type: Date, default: null },
  endedAt: { type: Date, default: null },
  // New completion status field
  completionStatus: { type: String, enum: ['completed', 'partial', 'not_finished', null], default: null },
  // Quick blocker chips (array of predefined blockers)
  blockerChips: { type: [String], default: [] },
  // Optional reflection text (no longer required)
  reflectionText: { type: String, default: '' },
  // Legacy field kept for backward compatibility
  reflectionType: { type: String, enum: ['finished', 'blocked', null], default: null },
  // Pomodoro cycle tracking
  pomodoroMode: { type: String, enum: ['classic', 'long', 'custom', null], default: null },
  cycleNumber: { type: Number, default: 1 },
  isBreak: { type: Boolean, default: false },
}, { timestamps: true });

// Index for analytics queries
FocusSessionSchema.index({ uid: 1, endedAt: -1 });
FocusSessionSchema.index({ uid: 1, startedAt: -1 });

const FocusSession = mongoose.model('FocusSession', FocusSessionSchema);

module.exports = { FocusSession };
