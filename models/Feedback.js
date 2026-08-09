const mongoose = require('mongoose');

const FeedbackSchema = new mongoose.Schema({
  uid: { type: String, required: true, index: true },
  email: { type: String, default: '' },
  category: { type: String, enum: ['bug', 'feature', 'general', 'billing'], default: 'general' },
  message: { type: String, required: true },
  status: { type: String, enum: ['open', 'in_review', 'resolved', 'closed'], default: 'open' },
  reply: { type: String, default: '' },
  repliedAt: { type: Date, default: null },
  repliedBy: { type: String, default: '' },
}, { timestamps: true });

const Feedback = mongoose.model('Feedback', FeedbackSchema);

module.exports = Feedback;
