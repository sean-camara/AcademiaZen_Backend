const mongoose = require('mongoose');

const AnnouncementSchema = new mongoose.Schema({
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'warning', 'success', 'banner'], default: 'info' },
  isActive: { type: Boolean, default: true },
  createdBy: { type: String, default: '' },
}, { timestamps: true });

const Announcement = mongoose.model('Announcement', AnnouncementSchema);

module.exports = Announcement;
