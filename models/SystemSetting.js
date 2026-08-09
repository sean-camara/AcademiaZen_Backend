const mongoose = require('mongoose');

const SystemSettingSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true, index: true },
  value: { type: mongoose.Schema.Types.Mixed, required: true },
  description: { type: String, default: '' },
  updatedBy: { type: String, default: '' },
}, { timestamps: true });

const SystemSetting = mongoose.model('SystemSetting', SystemSettingSchema);

module.exports = SystemSetting;
