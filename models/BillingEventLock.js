const mongoose = require('mongoose');

const BillingEventLockSchema = new mongoose.Schema({
  _id: { type: String, required: true },
  owner: { type: String, required: true },
  lockedUntil: { type: Date, required: true },
}, { versionKey: false, timestamps: true });

const BillingEventLock = mongoose.models.BillingEventLock
  || mongoose.model('BillingEventLock', BillingEventLockSchema);

module.exports = { BillingEventLock };
