const mongoose = require('mongoose');

const PushSubscriptionSchema = new mongoose.Schema({
  uid: { type: String, required: true, index: true },
  endpoint: { type: String, required: true },
  subscription: { type: Object, required: true },
}, { timestamps: true });

PushSubscriptionSchema.index({ uid: 1, endpoint: 1 }, { unique: true });

module.exports = mongoose.model('PushSubscription', PushSubscriptionSchema);
