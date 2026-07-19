const { BillingEventLock } = require('../models/BillingEventLock');

const BILLING_LOCK_TTL_MS = 30_000;

async function acquireBillingEventLock(key, owner, now = new Date()) {
  const lockedUntil = new Date(now.getTime() + BILLING_LOCK_TTL_MS);
  const existing = await BillingEventLock.findOneAndUpdate(
    { _id: key, lockedUntil: { $lte: now } },
    { $set: { owner, lockedUntil } },
    { new: true }
  );
  if (existing) return true;
  try {
    await BillingEventLock.create({ _id: key, owner, lockedUntil });
    return true;
  } catch (error) {
    if (error?.code === 11000) return false;
    throw error;
  }
}

async function releaseBillingEventLock(key, owner) {
  await BillingEventLock.deleteOne({ _id: key, owner });
}

module.exports = { BILLING_LOCK_TTL_MS, acquireBillingEventLock, releaseBillingEventLock };
