const { AIQuotaLock } = require('../models/AIQuotaLock');

const LOCK_TTL_MS = 15_000;

async function acquireAIQuotaLock(uid, owner, now = new Date()) {
  const lockedUntil = new Date(now.getTime() + LOCK_TTL_MS);
  const existing = await AIQuotaLock.findOneAndUpdate(
    { _id: uid, lockedUntil: { $lte: now } },
    { $set: { owner, lockedUntil } },
    { new: true }
  );
  if (existing) return true;

  try {
    await AIQuotaLock.create({ _id: uid, owner, lockedUntil });
    return true;
  } catch (error) {
    if (error && error.code === 11000) return false;
    throw error;
  }
}

async function releaseAIQuotaLock(uid, owner) {
  await AIQuotaLock.deleteOne({ _id: uid, owner });
}

module.exports = {
  LOCK_TTL_MS,
  acquireAIQuotaLock,
  releaseAIQuotaLock,
};
