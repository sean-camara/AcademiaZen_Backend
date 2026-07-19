import { BillingEventLock } from '../models/BillingEventLock.js';

const BILLING_LOCK_TTL_MS = 30_000;

function isDuplicateKeyError(error: unknown): error is { code: number } {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 11000;
}

async function acquireBillingEventLock(key: string, owner: string, now = new Date()): Promise<boolean> {
  const lockedUntil = new Date(now.getTime() + BILLING_LOCK_TTL_MS);
  const existing = await BillingEventLock.findOneAndUpdate(
    { _id: key, lockedUntil: { $lte: now } },
    { $set: { owner, lockedUntil } },
    { new: true },
  );
  if (existing) return true;
  try {
    await BillingEventLock.create({ _id: key, owner, lockedUntil });
    return true;
  } catch (error: unknown) {
    if (isDuplicateKeyError(error)) return false;
    throw error;
  }
}

async function releaseBillingEventLock(key: string, owner: string): Promise<void> {
  await BillingEventLock.deleteOne({ _id: key, owner });
}

export { BILLING_LOCK_TTL_MS, acquireBillingEventLock, releaseBillingEventLock };
