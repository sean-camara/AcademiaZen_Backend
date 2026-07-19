import { AIQuotaLock } from '../models/AIQuotaLock.js';

const LOCK_TTL_MS = 15_000;

function isDuplicateKeyError(error: unknown): error is { code: number } {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 11000;
}

async function acquireAIQuotaLock(uid: string, owner: string, now = new Date()): Promise<boolean> {
  const lockedUntil = new Date(now.getTime() + LOCK_TTL_MS);
  const existing = await AIQuotaLock.findOneAndUpdate(
    { _id: uid, lockedUntil: { $lte: now } },
    { $set: { owner, lockedUntil } },
    { new: true },
  );
  if (existing) return true;

  try {
    await AIQuotaLock.create({ _id: uid, owner, lockedUntil });
    return true;
  } catch (error: unknown) {
    if (isDuplicateKeyError(error)) return false;
    throw error;
  }
}

async function releaseAIQuotaLock(uid: string, owner: string): Promise<void> {
  await AIQuotaLock.deleteOne({ _id: uid, owner });
}

export { LOCK_TTL_MS, acquireAIQuotaLock, releaseAIQuotaLock };
