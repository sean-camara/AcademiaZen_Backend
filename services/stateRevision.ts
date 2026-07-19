type StateRevisionFilter =
  | { uid: string }
  | { uid: string; stateRevision: number }
  | { uid: string; $or: Array<{ stateRevision: number } | { stateRevision: { $exists: false } }> };

function hasValidRevision(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0;
}

function buildStateRevisionFilter(uid: string, baseRevision: unknown): StateRevisionFilter {
  if (!hasValidRevision(baseRevision)) return { uid };
  if (baseRevision === 0) {
    return { uid, $or: [{ stateRevision: 0 }, { stateRevision: { $exists: false } }] };
  }
  return { uid, stateRevision: baseRevision };
}

export { buildStateRevisionFilter, hasValidRevision };
