function hasValidRevision(value) {
  return Number.isInteger(value) && value >= 0;
}

function buildStateRevisionFilter(uid, baseRevision) {
  if (!hasValidRevision(baseRevision)) return { uid };
  if (baseRevision === 0) {
    return {
      uid,
      $or: [{ stateRevision: 0 }, { stateRevision: { $exists: false } }],
    };
  }
  return { uid, stateRevision: baseRevision };
}

module.exports = { buildStateRevisionFilter, hasValidRevision };
