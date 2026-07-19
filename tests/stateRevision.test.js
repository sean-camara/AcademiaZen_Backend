const { buildStateRevisionFilter, hasValidRevision } = require('../dist/services/stateRevision');

describe('state revision filters', () => {
  it('keeps old clients compatible when no revision is supplied', () => {
    expect(hasValidRevision(undefined)).toBe(false);
    expect(buildStateRevisionFilter('user-1', undefined)).toEqual({ uid: 'user-1' });
  });

  it('matches legacy documents without a revision at revision zero', () => {
    expect(buildStateRevisionFilter('user-1', 0)).toEqual({
      uid: 'user-1',
      $or: [{ stateRevision: 0 }, { stateRevision: { $exists: false } }],
    });
  });

  it('requires an exact positive revision', () => {
    expect(buildStateRevisionFilter('user-1', 4)).toEqual({
      uid: 'user-1',
      stateRevision: 4,
    });
  });

  it('rejects negative and fractional revisions', () => {
    expect(hasValidRevision(-1)).toBe(false);
    expect(hasValidRevision(1.5)).toBe(false);
  });
});
