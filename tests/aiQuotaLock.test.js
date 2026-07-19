const { AIQuotaLock } = require('../dist/models/AIQuotaLock');
const { acquireAIQuotaLock, releaseAIQuotaLock } = require('../dist/services/aiQuotaLock');

describe('AI quota lock', () => {
  afterEach(() => vi.restoreAllMocks());

  it('takes over an expired lock atomically', async () => {
    vi.spyOn(AIQuotaLock, 'findOneAndUpdate').mockResolvedValue({ _id: 'user-1' });
    const create = vi.spyOn(AIQuotaLock, 'create');

    await expect(acquireAIQuotaLock('user-1', 'request-1')).resolves.toBe(true);
    expect(create).not.toHaveBeenCalled();
  });

  it('creates the first lock for a user', async () => {
    vi.spyOn(AIQuotaLock, 'findOneAndUpdate').mockResolvedValue(null);
    vi.spyOn(AIQuotaLock, 'create').mockResolvedValue({ _id: 'user-1' });

    await expect(acquireAIQuotaLock('user-1', 'request-1')).resolves.toBe(true);
  });

  it('rejects a concurrent owner on duplicate key', async () => {
    vi.spyOn(AIQuotaLock, 'findOneAndUpdate').mockResolvedValue(null);
    vi.spyOn(AIQuotaLock, 'create').mockRejectedValue({ code: 11000 });

    await expect(acquireAIQuotaLock('user-1', 'request-2')).resolves.toBe(false);
  });

  it('does not hide storage failures', async () => {
    vi.spyOn(AIQuotaLock, 'findOneAndUpdate').mockRejectedValue(new Error('database unavailable'));

    await expect(acquireAIQuotaLock('user-1', 'request-1')).rejects.toThrow('database unavailable');
  });

  it('releases only the matching owner', async () => {
    const remove = vi.spyOn(AIQuotaLock, 'deleteOne').mockResolvedValue({ deletedCount: 1 });
    await releaseAIQuotaLock('user-1', 'request-1');
    expect(remove).toHaveBeenCalledWith({ _id: 'user-1', owner: 'request-1' });
  });
});
