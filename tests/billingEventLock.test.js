const { BillingEventLock } = require('../models/BillingEventLock');
const { acquireBillingEventLock, releaseBillingEventLock } = require('../services/billingEventLock');

describe('billing event lock', () => {
  afterEach(() => vi.restoreAllMocks());

  it('creates the first lock', async () => {
    vi.spyOn(BillingEventLock, 'findOneAndUpdate').mockResolvedValue(null);
    vi.spyOn(BillingEventLock, 'create').mockResolvedValue({ _id: 'payment:1' });
    await expect(acquireBillingEventLock('payment:1', 'request:1')).resolves.toBe(true);
  });

  it('rejects a concurrent duplicate', async () => {
    vi.spyOn(BillingEventLock, 'findOneAndUpdate').mockResolvedValue(null);
    vi.spyOn(BillingEventLock, 'create').mockRejectedValue({ code: 11000 });
    await expect(acquireBillingEventLock('payment:1', 'request:2')).resolves.toBe(false);
  });

  it('releases only the owner', async () => {
    const remove = vi.spyOn(BillingEventLock, 'deleteOne').mockResolvedValue({ deletedCount: 1 });
    await releaseBillingEventLock('payment:1', 'request:1');
    expect(remove).toHaveBeenCalledWith({ _id: 'payment:1', owner: 'request:1' });
  });
});
