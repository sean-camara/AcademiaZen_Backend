const {
  MAX_PROCESSED_PAYMENT_KEYS,
  applyPaidSubscription,
  getBillingSnapshot,
  getPaymentKey,
} = require('../services/billing');

function makeUser() {
  return {
    billing: {
      plan: 'free',
      interval: 'none',
      status: 'pending',
      pendingCheckoutId: 'checkout-1',
      pendingInterval: 'monthly',
      paymongo: { processedPaymentKeys: [] },
    },
    aiUsage: { dailyCount: 4, monthlyCount: 8 },
  };
}

describe('billing domain', () => {
  it('prefers the provider payment ID for idempotency', () => {
    expect(getPaymentKey({ paymentId: 'pay-1', eventId: 'evt-1' })).toBe('payment:pay-1');
  });

  it('applies a verified payment exactly once', () => {
    const user = makeUser();
    const now = new Date('2026-07-19T00:00:00.000Z');
    const details = { paymentId: 'pay-1', checkoutId: 'checkout-1', eventId: 'evt-1' };

    expect(applyPaidSubscription(user, 'monthly', details, now).applied).toBe(true);
    const firstEnd = user.billing.currentPeriodEnd.toISOString();
    expect(applyPaidSubscription(user, 'monthly', details, now).applied).toBe(false);
    expect(user.billing.currentPeriodEnd.toISOString()).toBe(firstEnd);
    expect(user.billing.paymongo.processedPaymentKeys).toEqual(['payment:pay-1']);
  });

  it('extends a subscription for a distinct payment', () => {
    const user = makeUser();
    const now = new Date('2026-07-19T00:00:00.000Z');
    applyPaidSubscription(user, 'weekly', { paymentId: 'pay-1' }, now);
    applyPaidSubscription(user, 'weekly', { paymentId: 'pay-2' }, now);
    expect(user.billing.currentPeriodEnd.toISOString()).toBe('2026-08-02T00:00:00.000Z');
  });

  it('bounds retained payment keys', () => {
    const user = makeUser();
    const now = new Date('2026-07-19T00:00:00.000Z');
    for (let index = 0; index < MAX_PROCESSED_PAYMENT_KEYS + 5; index += 1) {
      applyPaidSubscription(user, 'weekly', { paymentId: `pay-${index}` }, now);
    }
    expect(user.billing.paymongo.processedPaymentKeys).toHaveLength(MAX_PROCESSED_PAYMENT_KEYS);
    expect(user.billing.paymongo.processedPaymentKeys[0]).toBe('payment:pay-5');
  });

  it('does not expose an expired plan as effective premium', () => {
    const snapshot = getBillingSnapshot({
      plan: 'premium',
      status: 'active',
      currentPeriodEnd: '2026-07-18T00:00:00.000Z',
    }, new Date('2026-07-19T00:00:00.000Z'));
    expect(snapshot).toMatchObject({ status: 'expired', effectivePlan: 'free', isActive: false });
  });
});
