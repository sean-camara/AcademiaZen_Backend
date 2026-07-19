const MAX_PROCESSED_PAYMENT_KEYS = 50;

function addInterval(date, interval) {
  const next = new Date(date);
  if (interval === 'weekly') next.setDate(next.getDate() + 7);
  else if (interval === 'yearly') next.setFullYear(next.getFullYear() + 1);
  else next.setMonth(next.getMonth() + 1);
  return next;
}

function isBillingActive(billing, now = new Date()) {
  if (!billing?.currentPeriodEnd) return false;
  const end = new Date(billing.currentPeriodEnd);
  return ['active', 'canceled'].includes(billing?.status) && end.getTime() > now.getTime();
}

function getBillingSnapshot(billing, now = new Date()) {
  const active = isBillingActive(billing, now);
  const plan = billing?.plan || 'free';
  let status = billing?.status || 'free';
  if (['active', 'canceled'].includes(status) && !active) status = 'expired';
  if (status === 'pending' && !billing?.pendingCheckoutId) status = 'free';
  return {
    plan,
    interval: billing?.interval || 'none',
    status,
    currentPeriodEnd: billing?.currentPeriodEnd ? new Date(billing.currentPeriodEnd).toISOString() : null,
    autoRenew: plan === 'premium' ? (billing?.autoRenew ?? true) : false,
    isActive: active,
    effectivePlan: active ? plan : 'free',
    pendingCheckoutId: billing?.pendingCheckoutId || '',
  };
}

function getPaymentKey({ paymentId, eventId, checkoutId, eventType } = {}) {
  if (paymentId) return `payment:${paymentId}`;
  if (eventId) return `event:${eventId}`;
  if (checkoutId && eventType) return `checkout:${checkoutId}:${eventType}`;
  return '';
}

function applyPaidSubscription(user, interval, details = {}, now = new Date()) {
  if (!user.billing) user.billing = {};
  if (!user.billing.paymongo) user.billing.paymongo = {};
  const paymentKey = details.paymentKey || getPaymentKey(details);
  const processed = user.billing.paymongo.processedPaymentKeys || [];

  if (paymentKey && processed.includes(paymentKey)) {
    return { applied: false, paymentKey };
  }

  const currentEnd = user.billing.currentPeriodEnd ? new Date(user.billing.currentPeriodEnd) : null;
  const base = currentEnd && currentEnd > now ? currentEnd : now;
  user.billing.plan = 'premium';
  user.billing.interval = interval;
  user.billing.status = 'active';
  user.billing.currentPeriodEnd = addInterval(base, interval);
  user.billing.lastPaymentAt = now;
  user.billing.pendingCheckoutId = '';
  user.billing.pendingPlan = '';
  user.billing.pendingInterval = '';

  if (details.checkoutId) user.billing.paymongo.checkoutId = details.checkoutId;
  if (details.paymentId) user.billing.paymongo.paymentId = details.paymentId;
  if (details.paymentIntentId) user.billing.paymongo.paymentIntentId = details.paymentIntentId;
  if (details.sourceId) user.billing.paymongo.sourceId = details.sourceId;
  if (details.eventId) user.billing.paymongo.lastEventId = details.eventId;
  if (details.eventType) user.billing.paymongo.lastEventType = details.eventType;
  if (paymentKey) {
    user.billing.paymongo.processedPaymentKeys = [...processed, paymentKey]
      .slice(-MAX_PROCESSED_PAYMENT_KEYS);
  }

  if (!user.aiUsage) user.aiUsage = {};
  user.aiUsage.dailyCount = 0;
  user.aiUsage.monthlyCount = 0;
  user.aiUsage.deepDailyCount = 0;
  user.aiUsage.deepMonthlyCount = 0;
  return { applied: true, paymentKey };
}

module.exports = {
  MAX_PROCESSED_PAYMENT_KEYS,
  addInterval,
  isBillingActive,
  getBillingSnapshot,
  getPaymentKey,
  applyPaidSubscription,
};
