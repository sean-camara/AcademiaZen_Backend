const crypto = require('node:crypto');
const { verifyPaymongoWebhookSignature } = require('../dist/services/paymongoSignature');

describe('PayMongo webhook signatures', () => {
  const secret = 'whsk_test_secret';
  const timestamp = 1_721_347_200;
  const rawBody = '{"data":{"attributes":{"livemode":false}}}';
  const digest = crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');

  it('accepts the documented test-mode signature', () => {
    expect(verifyPaymongoWebhookSignature({
      rawBody,
      header: `t=${timestamp},te=${digest},li=`,
      secret,
      livemode: false,
      nowSeconds: timestamp + 60,
    })).toBe(true);
  });

  it('uses the live signature only for live events', () => {
    expect(verifyPaymongoWebhookSignature({
      rawBody,
      header: `t=${timestamp},te=,li=${digest}`,
      secret,
      livemode: true,
      nowSeconds: timestamp,
    })).toBe(true);
    expect(verifyPaymongoWebhookSignature({
      rawBody,
      header: `t=${timestamp},te=,li=${digest}`,
      secret,
      livemode: false,
      nowSeconds: timestamp,
    })).toBe(false);
  });

  it('rejects stale, malformed, and tampered deliveries', () => {
    const base = { rawBody, secret, livemode: false, nowSeconds: timestamp + 301 };
    expect(verifyPaymongoWebhookSignature({ ...base, header: `t=${timestamp},te=${digest},li=` })).toBe(false);
    expect(verifyPaymongoWebhookSignature({ ...base, nowSeconds: timestamp, header: 'not-a-signature' })).toBe(false);
    expect(verifyPaymongoWebhookSignature({
      ...base,
      nowSeconds: timestamp,
      rawBody: `${rawBody} `,
      header: `t=${timestamp},te=${digest},li=`,
    })).toBe(false);
  });
});
