import crypto from 'node:crypto';

interface SignatureInput {
  rawBody: Buffer | string;
  header: string;
  secret: string;
  livemode: boolean;
  nowSeconds?: number;
  toleranceSeconds?: number;
}

function verifyPaymongoWebhookSignature({
  rawBody,
  header,
  secret,
  livemode,
  nowSeconds = Math.floor(Date.now() / 1000),
  toleranceSeconds = 300,
}: SignatureInput): boolean {
  if (!rawBody || !header || !secret || !Number.isFinite(toleranceSeconds) || toleranceSeconds < 0) return false;
  const parts = new Map<string, string>();
  for (const segment of header.split(',')) {
    const separator = segment.indexOf('=');
    if (separator <= 0) continue;
    parts.set(segment.slice(0, separator).trim(), segment.slice(separator + 1).trim());
  }

  const timestamp = Number(parts.get('t'));
  const signature = parts.get(livemode ? 'li' : 'te');
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0 || !signature || !/^[0-9a-f]{64}$/i.test(signature)) {
    return false;
  }
  if (Math.abs(nowSeconds - timestamp) > toleranceSeconds) return false;

  const body = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
  const expected = crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
  const providedBuffer = Buffer.from(signature, 'hex');
  const expectedBuffer = Buffer.from(expected, 'hex');
  return providedBuffer.length === expectedBuffer.length
    && crypto.timingSafeEqual(providedBuffer, expectedBuffer);
}

export { verifyPaymongoWebhookSignature };
