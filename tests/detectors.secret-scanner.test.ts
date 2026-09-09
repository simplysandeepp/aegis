import { describe, expect, it } from 'vitest';
import { secretScannerDetector as det } from '@/lib/guard/detectors';
import { run } from './helpers';

describe('secret-scanner — true positives', () => {
  const positives: Array<[string, string, string]> = [
    ['AWS access key', 'deploy with AKIAIOSFODNN7EXAMPLE please', 'secret:aws-access-key'],
    ['GitHub classic PAT', 'token ghp_1234567890abcdefghijklmnopqrstuvwxyzAB', 'secret:github-pat'],
    ['Google API key', 'key=AIzaSyA1234567890abcdefghijklmnopqrstuv', 'secret:google-api-key'],
    ['Slack bot token', 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx', 'secret:slack-token'],
    ['PEM private key', '-----BEGIN RSA PRIVATE KEY-----\nMIIE...', 'secret:private-key-block'],
    ['Stripe live key', 'sk_live_abcdefghijklmnopqrstuvwx', 'secret:stripe-key'],
  ];

  for (const [name, text, label] of positives) {
    it(`flags a ${name}`, async () => {
      const r = await run(det, text);
      expect(r.triggered).toBe(true);
      expect(r.labels).toContain(label);
      expect(r.severity).toBe('critical');
      expect(r.spans.length).toBeGreaterThan(0);
    });
  }

  it('flags a structurally valid JWT', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '1234567890', name: 'Ada' })).toString('base64url');
    const jwt = `${header}.${payload}.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk`;
    const r = await run(det, `Authorization: Bearer ${jwt}`);
    expect(r.triggered).toBe(true);
    expect(r.labels).toContain('secret:jwt');
  });

  it('flags a Luhn-valid card number', async () => {
    const r = await run(det, 'card 4111 1111 1111 1111 expires soon');
    expect(r.triggered).toBe(true);
    expect(r.labels).toContain('secret:card-number');
  });

  it('flags an unknown-format high-entropy token', async () => {
    const r = await run(det, 'session=Xq7Fv2Lm9Pw4Zc1Nk8Rt6Ys3Bd5Hj0Gu');
    expect(r.triggered).toBe(true);
    expect(r.labels).toContain('secret:high-entropy-token');
  });

  it('emits spans that isolate the secret itself', async () => {
    const text = 'the key is AKIAIOSFODNN7EXAMPLE ok';
    const r = await run(det, text);
    const span = r.spans[0]!;
    expect(text.slice(span.start, span.end)).toBe('AKIAIOSFODNN7EXAMPLE');
  });
});

describe('secret-scanner — true negatives', () => {
  const negatives: Array<[string, string]> = [
    ['prose about credentials', 'You should never paste your API key into a chat window.'],
    ['env var reference', 'api_key = process.env.OPENAI_API_KEY'],
    ['documented placeholder', 'Set api_key: "your-api-key-here" in the config file.'],
    ['templated value', 'apiKey: "{{ SECRET_API_KEY }}"'],
    ['angle-bracket placeholder', 'export API_KEY=<your-key>'],
    ['a plain sentence', 'The quick brown fox jumps over the lazy dog repeatedly.'],
    ['a non-Luhn digit run', 'order number 1234567890123456 shipped'],
    ['a lowercase hash-like word', 'abcdefghijklmnopqrstuvwxyzabcdef'],
  ];

  for (const [name, text] of negatives) {
    it(`does not flag ${name}`, async () => {
      const r = await run(det, text);
      expect(r.triggered, `unexpectedly flagged: ${r.explanation}`).toBe(false);
    });
  }
});
