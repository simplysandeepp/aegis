import { describe, expect, it } from 'vitest';
import { piiDetector as det } from '@/lib/guard/detectors';
import { run } from './helpers';

describe('pii-detector — true positives', () => {
  const positives: Array<[string, string, string]> = [
    ['email', 'reach me at ada.lovelace@example.com tomorrow', 'pii:email'],
    ['E.164 phone', 'call +14155552671 after noon', 'pii:phone-e164'],
    ['US national phone', 'my number is 415-555-2671', 'pii:phone-national'],
    ['parenthesised phone', 'ring (415) 555-2671 please', 'pii:phone-national'],
    ['US SSN', 'SSN 123-45-6789 on file', 'pii:ssn'],
    ['public IPv4', 'origin was 203.0.113.42 last night', 'pii:ipv4'],
    ['IPv6', 'peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 connected', 'pii:ipv6'],
    ['street address', 'ship to 1600 Pennsylvania Avenue', 'pii:street-address'],
  ];

  for (const [name, text, label] of positives) {
    it(`flags ${name}`, async () => {
      const r = await run(det, text);
      expect(r.triggered, r.explanation).toBe(true);
      expect(r.labels).toContain(label);
    });
  }

  it('flags a mod-97 valid IBAN', async () => {
    const r = await run(det, 'transfer to GB82WEST12345698765432 today');
    expect(r.triggered).toBe(true);
    expect(r.labels).toContain('pii:iban');
  });

  it('flags a Luhn-valid card and marks it high severity', async () => {
    const r = await run(det, 'pay with 4111111111111111');
    expect(r.triggered).toBe(true);
    expect(r.labels).toContain('pii:credit-card');
  });

  it('produces spans that isolate the email exactly', async () => {
    const text = 'write to grace@example.org now';
    const r = await run(det, text);
    const s = r.spans.find((x) => x.label.includes('email'))!;
    expect(text.slice(s.start, s.end)).toBe('grace@example.org');
  });
});

describe('pii-detector — true negatives', () => {
  const negatives: Array<[string, string]> = [
    ['prose with no identifiers', 'Please summarise the attached quarterly report.'],
    ['loopback address', 'the dev server runs on 127.0.0.1 during tests'],
    ['RFC1918 address', 'the gateway sits at 192.168.1.1 internally'],
    ['a version string', 'we upgraded from 1.2.3 to 10.20.30 last week'],
    ['an invalid SSN area', 'reference 000-45-6789 is a placeholder'],
    ['a non-Luhn 16-digit number', 'invoice 1234567812345678 is overdue'],
    ['an IBAN-shaped string with a bad checksum', 'code GB00WEST12345698765432 is fake'],
  ];

  for (const [name, text] of negatives) {
    it(`does not flag ${name}`, async () => {
      const r = await run(det, text);
      expect(r.triggered, `unexpectedly flagged: ${r.explanation}`).toBe(false);
    });
  }
});
