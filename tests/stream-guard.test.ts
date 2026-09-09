import { describe, expect, it } from 'vitest';
import { createStreamGuard, runStreamGuard, scanPerChunk } from '@/lib/stream-guard';
import { secretScannerDetector, canaryLeakDetector, makeCanary } from '@/lib/guard/detectors';
import { ctx } from './helpers';

const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

/** A secret deliberately split so it exists only across the seam. */
const SPLIT_CHUNKS = [
  'Sure, here is what you asked for. The access key is AKIAIOSF',
  'ODNN7EXAMPLE and you should keep it somewhere safe.',
];

const secretPattern = /\bAKIA[0-9A-Z]{16}\b/;

describe('the sliding window catches what a per-chunk scan misses', () => {
  it('a per-chunk scan does NOT see the split secret', () => {
    expect(SPLIT_CHUNKS.join('')).toContain(AWS_KEY); // it is genuinely there
    expect(scanPerChunk(SPLIT_CHUNKS, secretPattern)).toBe(false);
  });

  it('the sliding-window guard DOES see it, and withholds it', async () => {
    const { output, handle } = await runStreamGuard(SPLIT_CHUNKS, {
      windowChars: 240,
      scan: (acc) => ({
        triggered: secretPattern.test(acc),
        replacement: '[BLOCKED: credential detected in output]',
        reason: 'secret in output',
      }),
    });

    expect(handle.triggered()).toBe(true);
    expect(output).not.toContain(AWS_KEY);
    expect(output).toContain('[BLOCKED');
  });

  it('uses the real secret-scanner detector, not just a regex', async () => {
    const { output, handle } = await runStreamGuard(SPLIT_CHUNKS, {
      windowChars: 240,
      scan: async (acc) => {
        const r = await secretScannerDetector.run(ctx(acc, { stage: 'output' }));
        return { triggered: r.triggered, replacement: '[BLOCKED]', reason: r.explanation };
      },
    });
    expect(handle.triggered()).toBe(true);
    expect(output).not.toContain(AWS_KEY);
  });

  it('a window of zero fails to protect the seam — the window is what matters', async () => {
    // With no window, the first chunk is released before the second arrives,
    // so the leading half of the secret is already on the wire.
    const { output } = await runStreamGuard(SPLIT_CHUNKS, {
      windowChars: 0,
      scan: (acc) => ({ triggered: secretPattern.test(acc), replacement: '[BLOCKED]' }),
    });
    expect(output).toContain('AKIAIOSF'); // leaked prefix
  });

  it('catches a canary split across three chunks', async () => {
    const canary = makeCanary();
    const mid = Math.floor(canary.length / 2);
    const chunks = ['Here are my instructions: ', canary.slice(0, mid), canary.slice(mid), ' — that is all.'];

    const { output, handle } = await runStreamGuard(chunks, {
      windowChars: 240,
      scan: async (acc) => {
        const r = await canaryLeakDetector.run(ctx(acc, { stage: 'output', canary }));
        return { triggered: r.triggered, replacement: '[BLOCKED: system prompt leak]' };
      },
    });
    expect(handle.triggered()).toBe(true);
    expect(output).not.toContain(canary);
  });
});

describe('sliding window — normal operation', () => {
  it('passes clean text through unchanged', async () => {
    const chunks = ['The capital ', 'of Denmark ', 'is Copenhagen.'];
    const { output, handle } = await runStreamGuard(chunks, {
      windowChars: 24,
      scan: () => ({ triggered: false }),
    });
    expect(output).toBe(chunks.join(''));
    expect(handle.triggered()).toBe(false);
  });

  it('withholds exactly windowChars until flush', async () => {
    const handle = createStreamGuard({ windowChars: 10, scan: () => ({ triggered: false }) });
    const writer = handle.transform.writable.getWriter();
    const reader = handle.transform.readable.getReader();

    // Read concurrently — a TransformStream applies backpressure, so writing
    // without a reader attached would deadlock.
    const chunks: string[] = [];
    const pump = (async () => {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) chunks.push(value);
      }
    })();

    await writer.write('0123456789ABCDEFGHIJ'); // 20 chars in, 10 withheld
    expect(handle.released()).toBe('0123456789');

    await writer.close();
    await pump;

    expect(chunks.join('')).toBe('0123456789ABCDEFGHIJ');
    expect(handle.accumulated()).toBe('0123456789ABCDEFGHIJ');
  });

  it('aborts upstream when it trips', async () => {
    let aborted = false;
    await runStreamGuard(SPLIT_CHUNKS, {
      windowChars: 240,
      abortUpstream: () => {
        aborted = true;
      },
      scan: (acc) => ({ triggered: secretPattern.test(acc), replacement: '[BLOCKED]' }),
    });
    expect(aborted).toBe(true);
  });

  it('scans the tail at flush, so a leak in the final characters is still caught', async () => {
    const { output, handle } = await runStreamGuard(['all good so far ', `key ${AWS_KEY}`], {
      windowChars: 4096, // nothing is ever released before flush
      scan: (acc) => ({ triggered: secretPattern.test(acc), replacement: '[BLOCKED]' }),
    });
    expect(handle.triggered()).toBe(true);
    expect(output).not.toContain(AWS_KEY);
  });
});

describe('window size versus time-to-first-token', () => {
  /**
   * The trade-off ARCHITECTURE.md documents, asserted rather than merely
   * described: a larger window means more characters must arrive before the
   * first byte is released, so time-to-first-token is strictly worse.
   */
  const chunksFor = () => Array.from({ length: 40 }, (_, i) => `chunk${String(i).padStart(3, '0')} `);

  async function chunksUntilFirstRelease(windowChars: number): Promise<number> {
    const handle = createStreamGuard({ windowChars, scan: () => ({ triggered: false }) });
    const writer = handle.transform.writable.getWriter();
    const reader = handle.transform.readable.getReader();
    const pump = (async () => {
      for (;;) {
        const { done } = await reader.read();
        if (done) break;
      }
    })();

    let n = 0;
    for (const c of chunksFor()) {
      n++;
      await writer.write(c);
      if (handle.released().length > 0) break;
    }
    await writer.close();
    await pump;
    return n;
  }

  it('a larger window delays the first release', async () => {
    const small = await chunksUntilFirstRelease(10);
    const large = await chunksUntilFirstRelease(200);
    expect(large).toBeGreaterThan(small);
  });
});
