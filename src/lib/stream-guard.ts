/**
 * Streaming output guard with a sliding buffer.
 *
 * THE PROBLEM. Output detectors are the last line of defence, but in a
 * streaming response the text arrives in chunks whose boundaries are chosen by
 * the tokenizer, not by us. A naive per-chunk scan sees
 *
 *     chunk 1: "...your key is AKIAIOSFOD"
 *     chunk 2: "NN7EXAMPLE, keep it safe"
 *
 * and matches nothing, because the credential exists only across the seam. The
 * same is true of a canary token, an exfiltration URL, or any multi-token
 * secret. By the time the full text is assembled, the leaked bytes are already
 * on the wire and in the client's DOM.
 *
 * THE FIX. Never emit the most recent `windowChars` characters. Text is held
 * back until enough further output has arrived to push it out of the window,
 * and every scan runs over the whole accumulated text, so a pattern spanning
 * any number of chunk boundaries is seen intact *before* its first byte is
 * released. On a trigger we stop pulling from the provider, discard the
 * unreleased tail — which is where the offending text still is — emit the
 * replacement, and close cleanly.
 *
 * THE TRADE-OFF. Time-to-first-token grows by however long it takes the model
 * to produce `windowChars` characters, and a leak longer than the window can
 * still straddle the release boundary. Bigger window, better coverage, worse
 * TTFT. `policy.streamWindowChars` makes it a measured parameter rather than a
 * guess: the harness reports added TTFT per window size. See ARCHITECTURE.md.
 */

export interface StreamScanVerdict {
  triggered: boolean;
  /** What to emit in place of the withheld tail. */
  replacement?: string;
  reason?: string;
}

export type StreamScanner = (accumulated: string) => StreamScanVerdict | Promise<StreamScanVerdict>;

export interface StreamGuardOptions {
  /** Characters withheld from the client at all times. */
  windowChars: number;
  /** Runs over the full accumulated text after each chunk. */
  scan: StreamScanner;
  /** Called once when the scanner trips. */
  onTrigger?: (info: { reason: string; accumulated: string; releasedChars: number }) => void;
  /** Called when the stream ends without a trigger. */
  onComplete?: (info: { accumulated: string }) => void;
  /** Invoked on trigger so the caller can abort the upstream provider call. */
  abortUpstream?: () => void;
}

export interface StreamGuardHandle {
  transform: TransformStream<string, string>;
  /** Everything the model produced, including any withheld tail. */
  accumulated(): string;
  /** Everything actually emitted downstream. */
  released(): string;
  triggered(): boolean;
  reason(): string | undefined;
}

/**
 * Build the guarding `TransformStream`.
 *
 * Invariant: at any moment, `released.length <= accumulated.length - windowChars`
 * until the stream flushes, at which point the remaining tail is scanned once
 * more and released only if clean.
 */
export function createStreamGuard(opts: StreamGuardOptions): StreamGuardHandle {
  const windowChars = Math.max(0, opts.windowChars);
  let accumulated = '';
  let released = '';
  let triggered = false;
  let reason: string | undefined;

  const transform = new TransformStream<string, string>({
    async transform(chunk, controller) {
      if (triggered) return; // swallow anything still in flight
      accumulated += chunk;

      // Scan the WHOLE accumulated text, not just this chunk. This is what
      // catches a pattern that spans chunk boundaries.
      const verdict = await opts.scan(accumulated);
      if (verdict.triggered) {
        triggered = true;
        reason = verdict.reason ?? 'output guard triggered';
        opts.abortUpstream?.();
        opts.onTrigger?.({ reason, accumulated, releasedChars: released.length });
        // The offending text is in the unreleased tail; dropping it is the
        // whole point of holding the window back. Never flush it.
        const replacement = verdict.replacement ?? '';
        if (replacement) controller.enqueue(replacement);
        controller.terminate();
        return;
      }

      // Release only what has fallen out of the window.
      const safeUpTo = accumulated.length - windowChars;
      if (safeUpTo > released.length) {
        const out = accumulated.slice(released.length, safeUpTo);
        released += out;
        if (out) controller.enqueue(out);
      }
    },

    async flush(controller) {
      if (triggered) return;
      // The model is done, so the tail can never grow further. Scan it once
      // more and release it only if it is clean.
      const verdict = await opts.scan(accumulated);
      if (verdict.triggered) {
        triggered = true;
        reason = verdict.reason ?? 'output guard triggered at flush';
        opts.onTrigger?.({ reason, accumulated, releasedChars: released.length });
        const replacement = verdict.replacement ?? '';
        if (replacement) controller.enqueue(replacement);
        return;
      }
      const rest = accumulated.slice(released.length);
      if (rest) {
        released += rest;
        controller.enqueue(rest);
      }
      opts.onComplete?.({ accumulated });
    },
  });

  return {
    transform,
    accumulated: () => accumulated,
    released: () => released,
    triggered: () => triggered,
    reason: () => reason,
  };
}

/**
 * Reference implementation of the naive approach, kept so the test suite can
 * demonstrate what the sliding window buys. It scans each chunk in isolation
 * and therefore misses anything that spans a boundary.
 */
export function scanPerChunk(chunks: readonly string[], pattern: RegExp): boolean {
  return chunks.some((c) => new RegExp(pattern.source, pattern.flags.replace('g', '')).test(c));
}

/** Convenience: run a string iterable through a guard and collect the output. */
export async function runStreamGuard(
  chunks: AsyncIterable<string> | Iterable<string>,
  opts: StreamGuardOptions,
): Promise<{ output: string; handle: StreamGuardHandle }> {
  const handle = createStreamGuard(opts);
  const source = new ReadableStream<string>({
    async start(controller) {
      for await (const c of chunks as AsyncIterable<string>) controller.enqueue(c);
      controller.close();
    },
  });

  const reader = source.pipeThrough(handle.transform).getReader();
  let output = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    output += value;
  }
  return { output, handle };
}
