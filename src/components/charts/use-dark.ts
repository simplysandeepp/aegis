'use client';

import { useSyncExternalStore } from 'react';

/**
 * Tracks the effective colour scheme so chart steps can be *selected* for the
 * dark surface rather than flipped automatically.
 *
 * Uses useSyncExternalStore rather than an effect: the theme lives outside
 * React (an attribute on <html> plus an OS media query), and subscribing to it
 * directly avoids a setState-in-effect render pass on every mount.
 */
function compute(): boolean {
  if (typeof document === 'undefined') return false;
  const stamped = document.documentElement.getAttribute('data-theme');
  if (stamped === 'dark') return true;
  if (stamped === 'light') return false;
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function subscribe(onChange: () => void): () => void {
  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  mq.addEventListener('change', onChange);
  const obs = new MutationObserver(onChange);
  obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'class'] });
  return () => {
    mq.removeEventListener('change', onChange);
    obs.disconnect();
  };
}

export function useDark(): boolean {
  // The third argument is the server snapshot. React uses it during hydration
  // and swaps to the client snapshot immediately afterwards, so there is no
  // mismatch and no setState-in-effect round trip.
  return useSyncExternalStore(subscribe, compute, () => false);
}
