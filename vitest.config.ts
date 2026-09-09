import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@config': resolve(__dirname, 'config'),
      '@policies': resolve(__dirname, 'policies'),
    },
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Nothing in the suite may touch the network. Detector tests are pure and
    // the gateway/harness tests use the deterministic mock provider.
    testTimeout: 20_000,
  },
});
