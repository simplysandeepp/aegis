import type { NextConfig } from 'next';

/**
 * `/v1/chat/completions` and `/v1/guard` are the public, OpenAI-compatible
 * paths documented in the README and used by the harness and every curl
 * example. The Next.js App Router only lets route handlers live under
 * `src/app/api/**`, so this rewrite maps the public path onto the internal
 * one without changing what callers point their base URL at.
 */
const nextConfig: NextConfig = {
  async rewrites() {
    return [
      { source: '/v1/:path*', destination: '/api/v1/:path*' },
    ];
  },
};

export default nextConfig;
