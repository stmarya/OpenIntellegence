import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Typed routes for improved type safety
  experimental: {
    typedRoutes: false,
  },
};

export default nextConfig;
