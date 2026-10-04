import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Build configuration only; test configuration lives in vitest.config.ts, which merges this file.
// base './' so the built bundle works from any sub-path (portfolio gallery or a Vercel root).
export default defineConfig({
  base: './',
  plugins: [react()],
  server: { port: 6110, strictPort: true },
  preview: { port: 6110, strictPort: true },
  // The modulepreload polyfill would add the only `fetch(` call to the bundle, and it is dead code here: the app
  // ships a single chunk with no dynamic imports, so index.html never carries a <link rel="modulepreload">.
  // Leaving it out keeps `scripts/verify-dist.mjs`'s "no network API in dist/" check literal.
  build: { sourcemap: false, target: 'es2022', modulePreload: { polyfill: false } },
});
