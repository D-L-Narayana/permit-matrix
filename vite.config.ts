/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// base './' so the built bundle works from any sub-path (portfolio gallery or a Vercel root).
export default defineConfig({
  base: './',
  plugins: [react()],
  server: { port: 6110, strictPort: true },
  preview: { port: 6110, strictPort: true },
  build: { sourcemap: false, target: 'es2022' },
  test: { environment: 'node', include: ['src/**/*.test.ts'] },
});
