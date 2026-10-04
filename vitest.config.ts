import { defineConfig, mergeConfig } from 'vitest/config';
import viteConfig from './vite.config';

// Test configuration lives here so vite.config.ts can stay a pure build config. Engine tests run in node;
// UI tests opt into jsdom per file with `// @vitest-environment jsdom`, so no DOM environment is forced globally.
// Coverage is measured on the engine only: the UI is covered by behavioural (Testing Library + axe) tests instead.
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: 'node',
      include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
      coverage: {
        provider: 'v8',
        include: ['src/engine/**/*.ts'],
        exclude: ['src/engine/__tests__/**'],
        reporter: ['text', 'lcov'],
        reportsDirectory: 'coverage',
        thresholds: { lines: 90, branches: 85, functions: 90, statements: 90 },
      },
    },
  }),
);
