// ESLint flat config. Besides the usual presets, the "browser-local invariants" block turns the product promise
// documented in README ("Browser-local only") and AUDIT.md ("Data flow", "Engine output → DOM") into lint errors:
// application code under src/ never talks to a network host, never touches browser storage and renders text only.
import js from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import jsxA11y from 'eslint-plugin-jsx-a11y';
import globals from 'globals';

const POLICY = 'Permit Matrix is browser-local (README "Browser-local only", AUDIT.md "Data flow"): application code';
const noNetwork = (api) => `${POLICY} must not issue network requests, so ${api} is forbidden in src/.`;
const noStorage = (api) => `${POLICY} must not persist data, so ${api} is forbidden in src/.`;
const textOnly = (what) => `${what} is forbidden: contract content is rendered as text nodes only (AUDIT.md "Engine output → DOM").`;

const restrictedGlobals = [
  { name: 'fetch', message: noNetwork('fetch') },
  { name: 'XMLHttpRequest', message: noNetwork('XMLHttpRequest') },
  { name: 'WebSocket', message: noNetwork('WebSocket') },
  { name: 'EventSource', message: noNetwork('EventSource') },
  { name: 'localStorage', message: noStorage('localStorage') },
  { name: 'sessionStorage', message: noStorage('sessionStorage') },
  { name: 'indexedDB', message: noStorage('indexedDB') },
];

const restrictedProperties = [
  { object: 'navigator', property: 'sendBeacon', message: noNetwork('navigator.sendBeacon') },
  { object: 'document', property: 'cookie', message: noStorage('document.cookie') },
  { object: 'window', property: 'fetch', message: noNetwork('window.fetch') },
  { object: 'globalThis', property: 'fetch', message: noNetwork('globalThis.fetch') },
  { object: 'window', property: 'localStorage', message: noStorage('window.localStorage') },
  { object: 'window', property: 'sessionStorage', message: noStorage('window.sessionStorage') },
];

const restrictedSyntax = [
  { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: textOnly('dangerouslySetInnerHTML') },
  { selector: "CallExpression[callee.name='eval']", message: textOnly('eval()') },
  { selector: "NewExpression[callee.name='Function']", message: textOnly('new Function()') },
];

export default defineConfig([
  globalIgnores(['dist/**', 'coverage/**', 'node_modules/**', 'qa/**', 'public/**'], 'permit-matrix/ignores'),
  {
    name: 'permit-matrix/linter-options',
    // A stale eslint-disable comment must not survive a refactor unnoticed.
    linterOptions: { reportUnusedDisableDirectives: 'error' },
  },
  js.configs.recommended,
  {
    name: 'permit-matrix/typescript',
    files: ['**/*.ts', '**/*.tsx'],
    extends: [tseslint.configs.recommended],
    rules: {
      // Names starting with "_" are intentionally unused — the convention tsconfig's noUnusedParameters already honours.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_', ignoreRestSiblings: true },
      ],
    },
  },
  {
    // Also on .ts so custom hooks that live outside .tsx files are still checked.
    name: 'permit-matrix/react-hooks',
    files: ['**/*.ts', '**/*.tsx'],
    extends: [reactHooks.configs.flat.recommended],
  },
  {
    name: 'permit-matrix/jsx-a11y',
    files: ['**/*.tsx'],
    extends: [jsxA11y.flatConfigs.recommended],
    rules: {
      // The request/response panes are scrollable <pre tabIndex={0}>: WCAG 2.1.1 (axe "scrollable-region-focusable")
      // requires keyboard access to scrollable regions, which the recommended options forbid on non-interactive tags.
      'jsx-a11y/no-noninteractive-tabindex': ['error', { tags: ['pre'], roles: ['tabpanel'], allowExpressionValues: true }],
    },
  },
  {
    name: 'permit-matrix/browser-globals',
    files: ['src/**/*.ts', 'src/**/*.tsx'],
    languageOptions: { globals: { ...globals.browser } },
  },
  {
    name: 'permit-matrix/node-globals',
    files: ['scripts/**/*.mjs', 'eslint.config.js', 'vite.config.ts', 'vitest.config.ts'],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    // Tests are exempt: they may stub or assert the absence of exactly these APIs.
    name: 'permit-matrix/browser-local-invariants',
    files: ['src/**/*.ts', 'src/**/*.tsx'],
    ignores: ['src/**/__tests__/**', 'src/**/*.test.ts', 'src/**/*.test.tsx'],
    rules: {
      'no-restricted-globals': ['error', ...restrictedGlobals],
      'no-restricted-properties': ['error', ...restrictedProperties],
      'no-restricted-syntax': ['error', ...restrictedSyntax],
    },
  },
]);
