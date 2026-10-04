# Third-party notices — Permit Matrix

All third-party components are installed from npm with pinned versions; their licence texts ship in `node_modules/<package>/LICENSE` and are not modified.

| Component | Version | Licence | Source |
|---|---|---|---|
| React, React DOM | 19.3.0 | MIT | https://github.com/facebook/react |
| @radix-ui/react-dialog | 1.1.23 | MIT | https://github.com/radix-ui/primitives |
| @radix-ui/react-switch | 1.3.7 | MIT | https://github.com/radix-ui/primitives |
| IBM Plex Sans / IBM Plex Mono (via @fontsource) | fonts © 2019 IBM Corp., SIL Open Font License 1.1; packaging MIT | 5.3.0 | https://github.com/IBM/plex · https://fontsource.org |
| Vite | 7.3.6 | MIT | https://github.com/vitejs/vite |
| Vitest | 4.1.11 | MIT | https://github.com/vitest-dev/vitest |
| TypeScript | 5.9.3 | Apache-2.0 | https://github.com/microsoft/TypeScript |
| @vitejs/plugin-react | 5.2.0 | MIT | https://github.com/vitejs/vite-plugin-react |

### Development-only dependencies (tests, lint, coverage — nothing below ships in `dist/`)

| Component | Version | Licence | Source |
|---|---|---|---|
| ESLint, @eslint/js | 9.39.5 | MIT | https://github.com/eslint/eslint |
| typescript-eslint | 8.71.0 | MIT | https://github.com/typescript-eslint/typescript-eslint |
| globals | 17.13.0 | MIT | https://github.com/sindresorhus/globals |
| eslint-plugin-react-hooks | 7.1.1 | MIT | https://github.com/facebook/react |
| eslint-plugin-jsx-a11y | 6.10.2 | MIT | https://github.com/jsx-eslint/eslint-plugin-jsx-a11y |
| Prettier | 3.9.9 | MIT | https://github.com/prettier/prettier |
| @vitest/coverage-v8 | 4.1.11 | MIT | https://github.com/vitest-dev/vitest |
| jsdom | 29.1.1 | MIT | https://github.com/jsdom/jsdom |
| @testing-library/react · dom · user-event · jest-dom | 16.3.3 · 10.4.2 · 14.6.7 · 6.9.1 | MIT | https://github.com/testing-library |
| axe-core | 4.13.0 | MPL-2.0 | https://github.com/dequelabs/axe-core |
| Ajv | 8.20.0 | MIT | https://github.com/ajv-validator/ajv |

`public/THIRD_PARTY_LICENSES.txt` reproduces the licence texts of the **production** bundle only; the development
tools above are installed from the lockfile and carry their licence texts in `node_modules/<package>/LICENSE`.

Standards referenced for educational mapping (not redistributed): OWASP API Security Top 10 (2023), OWASP Top 10:2021.
SARIF 2.1.0 (OASIS) is referenced as an export format; the schema URL is a string literal, never fetched.
