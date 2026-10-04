#!/usr/bin/env node
// verify-dist — checks that the production bundle keeps the browser-local promise made in README and AUDIT.md.
//
// Scans every .js, .css and .html file under dist/ and fails (exit 1) when it finds:
//   - a network or storage API token: fetch(, XMLHttpRequest, WebSocket, EventSource, localStorage,
//     sessionStorage, indexedDB, sendBeacon, document.cookie;
//   - an HTML <script src> or <link href> that points outside the deployed origin, or an inline <script>
//     (the CSP `script-src 'self'` would block it anyway, so shipping one is a bug);
//   - a literal http(s):// URL whose host is not in ALLOWED_HOSTS, or an http(s):// prefix with no literal host
//     (a URL assembled at runtime).
//
// Usage: node scripts/verify-dist.mjs [distDir]   (default: <repo>/dist — run `npm run build` first)
// Node >= 20, no dependencies. Every match is printed with file:line:column and surrounding context.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const distDir = path.resolve(repoRoot, process.argv[2] ?? 'dist');

// Hosts that may appear as *literal strings* in the bundle. None of them is ever contacted by application code;
// each entry explains where the string comes from so a new host cannot slip in without a reason.
const ALLOWED_HOSTS = new Map([
  // react-dom's production builds replace error messages with "https://react.dev/errors/<code>" decoder links.
  ['react.dev', 'react-dom production error-decoder URL'],
  // SARIF 2.1.0 logs carry the schemastore "$schema" identifier so SARIF consumers can validate them.
  ['json.schemastore.org', 'SARIF 2.1.0 $schema identifier'],
  // Findings and SARIF rule help reference the OWASP API Security Top 10 (2023) pages.
  ['owasp.org', 'OWASP API Security Top 10 reference links'],
  // SARIF tool.driver.informationUri points at the project repository.
  ['github.com', 'SARIF tool.driver.informationUri'],
  // react-dom hard-codes the XML, SVG and MathML namespace identifiers; they are names, never dereferenced.
  ['www.w3.org', 'XML/SVG/MathML namespace identifiers'],
]);

// A leading word boundary keeps unrelated identifiers that merely end with a token (e.g. "prefetch(") out of the
// report; there is no trailing boundary so "WebSocketStream" or "EventSourceInit" are still caught.
const FORBIDDEN_TOKENS = [
  ['fetch(', /\bfetch\(/g],
  ['XMLHttpRequest', /\bXMLHttpRequest/g],
  ['WebSocket', /\bWebSocket/g],
  ['EventSource', /\bEventSource/g],
  ['localStorage', /\blocalStorage/g],
  ['sessionStorage', /\bsessionStorage/g],
  ['indexedDB', /\bindexedDB/g],
  ['sendBeacon', /\bsendBeacon/g],
  ['document.cookie', /\bdocument\.cookie/g],
];
const URL_PREFIX = /https?:\/\//gi;
const HOST_AT_START = /^(\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)/i;
const SCANNED_EXTENSIONS = new Set(['.js', '.css', '.html']);
const CONTEXT_CHARS = 70;

const problems = [];
const allowedHostsSeen = new Map();

const label = (file) => path.relative(path.dirname(distDir), file).split(path.sep).join('/');

function walk(root) {
  const files = [];
  const pending = [root];
  while (pending.length > 0) {
    const dir = pending.pop();
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) pending.push(full);
      else if (entry.isFile() && SCANNED_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) files.push(full);
    }
  }
  return files.sort();
}

function lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function locate(starts, index) {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if (starts[mid] <= index) low = mid;
    else high = mid - 1;
  }
  return { line: low + 1, column: index - starts[low] + 1 };
}

function context(text, index, length) {
  const from = Math.max(0, index - CONTEXT_CHARS);
  const to = Math.min(text.length, index + length + CONTEXT_CHARS);
  const snippet = text.slice(from, to).replace(/\s+/g, ' ');
  return `${from > 0 ? '…' : ''}${snippet}${to < text.length ? '…' : ''}`;
}

function report(file, text, starts, index, length, message) {
  const { line, column } = locate(starts, index);
  problems.push({ file, index, line, column, message, context: context(text, index, length) });
}

function checkTokens(file, text, starts) {
  for (const [token, pattern] of FORBIDDEN_TOKENS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      report(file, text, starts, match.index, match[0].length, `forbidden token "${token}"`);
    }
  }
}

function checkUrls(file, text, starts) {
  URL_PREFIX.lastIndex = 0;
  let match;
  while ((match = URL_PREFIX.exec(text)) !== null) {
    const after = text.slice(URL_PREFIX.lastIndex, URL_PREFIX.lastIndex + 260);
    const host = HOST_AT_START.exec(after);
    if (!host) {
      report(file, text, starts, match.index, match[0].length, 'url without a literal host (assembled at runtime?)');
      continue;
    }
    const name = host[1].toLowerCase();
    if (ALLOWED_HOSTS.has(name)) allowedHostsSeen.set(name, (allowedHostsSeen.get(name) ?? 0) + 1);
    else report(file, text, starts, match.index, match[0].length + host[1].length, `disallowed host "${name}"`);
  }
}

function attributeValue(attributes, name) {
  const pattern = new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i');
  const match = pattern.exec(attributes);
  return match ? (match[1] ?? match[2] ?? match[3] ?? '') : null;
}

// Relative and root-relative URLs stay on the deployed origin; anything with a scheme or "//" does not.
const isSameOrigin = (url) => !url.trim().startsWith('//') && !/^[a-z][a-z0-9+.-]*:/i.test(url.trim());

function checkHtml(file, text, starts) {
  const tags = /<(script|link)\b([^>]*)>/gi;
  let match;
  while ((match = tags.exec(text)) !== null) {
    const [tag, rawName, attributes] = match;
    const name = rawName.toLowerCase();
    const attribute = name === 'script' ? 'src' : 'href';
    const value = attributeValue(attributes, attribute);
    if (name === 'script' && value === null) {
      const close = text.indexOf('</script', tags.lastIndex);
      const body = text.slice(tags.lastIndex, close === -1 ? text.length : close);
      if (body.trim() !== '') report(file, text, starts, match.index, tag.length, "inline <script> (blocked by the CSP script-src 'self')");
      continue;
    }
    if (value !== null && !isSameOrigin(value)) {
      report(file, text, starts, match.index, tag.length, `external <${name} ${attribute}="${value}">`);
    }
  }
}

function main() {
  if (!existsSync(distDir) || !statSync(distDir).isDirectory()) {
    console.log(`verify-dist: FAIL — ${label(distDir)}/ not found; run "npm run build" first.`);
    return 1;
  }
  if (!existsSync(path.join(distDir, 'index.html'))) {
    console.log(`verify-dist: FAIL — ${label(distDir)}/index.html not found; run "npm run build" first.`);
    return 1;
  }

  const files = walk(distDir);
  console.log(`verify-dist: scanning ${files.length} file(s) under ${label(distDir)}/ (.js, .css, .html)`);
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    const starts = lineStarts(text);
    checkTokens(file, text, starts);
    checkUrls(file, text, starts);
    if (file.toLowerCase().endsWith('.html')) checkHtml(file, text, starts);
  }

  problems.sort((a, b) => (a.file === b.file ? a.index - b.index : a.file.localeCompare(b.file)));
  for (const problem of problems) {
    console.log(`  FAIL ${label(problem.file)}:${problem.line}:${problem.column} ${problem.message}`);
    console.log(`       ${problem.context}`);
  }

  const seen = [...allowedHostsSeen.entries()].sort(([a], [b]) => a.localeCompare(b));
  console.log(
    `  allow-listed hosts seen: ${seen.length > 0 ? seen.map(([host, n]) => `${host} x${n} (${ALLOWED_HOSTS.get(host)})`).join(', ') : 'none'}`,
  );

  if (problems.length === 0) {
    console.log(`verify-dist: OK — ${files.length} file(s), no network/storage API tokens, no cross-origin references.`);
    return 0;
  }
  const failingFiles = new Set(problems.map((p) => p.file)).size;
  console.log(`verify-dist: FAIL — ${problems.length} problem(s) in ${failingFiles} file(s).`);
  return 1;
}

process.exitCode = main();
