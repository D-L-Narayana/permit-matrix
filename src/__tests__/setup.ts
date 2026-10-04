// Shared harness for the jsdom App tests; every file under src/__tests__/ imports it first.
// jsdom has no layout engine and no navigation, so the few browser APIs Radix, user-event and the App's
// download helper touch are stubbed here. Everything is guarded so a future environment that provides
// the real API wins.
import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

type Mutable = Record<string, unknown>;
const globalScope = globalThis as unknown as Mutable;

// Radix measures controls with ResizeObserver (useSize); observing nothing is fine without layout.
if (typeof globalScope.ResizeObserver === 'undefined') {
  class ResizeObserverStub {
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
  }
  globalScope.ResizeObserver = ResizeObserverStub;
}

if (typeof Element !== 'undefined') {
  const proto = Element.prototype as unknown as Mutable;
  if (typeof proto.scrollIntoView !== 'function') proto.scrollIntoView = function scrollIntoView(): void {};
  // Pointer capture is used by Radix pointer interactions and user-event; jsdom does not implement it.
  if (typeof proto.hasPointerCapture !== 'function') proto.hasPointerCapture = function hasPointerCapture(): boolean { return false; };
  if (typeof proto.setPointerCapture !== 'function') proto.setPointerCapture = function setPointerCapture(): void {};
  if (typeof proto.releasePointerCapture !== 'function') proto.releasePointerCapture = function releasePointerCapture(): void {};
}

if (typeof window !== 'undefined' && typeof window.matchMedia !== 'function') {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener(): void {},
      removeListener(): void {},
      addEventListener(): void {},
      removeEventListener(): void {},
      dispatchEvent: () => false,
    }) as unknown as MediaQueryList;
}

/** Every Blob the App hands to URL.createObjectURL, oldest first. Cleared after each test. */
export const capturedBlobs: Blob[] = [];

// The App downloads reports by creating an object URL and clicking a detached <a download>. jsdom would
// hand the Blob to Node's real createObjectURL and report the click as unimplemented navigation; instead
// the Blob is captured for assertions and the click is a no-op.
if (typeof URL !== 'undefined') {
  const urlStatics = URL as unknown as { createObjectURL(blob: Blob): string; revokeObjectURL(url: string): void };
  urlStatics.createObjectURL = (blob: Blob): string => {
    capturedBlobs.push(blob);
    return 'blob:captured';
  };
  urlStatics.revokeObjectURL = (): void => {};
}

if (typeof HTMLAnchorElement !== 'undefined') {
  Object.defineProperty(HTMLAnchorElement.prototype, 'click', {
    value: function click(): void {},
    configurable: true,
    writable: true,
  });
}

// Vitest globals are off, so Testing Library cannot register its own cleanup.
afterEach(() => {
  cleanup();
  capturedBlobs.length = 0;
});

/** Reads a Blob as text; uses blob.text() when available and falls back to FileReader. */
export function readBlob(blob: Blob): Promise<string> {
  if (typeof blob.text === 'function') return blob.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(reader.error ?? new Error('FileReader failed'));
    reader.readAsText(blob);
  });
}
