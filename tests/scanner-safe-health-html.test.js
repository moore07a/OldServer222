"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const buildScannerSafeHealthHtml = require("../modules/scanner-security/buildScannerSafeHealthHtml.js");

test("scanner-safe health HTML is static, accessible, and self-contained", () => {
  const html = buildScannerSafeHealthHtml("test_nonce-123");

  assert.match(html, /^<!DOCTYPE html>/);
  assert.equal((html.match(/<h1\b/g) || []).length, 1);
  assert.match(html, /<article class="guide" aria-labelledby="page-title">/);
  assert.match(html, /not a substitute for professional medical advice/);
  assert.match(html, /<style nonce="test_nonce-123">/);
  assert.doesNotMatch(html, /__SCANNER_SAFE_STYLE_NONCE__/);
  assert.doesNotMatch(html, /<(?:script|iframe|form)\b/i);
  assert.doesNotMatch(html, /(?:src|href)=["']https?:/i);
  assert.ok(Buffer.byteLength(html) < 16 * 1024);
});

test("scanner-safe health HTML validates the CSP nonce", () => {
  assert.throws(() => buildScannerSafeHealthHtml(""), /valid scanner-safe style nonce/);
  assert.throws(() => buildScannerSafeHealthHtml('bad\" nonce'), /valid scanner-safe style nonce/);
});

test("scanner-safe health HTML is deterministic for a supplied nonce", () => {
  assert.equal(buildScannerSafeHealthHtml("same_nonce"), buildScannerSafeHealthHtml("same_nonce"));
  assert.notEqual(buildScannerSafeHealthHtml("first_nonce"), buildScannerSafeHealthHtml("second_nonce"));
});
