"use strict";

const NONCE_PLACEHOLDER = "__SCANNER_SAFE_STYLE_NONCE__";

const SCANNER_SAFE_HEALTH_HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Simple Wellness Habits for Everyday Health</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <style nonce="${NONCE_PLACEHOLDER}">
    :root{color-scheme:light dark;--bg:#eef5f0;--surface:#fff;--surface-soft:#f7faf8;--text:#17251e;--muted:#52635a;--accent:#23734d;--accent-soft:#dcefe4;--border:#d8e4dc;--shadow:0 14px 38px rgba(28,67,46,.10);}
    *{box-sizing:border-box;}
    html{font-size:16px;}
    body{margin:0;min-height:100vh;font-family:Arial,Helvetica,sans-serif;background:linear-gradient(145deg,var(--bg),#f8faf9 55%,#e8f2ec);color:var(--text);line-height:1.65;}
    .page{width:min(100% - 2rem,68rem);margin-inline:auto;padding:clamp(1.5rem,5vw,4rem) 0;}
    .hero,.guide,.disclaimer{background:var(--surface);border:1px solid var(--border);box-shadow:var(--shadow);}
    .hero{display:grid;grid-template-columns:auto 1fr;gap:1.25rem;align-items:center;padding:clamp(1.5rem,4vw,2.75rem);border-radius:1.5rem;margin-bottom:1.25rem;}
    .hero-icon{display:grid;place-items:center;width:4.5rem;height:4.5rem;border-radius:1.25rem;background:var(--accent-soft);color:var(--accent);font-size:2rem;font-weight:700;line-height:1;}
    .eyebrow{margin:0 0 .35rem;color:var(--accent);font-size:.78rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;}
    h1{margin:0;font-size:clamp(1.8rem,4vw,2.65rem);line-height:1.15;letter-spacing:-.025em;}
    .summary{max-width:65ch;margin:.8rem 0 0;color:var(--muted);font-size:clamp(1rem,2vw,1.08rem);}
    .guide{padding:clamp(1rem,3vw,1.5rem);border-radius:1.5rem;}
    .cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem;}
    .habit{position:relative;min-height:10.5rem;padding:1.35rem 1.35rem 1.25rem;border:1px solid var(--border);border-radius:1rem;background:var(--surface-soft);}
    .habit:last-child{grid-column:1/-1;min-height:auto;}
    .number{display:inline-grid;place-items:center;width:1.85rem;height:1.85rem;margin-bottom:.65rem;border-radius:50%;background:var(--accent-soft);color:var(--accent);font-size:.78rem;font-weight:700;}
    h2{margin:0 0 .4rem;color:var(--text);font-size:1.12rem;line-height:1.3;}
    p{margin:0;}
    .habit p,.checklist{color:var(--muted);}
    .checklist{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.45rem 1.5rem;padding:0;margin:.75rem 0 0;list-style:none;}
    .checklist li{position:relative;padding-left:1.35rem;}
    .checklist li::before{content:"✓";position:absolute;left:0;color:var(--accent);font-weight:700;}
    .disclaimer{margin-top:1.25rem;padding:1.1rem 1.35rem;border-radius:1rem;color:var(--muted);font-size:.9rem;box-shadow:none;}
    @media (max-width:42rem){.hero{grid-template-columns:1fr}.hero-icon{width:3.75rem;height:3.75rem}.cards,.checklist{grid-template-columns:1fr}.habit:last-child{grid-column:auto}}
    @media (prefers-color-scheme:dark){:root{--bg:#101a15;--surface:#17231d;--surface-soft:#1d2b24;--text:#eef7f1;--muted:#b8c9bf;--accent:#71d39e;--accent-soft:#214a35;--border:#31483b;--shadow:0 14px 38px rgba(0,0,0,.28)}body{background:linear-gradient(145deg,var(--bg),#142019 55%,#0d1712)}}
    @media print{:root{--bg:#fff;--surface:#fff;--surface-soft:#fff;--text:#000;--muted:#333;--accent:#165b3a;--accent-soft:#fff;--border:#bbb;--shadow:none}body{background:#fff}.page{width:100%;padding:0}.hero,.guide,.disclaimer{box-shadow:none}.habit{min-height:auto;break-inside:avoid}}
  </style>
</head>
<body>
  <main class="page">
    <header class="hero">
      <div class="hero-icon" aria-hidden="true">+</div>
      <div>
        <p class="eyebrow">General wellness information</p>
        <h1 id="page-title">Simple Wellness Habits for Everyday Health</h1>
        <p class="summary">Small daily routines can support energy, focus, and general well-being. These practical reminders are intended for everyday lifestyle awareness.</p>
      </div>
    </header>
    <article class="guide" aria-labelledby="page-title">
      <div class="cards">
        <section class="habit"><span class="number" aria-hidden="true">01</span><h2>Hydration</h2><p>Keep water nearby during the day and consider starting the morning with a glass of water before caffeinated drinks.</p></section>
        <section class="habit"><span class="number" aria-hidden="true">02</span><h2>Movement</h2><p>Short walking or stretching breaks can help reduce stiffness during long periods of sitting.</p></section>
        <section class="habit"><span class="number" aria-hidden="true">03</span><h2>Balanced Meals</h2><p>A simple plate with vegetables, whole grains, and protein can make everyday meals more satisfying.</p></section>
        <section class="habit"><span class="number" aria-hidden="true">04</span><h2>Sleep Routine</h2><p>Consistent sleep and wake times, a quiet room, and reduced screen use before bed can support better rest.</p></section>
        <section class="habit"><span class="number" aria-hidden="true">05</span><h2>Stress Management</h2><p>Brief breathing breaks, journaling, or a few quiet minutes can make it easier to reset during a busy day.</p></section>
        <section class="habit"><span class="number" aria-hidden="true">06</span><h2>Quick Daily Checklist</h2><ul class="checklist"><li>Drink water regularly.</li><li>Take short movement breaks.</li><li>Choose balanced meals when possible.</li><li>Keep a consistent sleep routine.</li><li>Pause for a few calm minutes when needed.</li></ul></section>
      </div>
    </article>
    <footer class="disclaimer"><p>This page provides general lifestyle information only and is not a substitute for professional medical advice.</p></footer>
  </main>
</body>
</html>`;

function buildScannerSafeHealthHtml(styleNonce) {
  const nonce = String(styleNonce || "");
  if (!/^[A-Za-z0-9_-]+$/.test(nonce)) {
    throw new TypeError("A valid scanner-safe style nonce is required");
  }
  return SCANNER_SAFE_HEALTH_HTML_TEMPLATE.replace(NONCE_PLACEHOLDER, nonce);
}

module.exports = buildScannerSafeHealthHtml;
