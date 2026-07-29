"use strict";

function createBuildChallengeHtml(dependencies) {
  const {
    TURNSTILE_ORIGIN,
    withOptionalUrlPrefix
  } = dependencies;

  return function buildChallengeHtml(encryptedData, cspNonce = '') {
  return `<!doctype html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0c1116">
<meta name="robots" content="noindex,nofollow">
<title>Verify you are human</title>
<style>
  :root{
    --bg:#0c1116; --card:#0c1116; --text:#e8eef6; --muted:#93a1b2;
    --accent:#0ea5e9; --ring:rgba(255,255,255,0.05); --border:rgba(255,255,255,0.06);
  }
  @media (prefers-color-scheme: light){
    :root{
      --bg:#f7fafc; --card:#ffffff; --text:#0b1220; --muted:#516173;
      --accent:#0ea5e9; --ring:#e8eef5; --border:#e7eef6;
    }
  }
  *{ box-sizing:border-box; }
  html,body{ height:100%; }
  body{
    margin:0; background:var(--bg); color:var(--text);
    font:16px/1.45 system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif;
    -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
    display:flex; align-items:center; justify-content:center;
    padding:clamp(16px,4vw,40px);
  }
  .card{
    width:100%; max-width:760px; text-align:center;
    background:var(--card);
    border:1px solid var(--border);
    border-radius:16px;
    padding:clamp(22px,3vw,34px);
    box-shadow: 0 20px 50px rgba(0,0,0,.35), 0 0 0 1px rgba(255,255,255,.02) inset;
  }
  h2{ margin:0 0 10px; font-size:clamp(26px,3.4vw,38px); letter-spacing:.2px; }
  .muted{ color:var(--muted); }
  #ts{ display:inline-block; margin-top:12px; }
  .status{ margin-top:12px; color:var(--muted); font-size:14px; min-height:20px; }
  .err{ color:#ef4444; }
</style>

<script nonce="${cspNonce}">
  const ENCRYPTED_DATA = ${JSON.stringify(encryptedData)};
  const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";
  const TURNSTILE_SCRIPT_ID = "cf-turnstile-script";

  // SINGLETON STATE MANAGEMENT - Prevent duplicates
  let currentWidgetId = null;
  let isRendering = false;
  let scriptLoaded = false;
  let initializationStarted = false;
  let turnstileReady = false;
  let renderAttempts = 0;
  const MAX_RENDER_ATTEMPTS = 1; // Only allow one render attempt

  window.__sid = (Math.random().toString(36).slice(2) + Date.now().toString(36));

  function clientContext(extra) {
    return {
      phase: extra.phase || 'context',
      sid: window.__sid,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      lang: navigator.language,
      online: navigator.onLine,
      vis: document.visibilityState,
      ref: document.referrer || '',
      ts: Date.now(),
      widgetId: currentWidgetId,
      isRendering: isRendering,
      scriptLoaded: scriptLoaded,
      turnstileReady: turnstileReady,
      renderAttempts: renderAttempts
    };
  }

  function trackPhase(phase, data = {}) {
    const context = clientContext({ phase, ...data });

    // Only log critical phases to reduce noise
    const criticalPhases = [
      'script-load-error',
      'render-blocked-duplicate',
      'render-success',
      'render-error',
      'error-callback',
      'timeout',
      'navigation-error'
    ];

    if (criticalPhases.includes(phase)) {
      fetch(${JSON.stringify(withOptionalUrlPrefix("/ts-client-log"))}, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(context)
      }).catch(() => {}); // Silent fail for logging errors
    }
  }

  window.addEventListener('error', function(e) {
    trackPhase('window-error', {
      filename: e.filename,
      lineno: e.lineno,
      colno: e.colno,
      message: String(e.message||'')
    });
  }, true);

  window.addEventListener('unhandledrejection', function(e) {
    trackPhase('unhandledrejection', {
      reason: String(e.reason && (e.reason.stack||e.reason.message||e.reason) || '')
    });
  });

  function decryptChallengeData(encrypted) {
    return fetch(${JSON.stringify(withOptionalUrlPrefix("/decrypt-challenge-data"))}, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ data: encrypted })
    }).then(function(r) {
      if (!r.ok) throw new Error('Network response was not ok');
      return r.json();
    });
  }

  var getChallengePayload = (function() {
    var cached = null;
    return function(reset) {
      if (reset) cached = null;
      if (!cached) cached = decryptChallengeData(ENCRYPTED_DATA);
      return cached;
    };
  })();

  // SINGLE INITIALIZATION CONTROLLER
  function initializeTurnstile() {
    if (initializationStarted) {
      console.log('[TS] Initialization already started, skipping duplicate');
      return;
    }
    initializationStarted = true;

    const statusEl = document.getElementById('status');
    if (!statusEl) {
      console.error('[TS] Status element not found');
      return;
    }

    statusEl.textContent = 'Loading security check...';

    // Wait for both DOM ready and Turnstile ready
    function waitForTurnstileAndDOM() {
      const isDOMReady = document.readyState === 'complete' || document.readyState === 'interactive';
      const isTurnstileReady = window.turnstile && typeof window.turnstile.render === 'function';

      if (isDOMReady && isTurnstileReady && !turnstileReady) {
        turnstileReady = true;
        startWidgetRendering();
      } else if (!isDOMReady || !isTurnstileReady) {
        setTimeout(waitForTurnstileAndDOM, 100);
      }
    }

    // Fallback timeout
    const fallbackTimeout = setTimeout(() => {
      if (!currentWidgetId && renderAttempts === 0) {
        console.warn('[TS] Fallback: Starting render after timeout');
        startWidgetRendering();
      }
    }, 8000);

    function startWidgetRendering() {
      clearTimeout(fallbackTimeout);

      getChallengePayload()
        .then(function(data) {
          if (!data.success) throw new Error(data.error || 'Decryption failed');
          return data.payload;
        })
        .then(function(payload) {
          safeRenderTurnstile(payload.sitekey, payload.cdata);
        })
        .catch(function(e) {
          statusEl.textContent = 'Security initialization failed. Please refresh.';
          console.error('[TS] Initialization error:', e);
          trackPhase('initialization-error', { error: e.message });
        });
    }

    // Start waiting for readiness
    waitForTurnstileAndDOM();
  }

  // SINGLE RENDER FUNCTION with strict duplicate prevention
  function safeRenderTurnstile(sitekey, cdata) {
    if (renderAttempts >= MAX_RENDER_ATTEMPTS) {
      console.log('[TS] Max render attempts reached, skipping');
      trackPhase('render-blocked-max-attempts');
      return;
    }

    if (isRendering) {
      console.log('[TS] Already rendering, skipping duplicate');
      trackPhase('render-blocked-rendering');
      return;
    }

    if (currentWidgetId) {
      console.log('[TS] Widget already exists, skipping duplicate');
      trackPhase('render-blocked-existing-widget');
      return;
    }

    renderAttempts++;
    isRendering = true;

    const tsContainer = document.getElementById('ts');
    const statusEl = document.getElementById('status');

    if (!tsContainer || !statusEl) {
      console.error('[TS] Container or status element not found');
      isRendering = false;
      return;
    }

    // Clear any existing content
    tsContainer.innerHTML = '<div id="ts-inner" style="min-height:65px; display:flex; justify-content:center;"></div>';
    const innerContainer = document.getElementById('ts-inner');

    if (!innerContainer) {
      console.error('[TS] Inner container not found');
      isRendering = false;
      return;
    }

    // Small delay to ensure DOM is updated
    setTimeout(() => {
      if (!window.turnstile || typeof window.turnstile.render !== 'function') {
        console.error('[TS] Turnstile not available for rendering');
        statusEl.textContent = 'Security component not loaded. Please refresh.';
        isRendering = false;
        trackPhase('render-error-turnstile-unavailable');
        return;
      }

      try {
        console.log('[TS] Starting widget render attempt', renderAttempts);

        const widgetId = window.turnstile.render(innerContainer, {
          sitekey: sitekey,
          action: 'link_redirect',
          cData: cdata,
          appearance: 'always',
          callback: onOK,
          'error-callback': onErr,
          'timeout-callback': onTimeout
        });

        if (widgetId) {
          currentWidgetId = widgetId;
          isRendering = false;
          statusEl.textContent = 'Challenge ready.';
          console.log('[TS] Widget rendered successfully:', widgetId);
          trackPhase('render-success', { widgetId: widgetId });
        } else {
          console.error('[TS] Turnstile.render returned null widget ID');
          isRendering = false;
          statusEl.textContent = 'Challenge failed to load. Please refresh.';
          trackPhase('render-error-null-id');
        }
      } catch (renderError) {
        console.error('[TS] Render exception:', renderError);
        isRendering = false;
        statusEl.textContent = 'Challenge error. Please refresh.';
        trackPhase('render-exception', { error: renderError.message });
      }
    }, 100);
  }

  function onOK(token) {
    console.log('[TS] Challenge completed successfully');
    const statusEl = document.getElementById('status');
    if (statusEl) {
      statusEl.textContent = 'Verifying...';
    }

    // Prevent multiple submissions
    currentWidgetId = null;

    getChallengePayload()
      .then(function(data) {
        if (!data.success) throw new Error('Decryption failed');

        const next = data.payload.next;
        const lh = data.payload.lh;
        const reason = data.payload.cr || '';

        try {
          const decoded = decodeURIComponent(next);
          const parts = decoded.split('?');
          const base = parts[0];
          const qs = parts[1] || '';
          const sp = new URLSearchParams(qs);
          sp.delete('cft');
          sp.delete('lh');
          if (reason) {
            sp.set('cr', reason);
          }
          sp.append('cft', token);
          sp.append('lh', lh);
          const suffix = '&' + sp.toString();

          console.log('[TS] Redirecting after successful challenge');
          window.location.href = ${JSON.stringify(`${withOptionalUrlPrefix("/r")}?d=`)} + encodeURIComponent(base) + suffix;
        } catch(e) {
          console.error('[TS] Navigation error:', e);
          if (statusEl) statusEl.textContent = 'Navigation error. Please retry.';
          trackPhase('navigation-error', { error: e.message });
        }
      })
      .catch(function(e) {
        console.error('[TS] Payload decryption error:', e);
        if (statusEl) statusEl.textContent = 'Security error. Please refresh.';
        trackPhase('decrypt-error', { error: e.message });
      });
  }

  function onErr(errCode) {
    console.log('[TS] Error callback:', errCode);

    // Error 106010 means "already solved" - this is expected if user solved quickly
    if (errCode === '106010') {
      console.log('[TS] Ignoring 106010 (challenge already solved)');
      return; // DO NOT retry or reset state
    }

    trackPhase('error-callback', {
      errorCode: String(errCode || ''),
      widgetId: currentWidgetId,
      renderAttempts: renderAttempts
    });

    // For other errors, allow one retry but with careful state management
    if (renderAttempts < 2) {
      console.log('[TS] Scheduling retry for error:', errCode);
      currentWidgetId = null;
      isRendering = false;

      setTimeout(() => {
        getChallengePayload(true) // Reset cache
          .then(function(data) {
            if (!data.success) throw new Error('Retry decrypt failed');
            safeRenderTurnstile(data.payload.sitekey, data.payload.cdata);
          })
          .catch(function(err) {
            const statusEl = document.getElementById('status');
            if (statusEl) statusEl.textContent = 'Security check failed. Please refresh.';
          });
      }, 1000);
    } else {
      console.log('[TS] Max retries reached for error:', errCode);
      const statusEl = document.getElementById('status');
      if (statusEl) statusEl.textContent = 'Too many attempts. Please refresh the page.';
    }
  }

  function onTimeout() {
    console.log('[TS] Challenge timeout');
    const statusEl = document.getElementById('status');
    if (statusEl) statusEl.textContent = 'Challenge timed out. Refresh the page.';
    currentWidgetId = null;
    isRendering = false;
    trackPhase('timeout');
  }

  // SCRIPT LOAD HANDLERS - Only one initialization path
  function tsApiOnLoad(ev) {
    console.log('[TS] Script loaded successfully');
    scriptLoaded = true;

    const scriptEl = document.getElementById(TURNSTILE_SCRIPT_ID);
    if (scriptEl) {
      scriptEl.dataset.loaded = '1';
      scriptEl.dataset.failed = '';
    }

    trackPhase('script-loaded');

    // Start initialization
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
      initializeTurnstile();
    } else {
      document.addEventListener('DOMContentLoaded', initializeTurnstile, { once: true });
    }
  }

  function tsApiOnError(ev) {
    console.error('[TS] Script load failed');
    const scriptEl = document.getElementById(TURNSTILE_SCRIPT_ID);
    if (scriptEl) scriptEl.dataset.failed = '1';

    const statusEl = document.getElementById('status');
    if (statusEl) statusEl.textContent = 'Challenge script failed to load. Check adblock and refresh.';

    trackPhase('script-load-error', {
      src: ev && ev.target && ev.target.src || ''
    });
  }

  function onEarlyResourceErrorCapture(ev) {
    const target = ev && ev.target;
    if (!target || target.tagName !== 'SCRIPT') return;

    const src = target.getAttribute('src') || '';
    const isTurnstileScript =
      target.id === TURNSTILE_SCRIPT_ID ||
      src.indexOf('/turnstile/v0/api.js') !== -1;

    if (!isTurnstileScript) return;

    window.removeEventListener('error', onEarlyResourceErrorCapture, true);
    tsApiOnError(ev);
  }

  window.addEventListener('error', onEarlyResourceErrorCapture, true);

  function bindTurnstileScriptErrorHandler() {
    const scriptEl = document.getElementById(TURNSTILE_SCRIPT_ID);
    if (!scriptEl) return;
    scriptEl.addEventListener('error', tsApiOnError, { once: true });
    window.removeEventListener('error', onEarlyResourceErrorCapture, true);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindTurnstileScriptErrorHandler, { once: true });
  } else {
    bindTurnstileScriptErrorHandler();
  }
</script>

<!-- SINGLE SCRIPT TAG - No duplicate loading -->
<script id="cf-turnstile-script"
        src="${TURNSTILE_ORIGIN}/turnstile/v0/api.js?render=explicit&onload=tsApiOnLoad"
        async
        defer>
</script>

</head>
<body>
  <div class="card">
    <h3>Verify you are human by completing the action below.</h3>
    <p class="muted">We need to review the security of your connection before proceeding.</p>
    <div id="ts" aria-live="polite"></div>
    <p id="status" class="status muted">Loading security check...</p>
    <noscript><p class="err">Turnstile requires JavaScript. Please enable JS and refresh.</p></noscript>
    <p class="muted" style="margin-top:18px">Protected by Cloudflare Turnstile</p>
  </div>
</body>
</html>`;
}
}

module.exports = createBuildChallengeHtml;
