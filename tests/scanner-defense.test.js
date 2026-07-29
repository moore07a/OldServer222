'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadScannerDefenseHelpers(env = {}) {
  const source = fs.readFileSync('modules/server-runtime/serverRuntime.js', 'utf8');
  const start = source.indexOf('const SCANNER_PROBE_EXACT_PATHS = new Set([');
  const end = source.indexOf('\nconst backgroundTaskHandles = {', start);
  if (start < 0 || end < 0 || end <= start) {
    throw new Error('Could not locate scanner defense helper region in server.js');
  }

  const snippet = `
    const OPTIONAL_URL_PREFIX = 'Private';
    function readPositiveIntEnv(name, fallback) { return fallback; }
    function validateBase64Url(input) {
      const segments = String(input || '').split('/').filter(Boolean);
      return segments.some(segment => segment === 'validpayload1234567890abcdef' || segment === 'validpayload1234567890abcdef@@YWxpY2VAZXhhbXBsZS5jb20') ||
        String(input || '').includes('YWxpY2VAZXhhbXBsZS5jb20/validpayload1234567890abcdef');
    }
    function parseRedirectPayload(input) {
      let cleanInput = String(input || '');
      while (cleanInput.startsWith('/')) cleanInput = cleanInput.slice(1);
      while (cleanInput.endsWith('/')) cleanInput = cleanInput.slice(0, -1);
      const segments = cleanInput.split('/').filter(Boolean);
      const payloadIndex = segments.indexOf('validpayload1234567890abcdef');
      if (payloadIndex === 1 && segments[0] === 'YWxpY2VAZXhhbXBsZS5jb20') return { matchedNewFormat: true, parseMode: 'email_payload' };
      if (payloadIndex > 0) return { matchedNewFormat: true, parseMode: 'ignored_url_payload' };
      if (payloadIndex === 0) return { matchedNewFormat: true, parseMode: 'payload_ignored' };
      return { matchedNewFormat: false, parseMode: 'invalid' };
    }
    function stripOptionalUrlPrefix(value) {
      let clean = String(value || '');
      while (clean.startsWith('/')) clean = clean.slice(1);
      while (clean.endsWith('/')) clean = clean.slice(0, -1);
      const lower = clean.toLowerCase();
      if (lower === 'private') return { payloadPath: '', usedPrefix: true };
      if (lower.startsWith('private/')) return { payloadPath: clean.slice('private/'.length), usedPrefix: true };
      return { payloadPath: clean, usedPrefix: false };
    }
    function looksLikeHttpUrl(value) { const lower = String(value || '').toLowerCase(); return lower.startsWith('http://') || lower.startsWith('https://'); }
    function getClientIp(req) { return req.ip || '203.0.113.10'; }
    function getDenyCacheIp(req) { return req.denyIp || req.ip || '203.0.113.10'; }
    function sanitizeIpForKey(ip) {
      if (!ip || ip === 'unknown' || ip === '') return 'invalid_unknown';
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || /^[0-9a-fA-F:]+$/.test(ip)) return ip;
      return 'malformed_' + String(ip).replace(/[^a-z0-9_-]/gi, '_');
    }
    function boundedMapSet(map, key, value) { map.set(key, value); return map; }
    const SEARCH_BOT_DNS_VERIFY_ENABLED = true;
    const SEARCH_BOT_DNS_TIMEOUT_MS = 900;
    const SEARCH_BOT_DNS_CACHE_TTL_MS = 21600000;
    const SEARCH_BOT_DNS_NEGATIVE_TTL_MS = 900000;
    const SEARCH_BOT_DNS_CACHE_MAX_ENTRIES = 20000;
    const inMemDenyCache = new Map();
    function addDenyCache(ip, reason, ttlSec = 300) {
      inMemDenyCache.set(sanitizeIpForKey(ip), { until: Date.now() + ttlSec * 1000, reason });
    }
    function getDenyCache(ip) {
      return inMemDenyCache.get(sanitizeIpForKey(ip)) || null;
    }
    function getRequestIdentity(req) {
      const displayIp = getClientIp(req) || 'unknown';
      const keyIp = getDenyCacheIp(req) || displayIp || 'unknown';
      return {
        ip: displayIp,
        displayIp,
        keyIp,
        denyCacheKey: keyIp,
        source: keyIp === displayIp ? 'client' : 'trusted_proxy_key'
      };
    }
    function aggregatePerIpEvent() { return false; }
    function addLog() {}
    const IMPERSONATE_MIN_CONFIDENCE = 0.85;
    const SCANNER_PATTERNS_LIST = [];
    const dynamicScanners = [];
    function detectScannerEnhanced(req) {
      const ua = String(((req && req.headers) || {})['user-agent'] || '').toLowerCase();
      return [...SCANNER_PATTERNS_LIST, ...dynamicScanners]
        .filter(scanner => scanner && scanner.pattern instanceof RegExp && scanner.pattern.test(ua))
        .map(scanner => ({ ...scanner, matchedString: ua.match(scanner.pattern)[0] }));
    }
    const PUBLIC_CANONICAL_ALIASES = new Map([['/about-us', '/about']]);
    function isPublicContentSurfaceEnabled() {
      return process.env.PUBLIC_CONTENT_SURFACE !== '0';
    }
    function getCurrentPublicPathSet() {
      return { paths: new Set(['/', '/products', '/pricing', '/features', '/docs', '/blog', '/about', '/contact', '/security', '/status', '/partners', '/privacy', '/terms', '/support', '/signup', '/careers']) };
    }
    function pathMatchesWithOptionalPrefix(pathname, basePath) {
      const cleanPath = String(pathname || '');
      let cleanBase = String(basePath || '');
      while (cleanBase.startsWith('/')) cleanBase = cleanBase.slice(1);
      const normalizedBase = '/' + cleanBase;
      return cleanPath === normalizedBase ||
        cleanPath.startsWith(normalizedBase + '/') ||
        cleanPath === '/foo' + normalizedBase ||
        cleanPath.startsWith('/foo' + normalizedBase + '/');
    }
    ${source.slice(start, end)}
    this.__loaded = {
      sanitizeIpForKey,
      classifyScannerProbeCandidate,
      normalizeScannerProbeCandidate,
      isEmailSafePathCandidate,
      isLikelyRedirectPayloadPathCandidate,
      isLikelyRawUrlRedirectPayload,
      isLikelyFlexibleRedirectPayloadCandidate,
      isLikelyApiConfigProbePath,
      isLikelyCrawlerProbePath,
      isLikelyLocaleOnlyProbePath,
      classifyUnknownScannerBehavior,
      getUnknownScannerHeaderAnomalies,
      pathMatchesUnknownScannerSkipPrefix,
      shouldSkipUnknownScannerShield,
      getClaimedSearchBotVendorFromUa,
      searchBotHostnameMatchesVendor,
      classifyCrawlerIndexerUa,
      isLikelyNonBrowserCrawler,
      isVerifiedSearchBotRequest,
      shouldTrackVisibleIpPublicWalk,
      recordKnownScannerProbeBurst,
      recordKnownScannerVisibleIpBurst,
      shouldTrackVisibleIpKnownScannerBurst,
      getKnownScannerDenyKey,
      canDenyCacheVisibleIp,
      maybeDenyForVisibleIpReputation,
      recordVisibleIpReputationSignal,
      hasVisibleIpReputationSignal,
      summarizeVisibleIpReputationEvents,
      recordVisibleIpPublicWalkPath,
      getCrawlerPublicWalkSignal,
      checkCrawlerPublicWalkThrottle,
      CRAWLER_PUBLIC_WALK_HISTORY,
      CRAWLER_PUBLIC_WALK_DENY_CACHE,
      CRAWLER_PUBLIC_WALK_IP_HISTORY,
      CRAWLER_PUBLIC_WALK_IP_DENY_CACHE,
      VISIBLE_IP_REPUTATION_HISTORY,
      VISIBLE_IP_REPUTATION_DENY_THRESHOLD,
      VISIBLE_IP_PUBLIC_WALK_HISTORY,
      VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS,
      VISIBLE_IP_PUBLIC_WALK_RAPID_UNIQUE_PATHS,
      UNKNOWN_SCANNER_HISTORY,
      SCANNER_PATTERNS_LIST,
      dynamicScanners,
      normalizeScannerConfidence,
      getDenyCache,
      inMemDenyCache,
      KNOWN_SCANNER_BURST_HISTORY,
      KNOWN_SCANNER_VISIBLE_IP_BURST_HISTORY,
      KNOWN_SCANNER_DENY_THRESHOLD,
      KNOWN_SCANNER_VISIBLE_IP_THRESHOLD
    };
  `;
  const sandbox = { process: { env }, Map, Set, Date, String, Number, Math, RegExp, net: require('node:net'), crypto: require('node:crypto') };
  vm.createContext(sandbox);
  vm.runInContext(snippet, sandbox);
  return sandbox.__loaded;
}

function makeReq(path, ip = '203.0.113.10', headers = {}, extra = {}) {
  return {
    ip,
    denyIp: extra.denyIp,
    method: extra.method || 'GET',
    path,
    headers: {
      accept: 'text/html,application/xhtml+xml',
      ...headers
    }
  };
}

function browserHeaders() {
  return {
    'accept-language': 'en-US,en;q=0.9',
    'sec-ch-ua': '"Chromium";v="125"',
    'sec-fetch-site': 'none',
    'sec-fetch-mode': 'navigate',
    'user-agent': 'Mozilla/5.0 Chrome/125.0.0.0'
  };
}

test('scanner probe classifier catches nested sensitive config paths from logs', () => {
  const { classifyScannerProbeCandidate } = loadScannerDefenseHelpers();

  assert.equal(classifyScannerProbeCandidate('config/aws.yml'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('symfony/public/_profiler/phpinfo'), 'nested_probe');
  assert.equal(classifyScannerProbeCandidate('wp-includes/wlwmanifest.xml'), 'nested_probe');
});

test('scanner probe classifier catches top-level crawler probes from production logs', () => {
  const { classifyScannerProbeCandidate } = loadScannerDefenseHelpers();

  assert.equal(classifyScannerProbeCandidate('wp-json/'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('wp-json/wp/v2/posts'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('feed/rss/'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('readme.html'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('docs/go'), 'generic_probe');
});

test('scanner probe classifier keeps sensitive CMS and credential probes blocked', () => {
  const { classifyScannerProbeCandidate } = loadScannerDefenseHelpers();

  assert.equal(classifyScannerProbeCandidate('credentials'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('joomla/administrator/'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('cms/administrator/'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('sites/default/files/'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('modules/mod_login/mod_login.xml'), 'generic_probe');
});


test('scanner probe classifier catches latest credential and app-config probes from logs', () => {
  const { classifyScannerProbeCandidate, isLikelyApiConfigProbePath } = loadScannerDefenseHelpers();

  assert.equal(classifyScannerProbeCandidate('user/login'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('register'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('wp'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('old'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('env'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('env.backup'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('env.bak'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('env.old'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('env.txt'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('application.yml'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('application-production.properties'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('settings/production.py'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('var/log/app.log'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('.yarnrc.yml'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('heapdump'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('threaddump'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('configprops'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('api/heapdump'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('_profiler'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('profiler'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('profiler/phpinfo'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('api/docker-compose.prod.yml'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('app/docker-compose.prod.yml'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('deploy/docker-compose.yml'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('helm/values.yaml'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('api/actuator/env'), 'nested_probe');
  assert.equal(classifyScannerProbeCandidate('api/actuator/heapdump'), 'nested_probe');
  assert.equal(classifyScannerProbeCandidate('app/actuator/heapdump'), 'nested_probe');
  assert.equal(classifyScannerProbeCandidate('v1/actuator/env'), 'nested_probe');
  assert.equal(classifyScannerProbeCandidate('backend/actuator/configprops'), 'nested_probe');
  assert.equal(classifyScannerProbeCandidate('app/heapdump'), 'nested_probe');
  assert.equal(classifyScannerProbeCandidate('client_secret.json'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('google-service-account.json'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('firebase-service-account.json'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('serviceAccountKey.json'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('google-application-credentials.json'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('gcp-service-account.json'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('service-account-key.json'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('.npmrc'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('.openai/config.json'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('.openclaw/openclaw.json'), 'config_probe');
  assert.equal(classifyScannerProbeCandidate('.openclaw/agents/main/agent/models.json'), 'config_probe');

  assert.equal(isLikelyApiConfigProbePath('api/v1/status'), false);
  assert.equal(isLikelyApiConfigProbePath('api/config'), true);
  assert.equal(isLikelyApiConfigProbePath('api/im/v2/app/config'), true);
  assert.equal(isLikelyApiConfigProbePath('api/vue/common/config'), true);
  assert.equal(isLikelyApiConfigProbePath('public/api/index/config'), true);
  assert.equal(isLikelyApiConfigProbePath('memberapi/system/config/get'), true);
  assert.equal(isLikelyApiConfigProbePath('biz/server/config'), true);
  assert.equal(isLikelyApiConfigProbePath('mfzbs/config/base'), true);
  assert.equal(isLikelyApiConfigProbePath('main/config/getkefuData'), true);
});


test('scanner probe classifier catches framework manifest and app-route probes from logs', () => {
  const { classifyScannerProbeCandidate } = loadScannerDefenseHelpers();

  assert.equal(classifyScannerProbeCandidate('.next/required-server-files.json'), 'nested_probe');
  assert.equal(classifyScannerProbeCandidate('.vite/manifest.json'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('_nuxt/manifest.json'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('_ignition/execute-solution'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('build/manifest.json'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('asset-manifest.json'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('account/api-keys'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('swagger.json'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('var/task/serverless.yml'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('app/serverless.json'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('plugins/payments/stripe.json'), 'prefix_probe');
  assert.equal(classifyScannerProbeCandidate('templates/shaper_helix3/templateDetails.xml'), 'nested_probe');
});

test('crawler probe helper recognizes sitemap variants without treating real sitemap as a probe', () => {
  const { isLikelyCrawlerProbePath } = loadScannerDefenseHelpers();

  assert.equal(isLikelyCrawlerProbePath('/sitemaps.xml'), true);
  assert.equal(isLikelyCrawlerProbePath('/Private/sitemaps.xml'), true);
  assert.equal(isLikelyCrawlerProbePath('/sitemap_index.xml'), true);
  assert.equal(isLikelyCrawlerProbePath('/wp-sitemap.xml'), true);
  assert.equal(isLikelyCrawlerProbePath('/news-sitemap.xml'), true);
  assert.equal(isLikelyCrawlerProbePath('/atom.xml'), true);
  assert.equal(isLikelyCrawlerProbePath('/rss.xml'), true);
  assert.equal(isLikelyCrawlerProbePath('/feed.xml'), true);
  assert.equal(isLikelyCrawlerProbePath('/sitemap.xml'), false);
});

test('locale-only catch-all helper recognizes language probes without matching nested paths', () => {
  const { isLikelyLocaleOnlyProbePath } = loadScannerDefenseHelpers();

  assert.equal(isLikelyLocaleOnlyProbePath('/en'), true);
  assert.equal(isLikelyLocaleOnlyProbePath('/Private/en'), true);
  assert.equal(isLikelyLocaleOnlyProbePath('/pt-br'), true);
  assert.equal(isLikelyLocaleOnlyProbePath('/en/docs'), false);
  assert.equal(isLikelyLocaleOnlyProbePath('/english'), false);
});

test('scanner probe classifier strips optional prefix before sensitive matching', () => {
  const { classifyScannerProbeCandidate, normalizeScannerProbeCandidate } = loadScannerDefenseHelpers();

  assert.equal(normalizeScannerProbeCandidate('private/challenge'), 'challenge');
  assert.equal(normalizeScannerProbeCandidate('Private/challenge'), 'challenge');
  assert.equal(classifyScannerProbeCandidate('private/challenge'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('Private/challenge'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('private/e/abc123'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('private/config/aws.yml'), 'config_probe');
});

test('scanner probe classifier allows email-safe ignored config segments', () => {
  const { classifyScannerProbeCandidate, isEmailSafePathCandidate } = loadScannerDefenseHelpers();

  assert.equal(isEmailSafePathCandidate('e/payload/config'), true);
  assert.equal(classifyScannerProbeCandidate('e/payload/config'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('e/payload/config/foo'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('e/payload/backup/foo'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('private/e/payload/config/foo'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('e/payload/../config'), 'traversal_probe');
});

test('scanner probe helper recognizes flexible redirect payloads with ignored config segments', () => {
  const { classifyScannerProbeCandidate, isLikelyFlexibleRedirectPayloadCandidate } = loadScannerDefenseHelpers();

  assert.equal(isLikelyFlexibleRedirectPayloadCandidate('validpayload1234567890abcdef/config/foo'), true);
  assert.equal(isLikelyFlexibleRedirectPayloadCandidate('Private/validpayload1234567890abcdef/backup/foo'), true);
  assert.equal(isLikelyFlexibleRedirectPayloadCandidate('campaign/config/validpayload1234567890abcdef'), true);
  assert.equal(isLikelyFlexibleRedirectPayloadCandidate('campaign/config/validpayload1234567890abcdef//YTRhbmdlbGVzQHltYWlsLmNvbQ=='), true);
  assert.equal(isLikelyFlexibleRedirectPayloadCandidate('Private/campaign/config/validpayload1234567890abcdef'), true);
  assert.equal(classifyScannerProbeCandidate('validpayload1234567890abcdef/config/foo'), 'generic_probe');
  assert.equal(classifyScannerProbeCandidate('campaign/config/validpayload1234567890abcdef'), 'generic_probe');
  assert.equal(isLikelyFlexibleRedirectPayloadCandidate('application/config/aws.yml'), false);
  assert.equal(classifyScannerProbeCandidate('application/config/aws.yml'), 'config_probe');
});



test('crawler public-walk throttle limits noisy crawlers without matching browsers', () => {
  const {
    checkCrawlerPublicWalkThrottle,
    CRAWLER_PUBLIC_WALK_HISTORY,
    CRAWLER_PUBLIC_WALK_DENY_CACHE
  } = loadScannerDefenseHelpers();
  CRAWLER_PUBLIC_WALK_HISTORY.clear();
  CRAWLER_PUBLIC_WALK_DENY_CACHE.clear();

  const crawlerHeaders = {
    'user-agent': 'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)',
    accept: '*/*'
  };
  const paths = [
    '/',
    '/Products/',
    '/pricing/',
    '/FEATURES',
    '/Docs/',
    '/blog',
    '/About/',
    '/contact',
    '/security/',
    '/STATUS',
    '/partners',
    '/privacy/',
    '/terms',
    '/support/',
    '/signup'
  ];
  let decision = null;
  for (const path of paths) {
    decision = checkCrawlerPublicWalkThrottle(makeReq(path, '198.51.100.70', crawlerHeaders));
  }

  assert.equal(decision.limited, true);
  assert.equal(decision.crawlerClassification, 'crawler');
  assert.ok(decision.uniquePathCount > 14);

  const resumedDuringCooldown = checkCrawlerPublicWalkThrottle(makeReq('/careers', '198.51.100.70', {
    ...browserHeaders(),
    'user-agent': crawlerHeaders['user-agent']
  }));
  assert.equal(resumedDuringCooldown.limited, true);
  assert.equal(resumedDuringCooldown.cached, true);

  const browserDecision = checkCrawlerPublicWalkThrottle(makeReq('/careers', '198.51.100.70', browserHeaders()));
  assert.equal(browserDecision.limited, false);
});

test('crawler public-walk throttle keeps verified bot posture as attribution only', () => {
  const { checkCrawlerPublicWalkThrottle, CRAWLER_PUBLIC_WALK_HISTORY, CRAWLER_PUBLIC_WALK_DENY_CACHE } = loadScannerDefenseHelpers();
  CRAWLER_PUBLIC_WALK_HISTORY.clear();
  CRAWLER_PUBLIC_WALK_DENY_CACHE.clear();

  const googleHeaders = {
    'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    accept: '*/*'
  };
  const req = makeReq('/products', '66.249.75.38', googleHeaders);
  req.searchBotVerification = { vendor: 'google', verified: true, reason: 'verified' };

  const first = checkCrawlerPublicWalkThrottle(req);
  assert.equal(first.limited, false);
  assert.equal(first.crawlerClassification, 'crawler');
});

test('crawler public-walk throttle gives search crawlers a higher public-page allowance', () => {
  const { checkCrawlerPublicWalkThrottle, CRAWLER_PUBLIC_WALK_HISTORY, CRAWLER_PUBLIC_WALK_DENY_CACHE } = loadScannerDefenseHelpers();
  CRAWLER_PUBLIC_WALK_HISTORY.clear();
  CRAWLER_PUBLIC_WALK_DENY_CACHE.clear();

  const searchCrawlerHeaders = {
    'user-agent': 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    accept: '*/*'
  };
  const paths = ['/', '/products', '/pricing', '/features', '/docs', '/blog', '/about', '/contact', '/security', '/status', '/partners', '/privacy', '/terms', '/support', '/signup', '/careers'];
  let decision = null;
  for (const path of paths) {
    decision = checkCrawlerPublicWalkThrottle(makeReq(path, '198.51.100.71', searchCrawlerHeaders));
  }

  assert.equal(decision.limited, false);
  assert.equal(decision.publicWalkAllowed, true);
  assert.equal(decision.crawlerClassification, 'search_crawler');
  assert.equal(decision.maxUniquePaths, 30);
});

test('crawler public-walk throttle gives claimed Google crawlers the search allowance', () => {
  const { checkCrawlerPublicWalkThrottle, CRAWLER_PUBLIC_WALK_HISTORY, CRAWLER_PUBLIC_WALK_DENY_CACHE } = loadScannerDefenseHelpers();
  CRAWLER_PUBLIC_WALK_HISTORY.clear();
  CRAWLER_PUBLIC_WALK_DENY_CACHE.clear();

  const googleHeaders = {
    'user-agent': 'Mozilla/5.0 (compatible; GoogleOther; +http://www.google.com/bot.html)',
    accept: '*/*'
  };
  const paths = ['/', '/products', '/pricing', '/features', '/docs', '/blog', '/about', '/contact', '/security', '/status', '/partners', '/privacy', '/terms', '/support', '/signup', '/careers'];
  let decision = null;
  for (const path of paths) {
    decision = checkCrawlerPublicWalkThrottle(makeReq(path, '66.249.75.38', googleHeaders));
  }

  assert.equal(decision.limited, false);
  assert.equal(decision.publicWalkAllowed, true);
  assert.equal(decision.crawlerClassification, 'search_crawler');
  assert.equal(decision.maxUniquePaths, 30);
});

test('crawler public-walk throttle keeps an IP backstop across UA churn', () => {
  const {
    checkCrawlerPublicWalkThrottle,
    CRAWLER_PUBLIC_WALK_HISTORY,
    CRAWLER_PUBLIC_WALK_DENY_CACHE,
    CRAWLER_PUBLIC_WALK_IP_HISTORY,
    CRAWLER_PUBLIC_WALK_IP_DENY_CACHE
  } = loadScannerDefenseHelpers();
  CRAWLER_PUBLIC_WALK_HISTORY.clear();
  CRAWLER_PUBLIC_WALK_DENY_CACHE.clear();
  CRAWLER_PUBLIC_WALK_IP_HISTORY.clear();
  CRAWLER_PUBLIC_WALK_IP_DENY_CACHE.clear();

  const paths = ['/', '/products', '/pricing', '/features', '/docs', '/blog', '/about', '/contact', '/security', '/status', '/partners', '/privacy', '/terms', '/support', '/signup'];
  let decision = null;
  paths.forEach((path, index) => {
    decision = checkCrawlerPublicWalkThrottle(makeReq(path, '198.51.100.73', {
      'user-agent': `Mozilla/5.0 (compatible; SemrushBot/${index}; +http://www.semrush.com/bot.html)`,
      accept: '*/*'
    }));
  });

  assert.equal(decision.limited, true);
  assert.equal(decision.ipBackstop, true);
  assert.ok(decision.ipUniquePathCount > 14);

  const cached = checkCrawlerPublicWalkThrottle(makeReq('/careers', '198.51.100.73', {
    'user-agent': 'Mozilla/5.0 (compatible; SemrushBot/fresh; +http://www.semrush.com/bot.html)',
    accept: '*/*'
  }));
  assert.equal(cached.limited, true);
  assert.equal(cached.cached, true);
  assert.equal(cached.ipBackstop, true);
});

test('crawler public-walk throttle ignores disabled generated public routes', () => {
  const {
    checkCrawlerPublicWalkThrottle,
    CRAWLER_PUBLIC_WALK_HISTORY,
    CRAWLER_PUBLIC_WALK_DENY_CACHE,
    CRAWLER_PUBLIC_WALK_IP_HISTORY,
    CRAWLER_PUBLIC_WALK_IP_DENY_CACHE
  } = loadScannerDefenseHelpers({ PUBLIC_CONTENT_SURFACE: '0' });
  CRAWLER_PUBLIC_WALK_HISTORY.clear();
  CRAWLER_PUBLIC_WALK_DENY_CACHE.clear();
  CRAWLER_PUBLIC_WALK_IP_HISTORY.clear();
  CRAWLER_PUBLIC_WALK_IP_DENY_CACHE.clear();

  const decision = checkCrawlerPublicWalkThrottle(makeReq('/products', '198.51.100.74', {
    'user-agent': 'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)',
    accept: '*/*'
  }));

  assert.equal(decision.limited, false);
  assert.equal(decision.publicWalkAllowed, undefined);
});

test('crawler public-walk throttle respects trusted external scanner exemptions', () => {
  const {
    checkCrawlerPublicWalkThrottle,
    CRAWLER_PUBLIC_WALK_HISTORY,
    CRAWLER_PUBLIC_WALK_DENY_CACHE,
    dynamicScanners
  } = loadScannerDefenseHelpers();
  CRAWLER_PUBLIC_WALK_HISTORY.clear();
  CRAWLER_PUBLIC_WALK_DENY_CACHE.clear();
  dynamicScanners.push({
    name: 'TrustedSemrush',
    pattern: /semrushbot/i,
    confidence: 0.99,
    trustedExternalScanner: true
  });

  const scannerHeaders = {
    'user-agent': 'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)',
    accept: '*/*'
  };
  const paths = ['/', '/products', '/pricing', '/features', '/docs', '/blog', '/about', '/contact', '/security', '/status', '/partners', '/privacy', '/terms', '/support', '/signup'];
  let decision = null;
  for (const path of paths) {
    decision = checkCrawlerPublicWalkThrottle(makeReq(path, '198.51.100.72', scannerHeaders));
  }

  assert.equal(decision.limited, false);
  assert.equal(decision.publicWalkAllowed, true);
  assert.equal(decision.trustedExternalScanner, true);
});

test('crawler public-walk middleware allowance is honored before unknown-scanner classification', () => {
  const source = fs.readFileSync('modules/server-runtime/serverRuntime.js', 'utf8');
  const throttleIndex = source.indexOf('const crawlerWalk = checkCrawlerPublicWalkThrottle(req);');
  const allowanceIndex = source.indexOf('if (crawlerWalk.publicWalkAllowed) return next();', throttleIndex);
  const unknownScannerIndex = source.indexOf('const unknownScanner = classifyUnknownScannerBehavior(req);', throttleIndex);

  assert.notEqual(throttleIndex, -1);
  assert.notEqual(allowanceIndex, -1);
  assert.notEqual(unknownScannerIndex, -1);
  assert.ok(allowanceIndex < unknownScannerIndex);
});

test('crawler public-walk middleware records ops friction before early 429', () => {
  const source = fs.readFileSync('modules/server-runtime/serverRuntime.js', 'utf8');
  const limitedIndex = source.indexOf('if (crawlerWalk.limited) {');
  const reasonIndex = source.indexOf('"scanner_block_reason_crawler_public_walk"', limitedIndex);
  const statusIndex = source.indexOf('"status_429"', limitedIndex);
  const returnIndex = source.indexOf('return res.status(429).end("Too Many Requests");', limitedIndex);

  assert.notEqual(limitedIndex, -1);
  assert.notEqual(reasonIndex, -1);
  assert.notEqual(statusIndex, -1);
  assert.notEqual(returnIndex, -1);
  assert.ok(reasonIndex < returnIndex);
  assert.ok(statusIndex < returnIndex);
});

test('unknown scanner shield flags fast unique public-page walks', () => {
  const { classifyUnknownScannerBehavior, UNKNOWN_SCANNER_HISTORY, sanitizeIpForKey } = loadScannerDefenseHelpers();
  const paths = ['/', '/pricing', '/compliance', '/blog', '/status', '/security', '/partners', '/careers'];
  let decision = null;

  for (const path of paths) {
    decision = classifyUnknownScannerBehavior(makeReq(path));
  }

  assert.equal(decision.reason, 'rapid_unique_path_scan');
  assert.equal(decision.rapidUniquePathCount, 8);
  assert.equal(UNKNOWN_SCANNER_HISTORY.get(sanitizeIpForKey('203.0.113.10')).length, 8);
});

test('unknown scanner shield does not rapid-ban browser-like users behind one IP', () => {
  const { classifyUnknownScannerBehavior } = loadScannerDefenseHelpers();
  const paths = ['/', '/pricing', '/compliance', '/blog', '/status', '/security', '/partners', '/careers'];
  let decision = null;

  for (const path of paths) {
    decision = classifyUnknownScannerBehavior(makeReq(path, '203.0.113.11', browserHeaders()));
  }

  assert.equal(decision, null);
});

test('unknown scanner shield does not high-ratio-ban browser-like users behind one IP', () => {
  const { classifyUnknownScannerBehavior } = loadScannerDefenseHelpers();
  const paths = Array.from({ length: 16 }, (_, index) => `/docs/page-${index}`);
  let decision = null;

  for (const path of paths) {
    decision = classifyUnknownScannerBehavior(makeReq(path, '203.0.113.12', browserHeaders()));
  }

  assert.equal(decision, null);
});

test('unknown scanner shield skips likely valid redirect payload links', () => {
  const { isLikelyRedirectPayloadPathCandidate, shouldSkipUnknownScannerShield } = loadScannerDefenseHelpers();

  assert.equal(isLikelyRedirectPayloadPathCandidate('/validpayload1234567890abcdef/config/foo'), true);
  assert.equal(shouldSkipUnknownScannerShield(makeReq('/validpayload1234567890abcdef/config/foo', '203.0.113.13', { accept: '*/*' })), true);
  assert.equal(isLikelyRedirectPayloadPathCandidate('/application/config/aws.yml'), false);
});

test('unknown scanner shield skips configured-delimiter single-segment redirect payload links', () => {
  const { isLikelyRedirectPayloadPathCandidate, shouldSkipUnknownScannerShield } = loadScannerDefenseHelpers({ REDIRECT_EMAIL_DELIMITERS: '@@' });
  const path = '/Private/validpayload1234567890abcdef%40%40YWxpY2VAZXhhbXBsZS5jb20';

  assert.equal(isLikelyRedirectPayloadPathCandidate(path), true);
  assert.equal(shouldSkipUnknownScannerShield(makeReq(path, '203.0.113.16', { accept: '*/*' })), true);
});

test('unknown scanner shield skips email-first redirect payload links', () => {
  const { shouldSkipUnknownScannerShield, isLikelyFlexibleRedirectPayloadCandidate } = loadScannerDefenseHelpers();
  const path = '/Private/YWxpY2VAZXhhbXBsZS5jb20/validpayload1234567890abcdef';

  assert.equal(isLikelyFlexibleRedirectPayloadCandidate(path), true);
  assert.equal(shouldSkipUnknownScannerShield(makeReq(path, '203.0.113.17', { accept: '*/*' })), true);
});

test('unknown scanner shield skips raw URL redirect payload links', () => {
  const { isLikelyRawUrlRedirectPayload, shouldSkipUnknownScannerShield } = loadScannerDefenseHelpers();

  assert.equal(isLikelyRawUrlRedirectPayload('/https://example-a.test/path'), true);
  assert.equal(shouldSkipUnknownScannerShield(makeReq('/https://example-a.test/path', '203.0.113.14', { accept: '*/*' })), true);
  assert.equal(shouldSkipUnknownScannerShield(makeReq('/Private/https://example-b.test/path', '203.0.113.15', { accept: '*/*' })), true);
});

test('unknown scanner shield uses header anomalies for slower unnamed scanners', () => {
  const { classifyUnknownScannerBehavior } = loadScannerDefenseHelpers();
  const paths = ['/', '/network', '/docs', '/sla', '/about', '/support'];
  let decision = null;

  for (const path of paths) {
    decision = classifyUnknownScannerBehavior(makeReq(path, '203.0.113.20', { accept: '*/*' }));
  }

  assert.equal(decision.reason, 'header_anomaly_path_scan');
  assert.ok(decision.anomalies.includes('missing_accept_language'));
  assert.ok(decision.anomalies.includes('accept_not_html'));
});

test('unknown scanner shield skips externally configured scanners', () => {
  const { classifyUnknownScannerBehavior, dynamicScanners } = loadScannerDefenseHelpers();
  dynamicScanners.push({
    pattern: /SiteLockSpider/i,
    confidence: 0.9,
    name: 'SiteLock_Spider',
    trustedExternalScanner: true
  });
  const paths = ['/', '/solutions', '/support', '/about', '/pricing', '/security'];
  let decision = null;

  for (const path of paths) {
    decision = classifyUnknownScannerBehavior(makeReq(path, '203.0.113.21', {
      accept: '*/*',
      'user-agent': 'SiteLockSpider [en] (WinNT; I ;Nav)'
    }));
  }

  assert.equal(decision, null);
});

test('externally configured scanners do not populate unknown scanner history', () => {
  const {
    classifyUnknownScannerBehavior,
    dynamicScanners,
    UNKNOWN_SCANNER_HISTORY,
    sanitizeIpForKey
  } = loadScannerDefenseHelpers();
  const ip = '203.0.113.23';
  const historyKey = sanitizeIpForKey(ip);
  dynamicScanners.push({
    pattern: /SiteLockSpider/i,
    confidence: 0.9,
    name: 'SiteLock_Spider',
    trustedExternalScanner: true
  });

  for (const path of ['/', '/solutions', '/support', '/about', '/pricing', '/security']) {
    assert.equal(classifyUnknownScannerBehavior(makeReq(path, ip, {
      accept: '*/*',
      'user-agent': 'SiteLockSpider [en] (WinNT; I ;Nav)'
    })), null);
  }

  assert.equal(UNKNOWN_SCANNER_HISTORY.has(historyKey), false);
  assert.equal(classifyUnknownScannerBehavior(makeReq('/contact', ip, {
    accept: '*/*',
    'user-agent': 'Mozilla/5.0'
  })), null);
  assert.equal(UNKNOWN_SCANNER_HISTORY.get(historyKey).length, 1);
});

test('unknown scanner shield does not skip generic built-in scanner detections', () => {
  const { classifyUnknownScannerBehavior, SCANNER_PATTERNS_LIST } = loadScannerDefenseHelpers();
  SCANNER_PATTERNS_LIST.push({
    pattern: /curl/i,
    confidence: 0.9,
    name: 'generic curl'
  });
  const paths = ['/', '/solutions', '/support', '/about', '/pricing', '/security'];
  let decision = null;

  for (const path of paths) {
    decision = classifyUnknownScannerBehavior(makeReq(path, '203.0.113.22', {
      accept: '*/*',
      'user-agent': 'curl/8.4.0'
    }));
  }

  assert.equal(decision.reason, 'header_anomaly_path_scan');
});

test('scanner confidence normalization defaults empty external confidence values', () => {
  const { normalizeScannerConfidence } = loadScannerDefenseHelpers();

  assert.equal(normalizeScannerConfidence(null), 0.9);
  assert.equal(normalizeScannerConfidence(''), 0.9);
  assert.equal(normalizeScannerConfidence(undefined), 0.9);
  assert.equal(normalizeScannerConfidence('0.95'), 0.95);
});


test('unknown scanner shield does not deny text/html clients for browser-only missing headers alone', () => {
  const { classifyUnknownScannerBehavior } = loadScannerDefenseHelpers();
  const paths = ['/', '/network', '/docs', '/sla', '/about', '/support'];
  let decision = null;

  for (const path of paths) {
    decision = classifyUnknownScannerBehavior(makeReq(path, '203.0.113.30'));
  }

  assert.equal(decision, null);
});

test('unknown scanner shield does not skip claimed Googlebot user agents', () => {
  const { classifyUnknownScannerBehavior, UNKNOWN_SCANNER_HISTORY, shouldSkipUnknownScannerShield, isLikelyNonBrowserCrawler } = loadScannerDefenseHelpers();
  const paths = ['/', '/pricing', '/compliance', '/blog', '/status', '/security', '/partners', '/careers'];
  let decision = null;

  for (const path of paths) {
    decision = classifyUnknownScannerBehavior(makeReq(path, '203.0.113.40', {
      'user-agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'
    }));
  }

  assert.equal(decision.reason, 'rapid_unique_path_scan');
  assert.equal(decision.historyIp, '203.0.113.40');
  const googleReq = makeReq('/docs', '203.0.113.41', {
    'user-agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'
  });
  assert.equal(isLikelyNonBrowserCrawler(googleReq), false);
  assert.equal(shouldSkipUnknownScannerShield(googleReq), false);
});


test('search bot helper detects Google/Bing claims and verifies PTR suffixes', () => {
  const { getClaimedSearchBotVendorFromUa, searchBotHostnameMatchesVendor } = loadScannerDefenseHelpers();

  assert.equal(getClaimedSearchBotVendorFromUa('Mozilla/5.0 (compatible; Googlebot/2.1)'), 'google');
  assert.equal(getClaimedSearchBotVendorFromUa('Mozilla/5.0 AppleWebKit bingbot/2.0'), 'bing');
  assert.equal(getClaimedSearchBotVendorFromUa('Mozilla/5.0 Chrome/125'), null);
  assert.equal(searchBotHostnameMatchesVendor('crawl-66-249-66-1.googlebot.com.', 'google'), true);
  assert.equal(searchBotHostnameMatchesVendor('rate-limited-proxy-1-2-3-4.google.com', 'google'), true);
  assert.equal(searchBotHostnameMatchesVendor('msnbot-157-55-39-1.search.msn.com', 'bing'), true);
  assert.equal(searchBotHostnameMatchesVendor('crawl-66-249-66-1.googlebot.com.evil.test', 'google'), false);
});


test('crawler/indexer classifier labels noisy bots without scanner-shield bypass', () => {
  const {
    classifyCrawlerIndexerUa,
    classifyUnknownScannerBehavior,
    shouldSkipUnknownScannerShield,
    isLikelyNonBrowserCrawler
  } = loadScannerDefenseHelpers();
  const uas = [
    ['Claude-SearchBot', 'ai_search_indexer'],
    ['meta-webindexer', 'search_indexer'],
    ['MJ12bot', 'search_crawler'],
    ['Baiduspider', 'search_crawler'],
    ['bingbot', 'search_crawler'],
    ['SiteLockSpider', 'search_crawler']
  ];

  for (const [ua, classification] of uas) {
    const req = makeReq('/pricing', '203.0.113.50', { 'user-agent': ua });
    assert.equal(classifyCrawlerIndexerUa(ua), classification);
    assert.equal(isLikelyNonBrowserCrawler(req), false);
    assert.equal(shouldSkipUnknownScannerShield(req), false);
  }

  let decision = null;
  for (const path of ['/', '/pricing', '/compliance', '/blog', '/status', '/security', '/partners', '/careers']) {
    decision = classifyUnknownScannerBehavior(makeReq(path, '203.0.113.51', { 'user-agent': 'Claude-SearchBot' }));
  }
  assert.equal(decision.reason, 'rapid_unique_path_scan');
  assert.equal(decision.crawlerClassification, 'ai_search_indexer');
});

test('verified Googlebot attribution still does not bypass unknown scanner shield', () => {
  const { isLikelyNonBrowserCrawler, shouldSkipUnknownScannerShield, isVerifiedSearchBotRequest } = loadScannerDefenseHelpers();
  const req = makeReq('/pricing', '66.249.66.1', {
    'user-agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'
  });
  req.searchBotVerification = { vendor: 'google', verified: true, reason: 'verified' };

  assert.equal(isVerifiedSearchBotRequest(req), true);
  assert.equal(isLikelyNonBrowserCrawler(req), false);
  assert.equal(shouldSkipUnknownScannerShield(req), false);
});


test('verified Googlebot public-page walk is still classified as unknown scanner behavior', () => {
  const { classifyUnknownScannerBehavior } = loadScannerDefenseHelpers();
  const paths = ['/', '/pricing', '/compliance', '/blog', '/status', '/security', '/partners', '/careers'];
  let decision = null;

  for (const path of paths) {
    const req = makeReq(path, '66.249.66.1', {
      'user-agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'
    });
    req.searchBotVerification = { vendor: 'google', verified: true, reason: 'verified' };
    decision = classifyUnknownScannerBehavior(req);
  }

  assert.equal(decision.reason, 'rapid_unique_path_scan');
});

test('unknown scanner shield skips optional-prefixed operational routes', () => {
  const { shouldSkipUnknownScannerShield } = loadScannerDefenseHelpers();

  assert.equal(shouldSkipUnknownScannerShield(makeReq('/foo/challenge')), false);
  assert.equal(shouldSkipUnknownScannerShield(makeReq('/foo/challenge-fragment/widget')), false);
  assert.equal(shouldSkipUnknownScannerShield(makeReq('/Private/challenge')), true);
  assert.equal(shouldSkipUnknownScannerShield(makeReq('/private/challenge-fragment/widget')), true);
  assert.equal(shouldSkipUnknownScannerShield(makeReq('/e/payload/config/foo')), true);
  assert.equal(shouldSkipUnknownScannerShield(makeReq('/campaign/config/validpayload1234567890abcdef')), true);
  assert.equal(shouldSkipUnknownScannerShield(makeReq('/campaign/config/validpayload1234567890abcdef//YTRhbmdlbGVzQHltYWlsLmNvbQ==')), true);
  assert.equal(shouldSkipUnknownScannerShield(makeReq('/foo/e/payload/config/foo')), false);
  assert.equal(shouldSkipUnknownScannerShield(makeReq('/Private/e/payload/config/foo')), true);
});

test('unknown scanner history is capped for repeated same-path floods', () => {
  const { classifyUnknownScannerBehavior, UNKNOWN_SCANNER_HISTORY, sanitizeIpForKey } = loadScannerDefenseHelpers();

  for (let index = 0; index < 100; index += 1) {
    assert.equal(classifyUnknownScannerBehavior(makeReq('/', '203.0.113.50')), null);
  }

  assert.equal(UNKNOWN_SCANNER_HISTORY.get(sanitizeIpForKey('203.0.113.50')).length, 64);
});


test('known scanner burst tracker denies after threshold within window', () => {
  const { recordKnownScannerProbeBurst, KNOWN_SCANNER_BURST_HISTORY, KNOWN_SCANNER_DENY_THRESHOLD } = loadScannerDefenseHelpers();
  KNOWN_SCANNER_BURST_HISTORY.clear();
  const base = Date.now();

  for (let i = 1; i < KNOWN_SCANNER_DENY_THRESHOLD; i += 1) {
    const result = recordKnownScannerProbeBurst('198.51.100.10', base + i);
    assert.equal(result.shouldDeny, false);
    assert.equal(result.count, i);
  }

  const threshold = recordKnownScannerProbeBurst('198.51.100.10', base + KNOWN_SCANNER_DENY_THRESHOLD);
  assert.equal(threshold.shouldDeny, true);
  assert.equal(threshold.count, KNOWN_SCANNER_DENY_THRESHOLD);

  const reset = recordKnownScannerProbeBurst('198.51.100.10', base + 61_000);
  assert.equal(reset.shouldDeny, false);
  assert.equal(reset.count, 1);
});




test('known scanner deny key only uses proven client identities', () => {
  const { getKnownScannerDenyKey } = loadScannerDefenseHelpers();

  assert.equal(getKnownScannerDenyKey({ source: 'client', ip: '198.51.100.25', denyCacheKey: '172.70.0.10' }), '198.51.100.25');
  assert.equal(getKnownScannerDenyKey({ source: 'client', displayIp: '198.51.100.26', keyIp: '172.70.0.11' }), '198.51.100.26');
  assert.equal(getKnownScannerDenyKey({ source: 'trusted_proxy_key', ip: '166.88.2.99', denyCacheKey: '84.17.44.225' }), null);
  assert.equal(getKnownScannerDenyKey({ source: 'client', denyCacheKey: '172.70.0.12' }), '172.70.0.12');
});

test('visible IP burst deny-cache writes require proven client identities', () => {
  const { canDenyCacheVisibleIp } = loadScannerDefenseHelpers();

  assert.equal(canDenyCacheVisibleIp({ source: 'client', ip: '198.51.100.20', denyCacheKey: '198.51.100.20' }, '198.51.100.20'), true);
  assert.equal(canDenyCacheVisibleIp({ source: 'trusted_proxy_key', ip: '166.88.2.99', denyCacheKey: '84.17.44.225' }, '166.88.2.99'), false);
  assert.equal(canDenyCacheVisibleIp({ source: 'client', displayIp: '198.51.100.21', denyCacheKey: '198.51.100.21' }, '198.51.100.21'), true);
});


test('visible IP scanner burst tracker uses a separate higher threshold', () => {
  const {
    recordKnownScannerVisibleIpBurst,
    shouldTrackVisibleIpKnownScannerBurst,
    KNOWN_SCANNER_VISIBLE_IP_BURST_HISTORY,
    KNOWN_SCANNER_VISIBLE_IP_THRESHOLD
  } = loadScannerDefenseHelpers();
  KNOWN_SCANNER_VISIBLE_IP_BURST_HISTORY.clear();
  const base = Date.now();

  assert.equal(shouldTrackVisibleIpKnownScannerBurst('prefix_probe'), true);
  assert.equal(shouldTrackVisibleIpKnownScannerBurst('config_probe'), true);
  assert.equal(shouldTrackVisibleIpKnownScannerBurst('generic_probe'), false);

  for (let i = 1; i < KNOWN_SCANNER_VISIBLE_IP_THRESHOLD; i += 1) {
    const result = recordKnownScannerVisibleIpBurst('198.51.100.20', base + i);
    assert.equal(result.shouldDeny, false);
    assert.equal(result.count, i);
  }

  const threshold = recordKnownScannerVisibleIpBurst('198.51.100.20', base + KNOWN_SCANNER_VISIBLE_IP_THRESHOLD);
  assert.equal(threshold.shouldDeny, true);
  assert.equal(threshold.count, KNOWN_SCANNER_VISIBLE_IP_THRESHOLD);
});


test('visible IP reputation requires mixed high-signal categories before deny', () => {
  const {
    recordVisibleIpReputationSignal,
    hasVisibleIpReputationSignal,
    VISIBLE_IP_REPUTATION_HISTORY,
    VISIBLE_IP_REPUTATION_DENY_THRESHOLD
  } = loadScannerDefenseHelpers();
  VISIBLE_IP_REPUTATION_HISTORY.clear();
  const ip = '198.51.100.30';
  const base = Date.now();

  for (let index = 0; index < VISIBLE_IP_REPUTATION_DENY_THRESHOLD; index += 1) {
    const result = recordVisibleIpReputationSignal(ip, 'public_walk', { now: base + index, weight: 3 });
    assert.equal(result.shouldDeny, false);
  }
  assert.equal(hasVisibleIpReputationSignal(ip, { exclude: ['public_walk'] }), false);

  VISIBLE_IP_REPUTATION_HISTORY.clear();
  const first = recordVisibleIpReputationSignal(ip, 'headless', { now: base, weight: 5 });
  assert.equal(first.shouldDeny, false);
  assert.equal(hasVisibleIpReputationSignal(ip, { exclude: ['public_walk'] }), true);

  const second = recordVisibleIpReputationSignal(ip, 'invalid_scanner_path', { now: base + 1, weight: 4 });
  assert.equal(second.shouldDeny, false);

  const threshold = recordVisibleIpReputationSignal(ip, 'public_walk', { now: base + 2, weight: 3 });
  assert.equal(threshold.shouldDeny, true);
  assert.equal(threshold.score, 12);
  assert.deepEqual(new Set(threshold.categories), new Set(['headless', 'invalid_scanner_path', 'public_walk']));
});

test('visible IP reputation keeps malformed IP history under one sanitized key', () => {
  const {
    recordVisibleIpReputationSignal,
    VISIBLE_IP_REPUTATION_HISTORY,
    sanitizeIpForKey
  } = loadScannerDefenseHelpers();
  VISIBLE_IP_REPUTATION_HISTORY.clear();
  const malformedIp = 'bad, forwarded, header';
  const base = Date.now();

  const first = recordVisibleIpReputationSignal(malformedIp, 'headless', { now: base, weight: 5 });
  const second = recordVisibleIpReputationSignal(malformedIp, 'invalid_scanner_path', { now: base + 1, weight: 4 });

  assert.equal(first.count, 1);
  assert.equal(second.count, 2);
  assert.equal(VISIBLE_IP_REPUTATION_HISTORY.size, 1);
  assert.equal(VISIBLE_IP_REPUTATION_HISTORY.get(sanitizeIpForKey(malformedIp)).length, 2);
});

test('visible IP reputation does not deny-cache untrusted display IPs', () => {
  const {
    maybeDenyForVisibleIpReputation,
    VISIBLE_IP_REPUTATION_HISTORY,
    inMemDenyCache,
    getDenyCache
  } = loadScannerDefenseHelpers();
  VISIBLE_IP_REPUTATION_HISTORY.clear();
  inMemDenyCache.clear();
  const ip = '198.51.100.77';
  const req = makeReq('/docs/swift', ip, {}, { denyIp: '203.0.113.60' });
  const base = Date.now();

  maybeDenyForVisibleIpReputation(req, ip, 'headless', { now: base, weight: 5 });
  maybeDenyForVisibleIpReputation(req, ip, 'invalid_scanner_path', { now: base + 1, weight: 4 });
  const result = maybeDenyForVisibleIpReputation(req, ip, 'public_walk', { now: base + 2, weight: 3 });

  assert.equal(result.shouldDeny, true);
  assert.equal(result.denyCacheSkipped, true);
  assert.equal(result.denyCacheSkipReason, 'untrusted_visible_ip');
  assert.equal(getDenyCache(ip), null);
  assert.equal(getDenyCache('203.0.113.60'), null);
});

test('unknown scanner history keys on trusted deny-cache IP', () => {
  const { classifyUnknownScannerBehavior, UNKNOWN_SCANNER_HISTORY, sanitizeIpForKey } = loadScannerDefenseHelpers();

  classifyUnknownScannerBehavior(makeReq('/docs', '198.51.100.99', {}, { denyIp: '203.0.113.60' }));

  assert.equal(UNKNOWN_SCANNER_HISTORY.has(sanitizeIpForKey('198.51.100.99')), false);
  assert.equal(UNKNOWN_SCANNER_HISTORY.has(sanitizeIpForKey('203.0.113.60')), true);
});

test('visible IP public-walk tracking honors unknown-scanner shield kill switch', () => {
  const disabled = loadScannerDefenseHelpers({ UNKNOWN_SCANNER_SHIELD_ENABLED: '0' });
  const req = makeReq('/pricing', '198.51.100.88', browserHeaders());

  assert.equal(disabled.classifyUnknownScannerBehavior(req), null);
  assert.equal(disabled.shouldTrackVisibleIpPublicWalk(req, true), false);

  const enabled = loadScannerDefenseHelpers();
  assert.equal(enabled.shouldTrackVisibleIpPublicWalk(req, true), true);
  assert.equal(enabled.shouldTrackVisibleIpPublicWalk(req, false), false);
});

test('visible IP public-walk history follows visible IP across rotating deny-cache keys', () => {
  const {
    classifyUnknownScannerBehavior,
    recordVisibleIpPublicWalkPath,
    VISIBLE_IP_PUBLIC_WALK_HISTORY,
    VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS,
    VISIBLE_IP_PUBLIC_WALK_RAPID_UNIQUE_PATHS,
    UNKNOWN_SCANNER_HISTORY,
    sanitizeIpForKey
  } = loadScannerDefenseHelpers();
  VISIBLE_IP_PUBLIC_WALK_HISTORY.clear();
  UNKNOWN_SCANNER_HISTORY.clear();

  const visibleIp = '198.51.100.77';
  const denyIps = ['203.0.113.71', '203.0.113.72'];
  const paths = Array.from({ length: VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS }, (_, index) => `/campaign-page-${index}`);
  let visibleSummary = null;

  for (let index = 0; index < paths.length; index += 1) {
    const req = makeReq(paths[index], visibleIp, browserHeaders(), { denyIp: denyIps[index % denyIps.length] });
    assert.equal(classifyUnknownScannerBehavior(req), null);
    visibleSummary = recordVisibleIpPublicWalkPath(visibleIp, req, Date.now() + index);
  }

  assert.equal(visibleSummary.uniquePathCount, VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS);
  assert.ok(visibleSummary.rapidUniquePathCount >= VISIBLE_IP_PUBLIC_WALK_RAPID_UNIQUE_PATHS);
  assert.equal(VISIBLE_IP_PUBLIC_WALK_HISTORY.get(sanitizeIpForKey(visibleIp)).length, VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS);
  assert.ok((UNKNOWN_SCANNER_HISTORY.get(sanitizeIpForKey(denyIps[0])) || []).length < VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS);
  assert.ok((UNKNOWN_SCANNER_HISTORY.get(sanitizeIpForKey(denyIps[1])) || []).length < VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS);
});

test('quiet static probe routes are registered before redirect validation', () => {
  const source = fs.readFileSync('modules/server-runtime/serverRuntime.js', 'utf8');
  const validationIndex = source.indexOf('app.use(validateRedirectRequest);');
  assert.notEqual(validationIndex, -1);

  for (const route of [
    'app.get("/.well-known/", handleWellKnownDirectoryProbe);',
    'app.get("/ads.txt", handleAdsTxt);',
    'app.get("/.well-known/security.txt", handleSecurityTxt);'
  ]) {
    const routeIndex = source.indexOf(route);
    assert.notEqual(routeIndex, -1);
    assert.ok(routeIndex < validationIndex, `${route} should be registered before redirect validation`);
  }

  for (const blockedProbe of [
    '/credentials',
    '/joomla/administrator/',
    '/cms/administrator/',
    '/sites/default/files/',
    '/modules/mod_login/mod_login.xml',
    '/composer.json',
    '/account.json',
    '/terraform.tfvars',
    '/application_default_credentials.json'
  ]) {
    assert.equal(source.includes(`app.get("${blockedProbe}"`), false, `${blockedProbe} must not become a static route`);
  }
});

test('baseline security headers are attached before scanner early exits', () => {
  const source = fs.readFileSync('modules/server-runtime/serverRuntime.js', 'utf8');
  const baselineMiddlewareIndex = source.indexOf('applyEarlyBaselineSecurityHeaders(req, res);');
  const scannerProbeBlockerIndex = source.indexOf('// Change 1: Scanner probe blocker');
  const unknownScannerShieldIndex = source.indexOf('// Adaptive shield for unknown scanners');
  const rateLimiterIndex = source.indexOf('// Change 3: Per-IP rate limiter');

  assert.notEqual(baselineMiddlewareIndex, -1);
  assert.notEqual(scannerProbeBlockerIndex, -1);
  assert.notEqual(unknownScannerShieldIndex, -1);
  assert.notEqual(rateLimiterIndex, -1);
  assert.ok(baselineMiddlewareIndex < scannerProbeBlockerIndex, 'baseline headers should precede scanner probe 404 exits');
  assert.ok(baselineMiddlewareIndex < unknownScannerShieldIndex, 'baseline headers should precede unknown scanner 429 exits');
  assert.ok(baselineMiddlewareIndex < rateLimiterIndex, 'baseline headers should precede rate-limit 429 exits');

  const helperStart = source.indexOf('function applyEarlyBaselineSecurityHeaders');
  assert.notEqual(helperStart, -1);
  const helperEnd = source.indexOf('// Attach scanner-visible baseline headers', helperStart);
  assert.ok(helperEnd > helperStart);
  const helperSource = source.slice(helperStart, helperEnd);

  assert.match(source, /contentTypeOptions: "nosniff"/);
  assert.match(source, /referrerPolicy: "no-referrer"/);
  assert.match(source, /frameOptions: "DENY"/);
  assert.equal((source.match(/"X-Content-Type-Options"/g) || []).length, 2);
  assert.match(helperSource, /setBaselineSecurityHeaders\(res/);
  assert.doesNotMatch(helperSource, /includeRobots: true/);
  assert.match(helperSource, /SECURITY_HEADER_VALUES\.hstsPreload/);
  assert.match(source, /function applyNoIndexToEarlyErrorResponses/);
  assert.match(source, /numericStatus >= 400/);
});

test('scanner safety lane is shared by email-safe and catch-all redirect paths', () => {
  const source = fs.readFileSync('modules/server-runtime/serverRuntime.js', 'utf8');

  assert.match(source, /function setInterstitialReasonHeader\(res, reason\)/);
  assert.match(source, /function sendScannerSafetyLaneHeadResponse\(req, res, payloadPath, reason = "HEAD-probe"/);
  assert.match(source, /function tryRenderTrustedScannerSafeHtmlForPayload\(req, res, baseString, securityCheck = \{\}, options = \{\}\)/);
  assert.match(source, /\[SCANNER-SAFETY-LANE\]/);

  const catchAllIndex = source.indexOf('app.get("/:data(*)"');
  const handleRedirectIndex = source.indexOf('async function handleRedirectCore');
  assert.notEqual(catchAllIndex, -1);
  assert.notEqual(handleRedirectIndex, -1);

  const handleRedirectSource = source.slice(handleRedirectIndex, catchAllIndex);
  assert.match(handleRedirectSource, /tryRenderTrustedScannerSafeHtmlForPayload\(req, res, baseString, securityCheck/);
  assert.match(handleRedirectSource, /source: "catchall"/);

  const emailSafeRouteIndex = source.indexOf('const handleEmailSafePath = async');
  assert.notEqual(emailSafeRouteIndex, -1);
  const emailSafeRouteSource = source.slice(emailSafeRouteIndex, source.indexOf('app.get("/e/:data(*)"', emailSafeRouteIndex));
  assert.match(emailSafeRouteSource, /scannerCtx\.scannerSafeHtmlEligible/);
  assert.match(emailSafeRouteSource, /tryRenderTrustedScannerSafeHtmlForPayload\(req, res, clean, scannerCtx/);
  assert.match(emailSafeRouteSource, /source: "email-safe-route"/);
});

test('HEAD safety-lane responses set explicit head-probe reason headers', () => {
  const source = fs.readFileSync('modules/server-runtime/serverRuntime.js', 'utf8');
  const helperStart = source.indexOf('function sendScannerSafetyLaneHeadResponse');
  assert.notEqual(helperStart, -1);
  const helperEnd = source.indexOf('async function tryRenderTrustedScannerSafeHtmlForPayload', helperStart);
  assert.ok(helperEnd > helperStart);
  const helperSource = source.slice(helperStart, helperEnd);

  assert.match(helperSource, /setInterstitialReasonHeader\(res, reason\)/);
  assert.match(helperSource, /return res\.status\(200\)\.type\("html"\)\.end\(\)/);

  const headRouteIndex = source.indexOf('const handleEmailSafePathHead =');
  assert.notEqual(headRouteIndex, -1);
  const headRouteSource = source.slice(headRouteIndex, source.indexOf('app.head("/e/:data(*)"', headRouteIndex));
  assert.match(headRouteSource, /sendScannerSafetyLaneHeadResponse\(req, res, clean, "HEAD-probe"/);

  const catchAllHeadSourceStart = source.indexOf('const looksDeep = longPath && looksEncoded');
  assert.notEqual(catchAllHeadSourceStart, -1);
  const catchAllHeadSource = source.slice(catchAllHeadSourceStart, source.indexOf('return next();', catchAllHeadSourceStart));
  assert.match(catchAllHeadSource, /req\.method === "HEAD"/);
  assert.match(catchAllHeadSource, /sendScannerSafetyLaneHeadResponse\(req, res, clean, "HEAD-probe"/);
});
