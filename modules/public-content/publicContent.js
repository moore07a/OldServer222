"use strict";

function createPublicContent(dependencies) {
  const {
    addLog,
    app,
    crypto,
    deterministicPick,
    express,
    hash32,
    pathMatchesWithOptionalPrefix,
    process,
    require,
    resolvePublicBaseUrls,
    rotationSeed,
    safeLogValue
  } = dependencies;

// ================== ENHANCED PUBLIC CONTENT SURFACE ==================
const PUBLIC_CONTENT_SURFACE = (process.env.PUBLIC_CONTENT_SURFACE || "0") === "1";
const PUBLIC_SITE_PERSONA = (process.env.PUBLIC_SITE_PERSONA || "rotating").toLowerCase();
const PUBLIC_SITE_NAME_OVERRIDE = (process.env.PUBLIC_SITE_NAME || "").trim();
const PUBLIC_SITE_BASE_URL = (process.env.TURNSTILE_EXPECT_HOSTNAME || "").trim();
const PUBLIC_ROTATION_MODE = (process.env.PUBLIC_ROTATION_MODE || "daily").trim().toLowerCase();
const PUBLIC_GENERATE_PATHS = parseInt(process.env.PUBLIC_GENERATE_PATHS || "25", 10);
const PUBLIC_ENABLE_ANALYTICS = (process.env.PUBLIC_ENABLE_ANALYTICS || "1") === "1";
const PUBLIC_ENABLE_BACKGROUND = (process.env.PUBLIC_ENABLE_BACKGROUND || "1") === "1";
const PUBLIC_TRAFFIC_SUMMARY_EVERY_RAW = parseInt(process.env.PUBLIC_TRAFFIC_SUMMARY_EVERY || "10", 10);
const PUBLIC_TRAFFIC_SUMMARY_EVERY = Number.isFinite(PUBLIC_TRAFFIC_SUMMARY_EVERY_RAW) && PUBLIC_TRAFFIC_SUMMARY_EVERY_RAW > 0
  ? PUBLIC_TRAFFIC_SUMMARY_EVERY_RAW
  : 10;

// Safety gate: allow explicit force-enable while keeping default-off posture.
function isPublicContentSurfaceEnabled() {
  const forceEnable = (process.env.PUBLIC_CONTENT_SURFACE_FORCE || "").trim().toLowerCase();
  const forced = forceEnable === "1" || forceEnable === "true" || forceEnable === "yes";
  return PUBLIC_CONTENT_SURFACE || forced;
}

// ================== MULTIPLE PERSONAS ==================
// Each persona is a completely different "cover story"
const PERSONAS = {
  // Persona 1: CDN / Edge Computing Provider
  cdn: {
    name: "EdgeFlow",
    tagline: "Global edge network for modern applications",
    description: "Accelerate your content with our global edge network",
    sitekey: "edgeflow",
    contentTypes: ['html', 'json', 'xml'],
    logo: "⚡",
    primaryColor: "#0066cc",
    secondaryColor: "#4c9aff",
    features: [
      "Global CDN with 200+ edge locations",
      "DDoS protection included",
      "Serverless compute at the edge",
      "Image optimization pipeline",
      "Real-time purging API",
      "Custom SSL certificates"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Network", path: "/network" },
      { text: "Pricing", path: "/pricing" },
      { text: "Documentation", path: "/docs" },
      { text: "Status", path: "/status" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/edge/locations", "/api/v1/metrics"]
  },

  // Persona 2: Media Streaming Platform
  media: {
    name: "StreamWave",
    tagline: "High-quality video streaming infrastructure",
    description: "Stream video content at any scale with our reliable platform",
    sitekey: "streamwave",
    contentTypes: ['html', 'json', 'xml'],
    logo: "🎬",
    primaryColor: "#9c27b0",
    secondaryColor: "#ce93d8",
    features: [
      "Adaptive bitrate streaming",
      "DRM and content protection",
      "Live transcoding",
      "Video analytics dashboard",
      "Multi-platform playback SDKs",
      "Sub-second latency options"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Features", path: "/features" },
      { text: "Pricing", path: "/pricing" },
      { text: "Developers", path: "/developers" },
      { text: "Status", path: "/status" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/streams", "/api/v1/analytics"]
  },

  // Persona 3: Cloud Storage Provider
  storage: {
    name: "CloudVault",
    tagline: "Secure object storage for any workload",
    description: "Store, protect, and serve data with enterprise-grade durability",
    sitekey: "cloudvault",
    contentTypes: ['html', 'json', 'xml'],
    logo: "☁️",
    primaryColor: "#2e7d32",
    secondaryColor: "#81c784",
    features: [
      "S3-compatible object storage",
      "99.999999999% durability",
      "Server-side encryption",
      "Lifecycle management",
      "Cross-region replication",
      "Presigned URL generation"
    ],
    footerLinks: [
    { text: "Home", path: "/" },
    { text: "Solutions", path: "/solutions" },
    { text: "Pricing", path: "/pricing" },
    { text: "Docs", path: "/docs" },
    { text: "Status", path: "/status" },
    { text: "Security", path: "/security" },
    { text: "Support", path: "/support" }
  ],
  apiEndpoints: ["/api/v1/status", "/api/v1/buckets", "/api/v1/objects"]
},

  // Persona 4: API Gateway / Proxy Service
  api: {
    name: "API Gateway Pro",
    tagline: "Enterprise API management platform",
    description: "Secure, scale, and monitor your APIs with our intelligent gateway",
    sitekey: "apigateway",
    contentTypes: ['html', 'json', 'xml'],
    logo: "🔌",
    primaryColor: "#d32f2f",
    secondaryColor: "#ef9a9a",
    features: [
      "Rate limiting and throttling",
      "API key authentication",
      "Request/response transformation",
      "Analytics and monitoring",
      "GraphQL federation",
      "OpenAPI/Swagger support"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Products", path: "/products" },
      { text: "Pricing", path: "/pricing" },
      { text: "Docs", path: "/docs" },
      { text: "Blog", path: "/blog" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/keys", "/api/v1/analytics"]
  },

  // Persona 5: Security / WAF Provider
  security: {
    name: "ShieldEdge",
    tagline: "Web application security for modern threats",
    description: "Protect your applications from bots, DDoS, and OWASP Top 10",
    sitekey: "shieldedge",
    contentTypes: ['html', 'json', 'xml'],
    logo: "🛡️",
    primaryColor: "#ff6f00",
    secondaryColor: "#ffb74d",
    features: [
      "Web Application Firewall",
      "Bot mitigation engine",
      "DDoS protection",
      "Rate limiting",
      "Security analytics",
      "Compliance reporting"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Products", path: "/products" },
      { text: "Pricing", path: "/pricing" },
      { text: "Docs", path: "/docs" },
      { text: "Status", path: "/status" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/threats", "/api/v1/rules"]
  },

  // Persona 6: Health & Wellness (keep as fallback)
  wellness: {
    name: "Wellness Hub",
    tagline: "Evidence-based health guidance",
    description: "Practical wellness advice for busy professionals",
    sitekey: "wellness",
    contentTypes: ['html'],
    logo: "🌿",
    primaryColor: "#2e7d32",
    secondaryColor: "#81c784",
    features: [
      "Morning mobility routines",
      "Sustainable nutrition tips",
      "Sleep optimization",
      "Stress management",
      "Workout plans for home",
      "Recovery protocols"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "About", path: "/about" },
      { text: "Articles", path: "/articles" },
      { text: "Guides", path: "/guides" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: []
  }
};

// Select active persona (deterministic based on date)
function getActivePersona() {
  if (PUBLIC_SITE_PERSONA !== "rotating" && PERSONAS[PUBLIC_SITE_PERSONA]) {
    return PERSONAS[PUBLIC_SITE_PERSONA];
  }

  // Rotate personas deterministically
  const personaKeys = Object.keys(PERSONAS);
  const seed = rotationSeed();
  const index = hash32(seed) % personaKeys.length;
  const personaKey = personaKeys[index];

  return PERSONAS[personaKey];
}

function getPublicSiteName(persona = getActivePersona()) {
  return PUBLIC_SITE_NAME_OVERRIDE || persona.name;
}

// ================== GENERATE DUMMY PATHS ==================
const PUBLIC_CORE_MARKETING_PATHS = [
  '/products', '/blog', '/articles', '/guides', '/pricing', '/solutions', '/services', '/docs',
  '/about', '/contact', '/features', '/developers', '/network', '/status', '/security', '/support'
];

const PUBLIC_CANONICAL_ALIASES = new Map([
  ['/about-us', '/about'],
  ['/contact-us', '/contact'],
  ['/services-us', '/solutions'],
  ['/services-page', '/solutions'],
  ['/status-page', '/status'],
  ['/status-check', '/status'],
  ['/docs-page', '/docs'],
  ['/docs-old', '/docs']
]);

function generateAllPaths(persona, rotationSeed) {
  const paths = [];
  const seed = rotationSeed || 'default-seed'; // Use provided seed or fallback

  // Always include core marketing pages so dynamic router cannot miss known render branches.
  paths.push(...PUBLIC_CORE_MARKETING_PATHS);

  // Add standard footer links
  persona.footerLinks.forEach(link => {
    if (link.path !== '/') paths.push(link.path);
  });

  // Add blog/articles section (10-15 posts)
  paths.push('/blog');
  for (let i = 1; i <= 12; i++) {
    const topics = ['getting-started', 'tutorial', 'guide', 'announcement', 'best-practices', 'case-study'];
    const topic = topics[hash32(`${seed}:blog:${i}`) % topics.length];

    paths.push(`/blog/${topic}-${i}`);
    paths.push(`/blog/post-${i}`);
    paths.push(`/articles/${i}`);
  }

  // Add product/service pages
  paths.push('/products');
  paths.push('/pricing');
  paths.push('/features');
  paths.push('/signup');
  const productTypes = ['enterprise', 'pro', 'business', 'starter', 'custom'];
  productTypes.forEach((type, idx) => {
    paths.push(`/products/${type}`);
    paths.push(`/pricing/${type}`);
    paths.push(`/features/${type}`);
  });

  // Add documentation section
  const docSections = ['getting-started', 'api', 'sdk', 'faq', 'troubleshooting', 'changelog'];
  docSections.forEach(section => {
    paths.push(`/docs/${section}`);

    // Sub-pages
    for (let i = 1; i <= 3; i++) {
      paths.push(`/docs/${section}/part-${i}`);
    }
  });

  // Add resource pages
  paths.push('/resources');
  paths.push('/articles');
  paths.push('/guides');
  paths.push('/articles/engineering-handbook');
  paths.push('/guides/implementation-playbook');
  paths.push('/whitepapers');
  paths.push('/case-studies');
  paths.push('/webinars');
  paths.push('/events');

  // Add legal pages
  paths.push('/privacy');
  paths.push('/terms');
  paths.push('/security');
  paths.push('/compliance');
  paths.push('/sla');
  paths.push('/status');

  // Add company pages
  paths.push('/about');
  paths.push('/careers');
  paths.push('/partners');
  paths.push('/news');
  paths.push('/press');

  // Add random generated paths (deterministic based on seed)
  for (let i = 0; i < PUBLIC_GENERATE_PATHS; i++) {
    const randomId = hash32(`${seed}:random:${i}`).toString(36).slice(0, 8);
    paths.push(`/p/${randomId}`);
    paths.push(`/shared/${randomId}`);
    paths.push(`/preview/${randomId}`);
    paths.push(`/embed/${randomId}`);
  }

  // Remove duplicates and sort
  return [...new Set(paths)].sort();
}

// ================== ENHANCED PAGE GENERATOR ==================

const createRenderEnhancedPublicPage = require("../public-page/renderEnhancedPublicPage.js");
const renderEnhancedPublicPage = createRenderEnhancedPublicPage({
  PUBLIC_ENABLE_ANALYTICS,
  deterministicPick,
  getActivePersona,
  getPublicSiteName,
  hash32,
  rotationSeed
});

// ================== GENERATE API RESPONSES ==================
function generateDummyAPIResponse(path, persona, seed) {
  const endpoint = path.split('/').pop();
  const timestamp = new Date().toISOString();
  const requestId = crypto.createHash('md5').update(`${seed}:${path}:${Date.now()}`).digest('hex').slice(0, 12);

  // Base response structure
  const response = {
    success: true,
    timestamp,
    request_id: requestId,
    service: persona.name,
    version: `v${hash32(`${seed}:version`) % 4 + 1}.0.0`
  };

  // Endpoint-specific data
  if (path.includes('/status')) {
    response.data = {
      status: 'operational',
      uptime: (99.9 + (hash32(`${seed}:uptime_api`) % 10) / 100).toFixed(2) + '%',
      latency_ms: hash32(`${seed}:latency_api`) % 30 + 10,
      services: {
        api: 'healthy',
        database: 'healthy',
        cache: 'healthy',
        storage: 'degraded'
      }
    };
  } else if (path.includes('/metrics')) {
    response.data = {
      requests_per_second: hash32(`${seed}:rps`) % 500 + 100,
      bandwidth_mbps: (hash32(`${seed}:bandwidth`) % 800 + 200).toFixed(2),
      active_connections: hash32(`${seed}:connections`) % 10000 + 1000,
      cache_hit_rate: (hash32(`${seed}:cache`) % 15 + 80).toFixed(1) + '%'
    };
  } else if (path.includes('/buckets') || path.includes('/objects')) {
    response.data = {
      buckets: Array.from({length: 3}, (_, i) => ({
        name: `bucket-${i + 1}-${seed.slice(0, 4)}`,
        objects: hash32(`${seed}:objects:${i}`) % 1000 + 100,
        size_gb: (hash32(`${seed}:size:${i}`) % 500 + 50).toFixed(2)
      }))
    };
  } else if (path.includes('/streams')) {
    response.data = {
      active_streams: hash32(`${seed}:streams`) % 500 + 50,
      viewers: hash32(`${seed}:viewers`) % 50000 + 5000,
      bitrates: ['240p', '480p', '720p', '1080p', '4K']
    };
  } else if (path.includes('/threats')) {
    response.data = {
      blocked_requests: hash32(`${seed}:blocked`) % 100000 + 5000,
      top_attack_types: [
        { type: 'SQL Injection', count: hash32(`${seed}:sql`) % 500 + 100 },
        { type: 'XSS', count: hash32(`${seed}:xss`) % 300 + 50 },
        { type: 'Bot', count: hash32(`${seed}:bot`) % 1000 + 200 }
      ]
    };
  } else {
    response.data = {
      message: 'Endpoint operational',
      documentation: 'https://docs.' + persona.sitekey + '.com',
      rate_limit: hash32(`${seed}:rate`) % 1000 + 500
    };
  }

  return JSON.stringify(response, null, 2);
}

// ================== DUMMY SITEMAP GENERATOR ==================
function escapeSitemapXml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function generateEnhancedSitemap(req, persona, allPaths) {
  const baseUrls = resolvePublicBaseUrls(req, { requestHostOnly: true, preferConfiguredCanonical: true });
  const today = new Date().toISOString().split('T')[0];

  const urlEntries = [];
  for (const baseUrl of baseUrls) {
    allPaths.forEach(rawPath => {
      const path = String(rawPath || "/");
      if (path.startsWith('/api/') ||
          path.startsWith('/_') ||
          path.includes('analytics') ||
          path.includes('collect') ||
          path.includes('interact')) {
        return;
      }

      const priority = path === '/' ? '1.0' :
                      path.match(/^\/(?:pricing|solutions|features)/) ? '0.9' :
                      path.match(/^\/(?:blog|articles|guides)/) ? '0.8' :
                      path.match(/^\/(?:docs|status|security)/) ? '0.7' : '0.6';

      const changefreq = path === '/' ? 'daily' :
                        path.includes('blog') ? 'weekly' :
                        path.includes('docs') ? 'monthly' : 'weekly';

      urlEntries.push(`
  <url>
    <loc>${escapeSitemapXml(`${baseUrl}${path}`)}</loc>
    <lastmod>${today}</lastmod>
    <changefreq>${changefreq}</changefreq>
    <priority>${priority}</priority>
  </url>`);
    });
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
  ${urlEntries.join('')}
</urlset>`;
}

// ================== BACKGROUND TRAFFIC GENERATOR ==================
function startPublicBackgroundTraffic() {
  if (!PUBLIC_CONTENT_SURFACE || !PUBLIC_ENABLE_BACKGROUND) return;
  const stats = {
    total: 0,
    bot: 0,
    realBrowser: 0,
    unknown: 0,
    errors: 0,
    lastPath: "-"
  };

  function classifyPublicTrafficRequest(req) {
    const ua = (req.get("user-agent") || "").toLowerCase();
    const knownBotFragments = [
      "bot", "spider", "crawler", "slurp", "duckduckbot", "bingbot", "googlebot", "ahrefsbot",
      "semrushbot", "mj12bot", "dotbot", "yandex", "baiduspider", "curl", "wget", "python-requests",
      "headless", "phantomjs", "scrapy"
    ];
    const isBotUa = knownBotFragments.some(fragment => ua.includes(fragment));
    const hasSecCHUA = !!req.get("sec-ch-ua");
    const hasFetchSite = !!req.get("sec-fetch-site");
    const hasFetchMode = !!req.get("sec-fetch-mode");

    if (isBotUa) return "bot";

    if (hasSecCHUA && hasFetchSite && hasFetchMode && ua && !ua.includes("headless")) {
      return "realBrowser";
    }

    return "unknown";
  }

  function maybeLogPublicTrafficVisit(req, path) {
    stats.total += 1;
    stats.lastPath = path || "-";
    const classification = classifyPublicTrafficRequest(req);
    if (classification === "bot") stats.bot += 1;
    else if (classification === "realBrowser") stats.realBrowser += 1;
    else stats.unknown += 1;

    if (stats.total % PUBLIC_TRAFFIC_SUMMARY_EVERY === 0) {
      addLog(
        `[PUBLIC-TRAFFIC] Summary total=${stats.total} Bot=${stats.bot} RealBrowser=${stats.realBrowser} Unknown=${stats.unknown} errors=${stats.errors} lastPath=${safeLogValue(stats.lastPath, 80)}`
      );
    }
  }

  function maybeLogPublicTrafficError(error, path) {
    stats.errors += 1;
    if (path) stats.lastPath = path;
    if (stats.errors % PUBLIC_TRAFFIC_SUMMARY_EVERY === 0) {
      addLog(`[PUBLIC-TRAFFIC] Summary total=${stats.total} Bot=${stats.bot} RealBrowser=${stats.realBrowser} Unknown=${stats.unknown} errors=${stats.errors} lastPath=${safeLogValue(stats.lastPath, 80)}`);
    }
  }

  app.locals.recordPublicTrafficVisit = maybeLogPublicTrafficVisit;
  app.locals.recordPublicTrafficError = maybeLogPublicTrafficError;
}

// ================== REGISTER ENHANCED ROUTES ==================
const createRegisterEnhancedPublicRoutes = require("../public-routes/registerEnhancedPublicRoutes.js");
const registerEnhancedPublicRoutes = createRegisterEnhancedPublicRoutes({
  PUBLIC_CANONICAL_ALIASES,
  PUBLIC_ENABLE_ANALYTICS,
  addLog,
  app,
  express,
  generateAllPaths,
  generateDummyAPIResponse,
  generateEnhancedSitemap,
  getActivePersona,
  getCurrentPublicPathSet,
  getPublicSiteName,
  hash32,
  isPublicContentSurfaceEnabled,
  renderEnhancedPublicPage,
  resolvePublicBaseUrls,
  rotationSeed,
  servePublicPathResponse
});

function derivePublicPageTitle(routePath = '') {
  return String(routePath)
    .split('/')
    .pop()
    .replace(/-/g, ' ')
    .replace(/^\w/, c => c.toUpperCase()) || 'Home';
}

function servePublicPathResponse(req, res, routePath, persona, seed) {
  const normalizedPath = String(routePath || '').toLowerCase();
  const acceptHeader = String(req.headers.accept || '').toLowerCase();
  const hasJsonExtension = normalizedPath.endsWith('.json');
  const isApiPath = normalizedPath.startsWith('/api/');
  const wantsJson = acceptHeader.includes('application/json');

  if (isApiPath || hasJsonExtension || wantsJson) {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-cache');
    return res.send(generateDummyAPIResponse(routePath, persona, `${seed}:${routePath}`));
  }

  const pageTitle = derivePublicPageTitle(routePath);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=300');

  return res.send(renderEnhancedPublicPage(req, {
    path: routePath,
    title: pageTitle,
    summary: `${persona.name} - ${pageTitle}`
  }));
}

let cachedPublicPathState = {
  key: '',
  paths: new Set()
};

function getCurrentPublicPathSet() {
  const persona = getActivePersona();
  const seed = rotationSeed();
  const cacheKey = `${persona.sitekey}:${seed}`;

  if (cachedPublicPathState.key !== cacheKey) {
    cachedPublicPathState = {
      key: cacheKey,
      paths: new Set(generateAllPaths(persona, seed))
    };
  }

  return { persona, seed, paths: cachedPublicPathState.paths };
}

function shouldHandleAsDynamicPublicPath(req) {
  const publicSurfaceEnabled = isPublicContentSurfaceEnabled();
  if (!publicSurfaceEnabled) return false;

  if (!['GET', 'HEAD'].includes(req.method)) return false;

  const pathname = String(req.path || '');
  if (!pathname || pathname === '/') return false;

  const reservedPrefixes = [
    '/challenge',
    '/ts-client-log',
    '/interstitial-human',
    '/stream-log',
    '/view-log',
    '/__debug',
    '/admin',
    '/health',
    '/turnstile-sitekey',
    '/decrypt-challenge-data',
    '/e/',
    '/r'
  ];

  return !reservedPrefixes.some((prefix) => pathMatchesWithOptionalPrefix(pathname, prefix));
}


  return {
    PUBLIC_CONTENT_SURFACE,
    PUBLIC_SITE_BASE_URL,
    PUBLIC_ROTATION_MODE,
    PUBLIC_ENABLE_BACKGROUND,
    PUBLIC_TRAFFIC_SUMMARY_EVERY,
    isPublicContentSurfaceEnabled,
    getActivePersona,
    PUBLIC_CORE_MARKETING_PATHS,
    PUBLIC_CANONICAL_ALIASES,
    generateAllPaths,
    startPublicBackgroundTraffic,
    registerEnhancedPublicRoutes,
    servePublicPathResponse,
    getCurrentPublicPathSet,
    shouldHandleAsDynamicPublicPath
  };
}

module.exports = createPublicContent;
