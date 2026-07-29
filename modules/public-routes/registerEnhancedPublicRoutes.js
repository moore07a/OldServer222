"use strict";

function createRegisterEnhancedPublicRoutes(dependencies) {
  const {
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
  } = dependencies;

  return function registerEnhancedPublicRoutes() {
  const publicSurfaceEnabled = isPublicContentSurfaceEnabled();
  if (!publicSurfaceEnabled) return;

  const persona = getActivePersona();
  const allPaths = generateAllPaths(persona, rotationSeed());
  const publicPathSet = new Set(allPaths);
  const seed = rotationSeed();

  app.use((req, res, next) => {
    if ((req.method || "GET").toUpperCase() !== "GET") return next();

    const path = req.path || "/";
    if (path !== "/") {
      const { paths: currentPathSet } = getCurrentPublicPathSet();
      const isServedPublicRoute = publicPathSet.has(path) || currentPathSet.has(path);
      if (!isServedPublicRoute) return next();
    }

    try {
      if (typeof app.locals.recordPublicTrafficVisit === "function") {
        app.locals.recordPublicTrafficVisit(req, path);
      }
    } catch (error) {
      if (typeof app.locals.recordPublicTrafficError === "function") {
        app.locals.recordPublicTrafficError(error, path);
      }
    }
    next();
  });

  // ===== STATIC PAGES =====
  // Homepage
  app.get('/', (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderEnhancedPublicPage(req, { path: '/', title: 'Home' }));
  });

  // Register canonical public aliases before generated paths/catch-all handling.
  PUBLIC_CANONICAL_ALIASES.forEach((targetPath, aliasPath) => {
    app.get(aliasPath, (_req, res) => res.redirect(301, targetPath));
  });

  // Register ALL generated paths
  allPaths.forEach(path => {
    app.get(path, (req, res) => servePublicPathResponse(req, res, path, persona, seed));
  });

  // ===== API ENDPOINTS - ✅ DEDICATED STATUS ENDPOINT with PUBLIC_SITE_NAME =====
app.get("/api/v1/status", (req, res) => {
  const mem = process.memoryUsage();
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-cache");
  res.json({
    service: getPublicSiteName(persona),
    status: "operational",
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    version: `v${hash32(`${seed}:version`) % 4 + 1}.0.0`,
    metrics: {
      dailyRequests: hash32(`${seed}:requests`) % 90000 + 10000,
      uptime: (99.9 + (hash32(`${seed}:uptime`) % 10) / 100).toFixed(2) + '%',
      latency: (hash32(`${seed}:latency`) % 40 + 15).toFixed(0) + 'ms'
    },
    persona: {
      name: persona.name,
      sitekey: persona.sitekey
    }
  });
});

  persona.apiEndpoints.forEach(endpoint => {
    app.get(endpoint, (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-cache');
      res.send(generateDummyAPIResponse(endpoint, persona, `${seed}:${endpoint}`));
    });
  });

  // ===== ANALYTICS COLLECTOR =====
  if (PUBLIC_ENABLE_ANALYTICS) {
    app.post('/_collect', express.json({ limit: '2kb' }), (req, res) => {
      // Silently collect analytics
      res.status(204).end();
    });

    app.post('/_interact', (req, res) => {
      // Track interaction
      res.status(204).end();
    });

    // 1x1 transparent GIF for legacy tracking
    app.get('/_analytics.gif', (req, res) => {
      res.setHeader('Content-Type', 'image/gif');
      res.setHeader('Cache-Control', 'no-store, max-age=0');
      res.send(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'));
    });
  }

  // ===== SITEMAP =====
app.get("/sitemap.xml", (req, res) => {
  const sitemapPaths = [...allPaths];
  const sitemap = generateEnhancedSitemap(req, persona, sitemapPaths);

  res.setHeader('Content-Type', 'application/xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=900');
  res.send(sitemap);

  addLog(`[SITEMAP] Generated ${sitemapPaths.length} candidate paths for ${persona.name}`);
});

  // ===== ROBOTS.TXT =====
  app.get('/robots.txt', (req, res) => {
    const baseUrls = resolvePublicBaseUrls(req, { requestHostOnly: true, preferConfiguredCanonical: true });
    const sitemapUrl = `${baseUrls[0]}/sitemap.xml`;

    const robots = `User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/internal/
Disallow: /_analytics
Disallow: /_collect
Disallow: /_interact

# Sitemap location
Sitemap: ${sitemapUrl}

# Crawl settings
Crawl-delay: 1

# Special directives for specific bots
User-agent: Googlebot
Allow: /blog/
Allow: /docs/

User-agent: Bingbot
Allow: /blog/
Allow: /docs/

User-agent: AhrefsBot
Crawl-delay: 2

User-agent: SemrushBot
Crawl-delay: 2`;

    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(robots);
  });

  // ===== FAVICON =====
  app.get('/favicon.ico', (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.status(204).end();
  });
}
}

module.exports = createRegisterEnhancedPublicRoutes;
