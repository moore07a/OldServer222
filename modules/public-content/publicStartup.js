module.exports = function createPublicStartup(dependencies) {
  const {
    PUBLIC_CONTENT_SURFACE, PUBLIC_ENABLE_BACKGROUND, PUBLIC_TRAFFIC_SUMMARY_EVERY,
    PUBLIC_CORE_MARKETING_PATHS, PUBLIC_ROTATION_MODE, generateAllPaths, getActivePersona,
    isPublicContentSurfaceEnabled, registerEnhancedPublicRoutes, rotationSeed,
    startPublicBackgroundTraffic
  } = dependencies;
function initEnhancedPublicContent() {
  if (!isPublicContentSurfaceEnabled()) return;

  // Register all routes
  registerEnhancedPublicRoutes();

  // Start background traffic
  startPublicBackgroundTraffic();
}

function publicContentStartupSummaryLines() {
  const publicSurfaceEnabled = isPublicContentSurfaceEnabled();
  const backgroundTrafficEnabled = PUBLIC_ENABLE_BACKGROUND && PUBLIC_CONTENT_SURFACE;
  const publicForce = String(process.env.PUBLIC_CONTENT_SURFACE_FORCE || '').trim() ? 'set' : 'unset';
  const publicExplicit = String(process.env.PUBLIC_CONTENT_SURFACE || '').trim() ? 'set' : 'unset';
  const lines = [
    `[PUBLIC-CONTENT] Effective enabled=${publicSurfaceEnabled} declared=${PUBLIC_CONTENT_SURFACE} force=${publicForce} explicit=${publicExplicit}`
  ];

  if (!publicSurfaceEnabled) {
    lines.push("[PUBLIC-CONTENT] Disabled by safe default (set PUBLIC_CONTENT_SURFACE=1 or PUBLIC_CONTENT_SURFACE_FORCE=1 to enable)");
    return lines;
  }

  const persona = getActivePersona();
  const allPaths = generateAllPaths(persona, rotationSeed());
  const allPathSet = new Set(allPaths);
  const missingCore = PUBLIC_CORE_MARKETING_PATHS.filter(path => !allPathSet.has(path));
  const missingFooter = (persona.footerLinks || [])
    .map(link => link && link.path)
    .filter(path => path && path !== '/' && !allPathSet.has(path));

  lines.push(`[PUBLIC-CONTENT] Active persona: ${persona.name} (${persona.sitekey})`);
  lines.push(`[PUBLIC-CONTENT] Generated ${allPaths.length} unique paths, rotation=${PUBLIC_ROTATION_MODE}`);
  if (missingCore.length || missingFooter.length) {
    lines.push(`[PUBLIC-CONTENT] ⚠️ Path coverage gaps core=[${missingCore.join(',') || '-'}] footer=[${missingFooter.join(',') || '-'}]`);
  }
  if (backgroundTrafficEnabled) {
    lines.push(`[PUBLIC-TRAFFIC] Real inbound traffic observer started (persona: ${persona.sitekey})`);
    lines.push(`[PUBLIC-TRAFFIC] Summary logging every ${PUBLIC_TRAFFIC_SUMMARY_EVERY} visits/errors`);
  } else {
    lines.push(`[PUBLIC-TRAFFIC] Real inbound traffic observer disabled (PUBLIC_ENABLE_BACKGROUND=${PUBLIC_ENABLE_BACKGROUND}, PUBLIC_CONTENT_SURFACE=${PUBLIC_CONTENT_SURFACE})`);
  }
  return lines;
}

  return { initEnhancedPublicContent, publicContentStartupSummaryLines };
};
