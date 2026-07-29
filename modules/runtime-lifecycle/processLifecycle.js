"use strict";

module.exports = function createProcessLifecycle(dependencies) {
  const {
    LOG_LISTENERS, SHUTDOWN_GRACE_MS, activeTrackedRequests, addLog,
    buildActiveRequestDiagnostics, clearBackgroundTasks, closeLogFileWriter,
    formatRuntimeCorrelationSuffix, getProcessRuntimeMetadata,
    getRuntimeCorrelationMetadata, logActiveRequestDiagnostics, openSockets,
    recordRuntimeIncident, runtimeStats, safeLogValue, server, summarizeError
  } = dependencies;

  let fatalExitScheduled = false;
  function scheduleFatalExit(origin, details) {
    if (fatalExitScheduled) return;
    fatalExitScheduled = true;

    const summary = safeLogValue(summarizeError(details), 180);
    const correlation = formatRuntimeCorrelationSuffix();
    recordRuntimeIncident("fatal", { origin, summary, correlation: getRuntimeCorrelationMetadata() });
    addLog(`[FATAL] ${safeLogValue(origin, 64)} scheduling process exit ${correlation} summary=${summary}`);

    setImmediate(() => {
      process.exitCode = 1;
      process.exit(1);
    });
  }

  let isShuttingDown = false;
  let forcedShutdownTimedOut = false;
  async function gracefulShutdown(signal) {
    runtimeStats.shutdownSignals += 1;

    if (isShuttingDown) {
      const correlation = formatRuntimeCorrelationSuffix();
      recordRuntimeIncident("shutdown_signal_while_closing", { signal, correlation: getRuntimeCorrelationMetadata() });
      addLog(`[SHUTDOWN] Received additional ${signal} while already closing (${correlation}); waiting for existing graceful shutdown`);
      return;
    }

    isShuttingDown = true;

    const uptimeSec = Math.round(process.uptime());
    const mem = process.memoryUsage();
    const rssMb = Math.round((mem.rss / (1024 * 1024)) * 100) / 100;
    const trackedInFlight = activeTrackedRequests.size;
    const correlation = formatRuntimeCorrelationSuffix();
    const activeRequestSnapshot = buildActiveRequestDiagnostics();
    recordRuntimeIncident("shutdown", {
      signal,
      source: "external_signal",
      note: "SIGTERM/SIGINT is delivered by the process supervisor, container runtime, npm parent, or user; it is not thrown by application code.",
      graceMs: SHUTDOWN_GRACE_MS,
      rssMb,
      trackedInFlight,
      activeRequests: activeRequestSnapshot,
      process: getProcessRuntimeMetadata(),
      correlation: getRuntimeCorrelationMetadata()
    });
    addLog(`[SHUTDOWN] Received ${signal} from external supervisor/runtime; closing server (${correlation} grace=${SHUTDOWN_GRACE_MS}ms uptimeSec=${uptimeSec} rssMb=${rssMb} trackedInFlight=${trackedInFlight} pid=${process.pid} ppid=${process.ppid})`);
    if (trackedInFlight > 0) logActiveRequestDiagnostics("shutdown");

    clearBackgroundTasks();
    activeTrackedRequests.clear();
    runtimeStats.inFlightRequests = 0;

    // End SSE log listeners before waiting on server.close(); long-lived streams can
    // otherwise keep the server open indefinitely and force timeout exits.
    for (const listenerRes of LOG_LISTENERS) {
      try { listenerRes.end(); } catch {}
    }

    const forceExitTimer = setTimeout(async () => {
      forcedShutdownTimedOut = true;
      recordRuntimeIncident("shutdown_forced", { signal, graceMs: SHUTDOWN_GRACE_MS, openSockets: openSockets.size, correlation: getRuntimeCorrelationMetadata() });
      addLog(`[SHUTDOWN] force exit after grace timeout (${correlation} grace=${SHUTDOWN_GRACE_MS}ms)`);
      for (const socket of openSockets) {
        try { socket.destroy(); } catch {}
      }
      await closeLogFileWriter(Math.min(2000, SHUTDOWN_GRACE_MS));
      process.exit(1);
    }, SHUTDOWN_GRACE_MS);

    server.close(async () => {
      clearTimeout(forceExitTimer);

      if (forcedShutdownTimedOut) {
        addLog(`[SHUTDOWN] server closed after grace timeout; preserving forced exit status (${correlation})`);
        return;
      }

      addLog(`[SHUTDOWN] server closed cleanly (${correlation})`);
      await closeLogFileWriter(Math.min(2000, SHUTDOWN_GRACE_MS));
      process.exit(0);
    });

    if (typeof server.closeIdleConnections === "function") {
      try { server.closeIdleConnections(); } catch {}
    }
  }

  return { gracefulShutdown, scheduleFatalExit };
};
