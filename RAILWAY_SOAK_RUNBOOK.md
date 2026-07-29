# Railway Stability / Leak Verification Runbook

## 1) Runtime gauges now available
The app exposes these in `GET /health` and `GET /healthz` under `stats.resources`:
- `openSockets`
- `sseListeners`
- `logFileQueueLines`
- `logFileQueueBytes`
- `logFileDroppedLines`
- `logFileDrainPending`
- `logFileStreamReady`

Also monitor existing:
- `stats.memory` (`rssMb`, `heapUsedMb`, `heapTotalMb`, `externalMb`, `arrayBuffersMb`)
- `stats.maxObservedEventLoopLagMs`
- `stats.inFlightRequests`
- `stats.serverErrors`, `stats.serverClientErrors`, `stats.requestTimeouts`

## 2) Synthetic soak test (30–120 mins)
Run against deployed URL:

```bash
node tests/soak-test.js \
  --url https://<your-service>.up.railway.app/health \
  --duration-min 60 \
  --concurrency 8 \
  --rps 20 \
  --timeout-ms 8000
```

The script prints minute summaries and a final JSON with:
- error rate (`5xx + network`) and latency percentiles (`p50/p95/p99`)
- tail samples of runtime gauges from health endpoint

Suggested pass gates:
- error rate < 1%
- no monotonic increase in `rssMb` without leveling
- `openSockets`, `logFileQueueBytes`, and `logFileDroppedLines` stay bounded

## 3) Railway diagnostics to review
In Railway deployment/service metrics & events, inspect:
- restart reason (manual / crash / OOM / platform)
- OOM events and memory ceiling usage
- CPU throttling / sustained high CPU
- concurrent requests and spikes around failures

Correlate timestamps with app logs:
- `[ALERT:RUNTIME] ...`
- `[HEALTH] event-loop-lag=...`
- `[PROCESS] ...` / `[SERVER] ...`
- `[SHUTDOWN] ...`


## 4) Restart / SIGTERM evidence that survives the current boot
When Railway stops a container, `npm` may print `signal SIGTERM` and its debug file under `/root/.npm/_logs` can disappear with the old container filesystem. This app now records its own shutdown/fatal snapshots before exiting.

Admin endpoint:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://<your-service>.up.railway.app/__debug/runtime-incidents
```

The response includes:
- current boot snapshot (`boot`)
- recent persisted shutdown/fatal incidents (`incidents`)
- paths for `incidentFile`, `npmDebugLogDir`, and the configured visitors log (`logFile`)
- any npm debug logs still visible to the current container

To read `visitors.log` from Railway through the app, use the admin-only log endpoint:

```bash
# Tail the latest 200 KiB by default
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://<your-service>.up.railway.app/__debug/log-file

# Download the whole file
curl -L -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://<your-service>.up.railway.app/__debug/log-file?download=1" \
  -o visitors.log
```

The app automatically creates the parent directory for `LOG_FILE` (for example `/data/logs`) before opening `visitors.log`, which prevents `ENOENT: no such file or directory` when the directory is missing but the filesystem is writable.

Recommended Railway env for longer retention is to point diagnostics at a mounted persistent volume:

```env
RUNTIME_DIAG_DIR=/data/runtime-diagnostics
RUNTIME_INCIDENT_READ_MAX_BYTES=1048576
LOG_DIR=/data/logs
LOG_TO_FILE=1
LOG_FILE=/data/logs/visitors.log
```

Without a persistent Railway volume, these diagnostics still help during the current container lifetime, but platform replacement can remove files from the previous container.


## 5) Interpreting `Starting Container` followed by `Stopping Container`
A log sequence like this usually means Railway started a newer deployment, waited for its healthcheck to pass, and then sent `SIGTERM` to the older deployment so it could drain and exit cleanly:

```text
[HEALTH] turnstile HEAD 200 ok (change)
Starting Container
Stopping Container
[SHUTDOWN] Received SIGTERM; closing server ...
[SHUTDOWN] server closed cleanly
```

That is not, by itself, an app crash. In this app, a crash/fatal path logs `[FATAL]`, `[PROCESS] uncaughtException`, `[PROCESS] unhandledRejection`, or `[SERVER] error`; a clean deploy replacement logs `[SHUTDOWN] Received SIGTERM` followed by `[SHUTDOWN] server closed cleanly`.

Railway can interleave log lines from old and new replicas in the same deployment view, so `server closed cleanly` and `Received SIGTERM` may appear visually out of order. Compare the `bootId=...`, `deploymentId=...`, and `replicaId=...` values printed on shutdown/fatal lines to confirm which process produced each line.

The startup summary and incident snapshots include Railway-provided deployment metadata such as `RAILWAY_DEPLOYMENT_ID`, `RAILWAY_REPLICA_ID`, `RAILWAY_SERVICE_ID`, `RAILWAY_GIT_COMMIT_SHA`, and draining/overlap settings when Railway injects them. Use these values to tell whether the `Stopping Container` line belongs to the old deployment while the `Starting Container` line belongs to the new deployment.

Railway variables worth checking if clean SIGTERM shutdowns are too abrupt:

```env
RAILWAY_DEPLOYMENT_OVERLAP_SECONDS=20
RAILWAY_DEPLOYMENT_DRAINING_SECONDS=30
```

Keep `SHUTDOWN_GRACE_MS` less than or equal to Railway's draining window so the app can finish `server.close()` before Railway sends `SIGKILL`.

## 6) Production tuning knobs
Start with defaults, then tune if needed:

```env
LOG_FILE_QUEUE_MAX_LINES=5000
LOG_FILE_QUEUE_MAX_BYTES=2097152
LOG_FILE_QUEUE_WARN_BYTES=1048576
OPEN_SOCKETS_WARN_THRESHOLD=400
SSE_LISTENERS_WARN_THRESHOLD=120
SHUTDOWN_GRACE_MS=10000
```

If pressure persists:
- increase `SHUTDOWN_GRACE_MS` (e.g. 15000)
- lower log volume/sampling in noisy paths
- increase service memory/CPU plan

## 7) File log rotation
File log rotation follows `LOG_TO_FILE` automatically:

- `LOG_TO_FILE=0` disables file writing and rotation. Logs still go to stdout/Railway logs.
- `LOG_TO_FILE=1` enables file writing and size-based rotation.

The active log rotates after reaching `LOG_FILE_MAX_BYTES`. Numbered archives are retained as
`visitors.log.1`, `visitors.log.2`, and so on, up to `LOG_FILE_MAX_FILES` archives. If the configured
archive count is reduced, the next rotation removes older numbered archives above the new limit.

Recommended starting values:

```env
LOG_TO_FILE=1
LOG_FILE=/data/logs/visitors.log
LOG_FILE_MAX_BYTES=52428800
LOG_FILE_MAX_FILES=5
```

With these values, disk use is bounded to approximately six 50 MiB files: the active file plus five archives.
