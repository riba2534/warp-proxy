# Changelog

## v1.1.0

WARP failures now propagate to the supervisor instead of leaving a live proxy
listener backed by a failed daemon. This release keeps Cloudflare WARP pinned
at 2026.7.1377.0 so wrapper changes can be evaluated independently.

- Reap daemon processes and exit on unexpected child termination; clean up on
  startup errors and handle shutdown while initialization is still in progress.
- Recover from sustained trace failures after configurable startup grace and a
  consecutive failure threshold. Docker restart policy performs the restart.
- Cancel SOCKS handshakes within the health request deadline, share concurrent
  health probes, and reserve time for fallback targets.
- Enforce initialization and CLI deadlines, and verify registration through the
  daemon instead of treating a settings file as proof of registration.
- Close both TCP sockets on abnormal copy errors while preserving normal
  half-close semantics. Bound admitted connections and synchronize shutdown.
- Redact license values from CLI errors. Correct the milliseconds JSON field.
- Apply wrapper log levels, bind sample ports to loopback, and rotate Docker
  logs. Official daemon logging is managed separately.
- Pin base images and WARP package, update x/net, include binary release/source
  metadata, and publish version tags while main pushes run validation only.
- Add cancellation, reset, timeout, process recovery and resource-limit tests.

The duration field correction changes monitoring values from nanoseconds to
milliseconds. Existing deployments should keep the WARP data volume. The Go
wrapper cannot guarantee Cloudflare tunnel availability or eliminate official
client memory pressure; verify a canary before rolling out to additional hosts.
