# Changelog

## v2.0.0

Cloudflare's `warp-svc` is gone. Its local proxy mode only supports MASQUE and its
resident memory grows with uptime (25–45 MB a day on every host we measured,
independent of traffic), so v2 talks WireGuard to Cloudflare WARP directly.

- Register a WARP device over Cloudflare's consumer API (protocol and TLS
  fingerprint as in wgcf) and keep it in `wireguard-account.json` (0600) in the
  existing data volume. The cached device config is used when the API is down.
- Bring up WireGuard inside the container's network namespace: kernel first,
  `wireguard-go` on `/dev/net/tun` when the kernel lacks the module. wg-quick
  style fwmark policy routing sends all egress through the tunnel while the
  container's own subnets keep working.
- Replace the L4 forwarder with a proxy server that speaks SOCKS5, SOCKS4/4a and
  HTTP CONNECT on one port (what `warp-svc` accepted), resolves names through
  Cloudflare DNS inside the tunnel and refuses loopback, private, link-local,
  CGNAT and multicast destinations unless `ALLOW_PRIVATE_DESTINATIONS=true`.
- Rotate Cloudflare endpoints when the handshake goes stale; exit after
  sustained failures so Docker restarts the container, as before.
- `/status` adds a `tunnel` object (mode, endpoint, last handshake, bytes);
  `warp_status` and `forwarder_stats` keep their names.
- The image is a static binary on distroless (about 15 MB instead of 1.25 GB).
  New settings: `WG_MODE`, `WG_INTERFACE`, `WG_MTU`, `WG_ENDPOINT`,
  `DNS_SERVERS`, `ALLOW_PRIVATE_DESTINATIONS`, `DIAL_TIMEOUT`, `WARP_DATA_DIR`;
  `WARP_SVC_HOST` and `WARP_SVC_PORT` are gone. New flag `-unregister`.

Upgrading creates a new WARP device, so the egress IP changes. Keep the data
volume; v1 files are left untouched, so rolling back to v1.1.0 still works.

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
