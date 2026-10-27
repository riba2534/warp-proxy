# Changelog

## v2.0.0

Cloudflare's `warp-svc` is gone. Its local proxy mode only supports MASQUE and its
resident memory grows with uptime (25–45 MB a day on every host we measured,
independent of traffic), so v2 talks WireGuard to Cloudflare WARP directly.

- Register a WARP device over Cloudflare's consumer API (protocol and TLS
  fingerprint as in wgcf) and keep it in `wireguard-account.json` (0600) in the
  existing data volume. The cached device config is used when the API is down.
- Bring up WireGuard inside the container's network namespace: kernel first,
  `wireguard-go` on `/dev/net/tun` when the kernel lacks the module. Policy
  routing (table 22337, mark 0x57415250, interface `warp0`) sends only the
  proxy's own marked sockets through the tunnel; replies to clients, Docker DNS
  and WireGuard's own UDP keep the normal routes, strict `rp_filter` hosts work,
  and a missing tunnel address family is unreachable rather than leaking. Only
  links and rules tagged as ours are ever cleaned up.
- Replace the L4 forwarder with a proxy server that speaks SOCKS5, SOCKS4/4a and
  HTTP CONNECT on one port (what `warp-svc` accepted), resolves names through
  Cloudflare DNS inside the tunnel and refuses loopback, private, link-local,
  CGNAT and multicast destinations unless `ALLOW_PRIVATE_DESTINATIONS=true`.
- Rotate Cloudflare endpoints in place, with a fresh handshake: at startup
  after 6s without a handshake, later from the second failed probe. Open
  connections are usually reset when the traffic moves to another Cloudflare
  edge, but the process and the tunnel stay up. Exit after `RECOVERY_FAILURES`
  consecutive failures, and only once a rotation was tried and given its 6s,
  so Docker restarts the container as before;
  `RECOVERY_FAILURES=0` keeps probing and rotating without exiting.
  `CONNECT_TIMEOUT` now defaults to 90s so every endpoint candidate gets a turn
  on networks that block some WireGuard ports.
- A WARP+ license that cannot be applied is logged and the proxy keeps running
  on the current account, as in v1.
- `/status` adds a `tunnel` object (mode, endpoint, last handshake, bytes);
  `warp_status` and `forwarder_stats` keep their names.
- The image is a static binary on distroless (about 20 MB instead of 1.25 GB).
  New settings: `WG_MODE`, `WG_INTERFACE`, `WG_MTU`, `WG_ENDPOINT`,
  `DNS_SERVERS`, `ALLOW_PRIVATE_DESTINATIONS`, `DIAL_TIMEOUT`, `WARP_DATA_DIR`;
  `WARP_SVC_HOST` and `WARP_SVC_PORT` are gone. New flag `-unregister`.

Upgrading creates a new WARP device, so the egress IP changes. Keep the data
volume; v1 files are left untouched, so rolling back to v1.1.0 still works.
The image has no shell any more: health checks must use the exec form
(`["CMD", "/usr/local/bin/warp-proxy", "-healthcheck"]`), not `CMD-SHELL`.

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
