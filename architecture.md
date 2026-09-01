# Architecture

## The layer stack

Bottom to top. Layers 2 and 3 are the project. Everything else is configuration.

| Layer | What it is | Components |
|---|---|---|
| 1 · Physical WAN | Independent internet connections | Starlink Roam, 5G modem(s), campground wifi |
| 2 · Overlay | One WireGuard tunnel per WAN link | WireGuard |
| 3 · Path selection | Measurement and steering. **The project.** | Custom daemon |
| 4 · Policy and QoS | Classification, shaping, admission control | nftables, CAKE |
| 5 · Observability | Per-path telemetry, UI, metrics | Custom UI, vnstat, Prometheus |
| 6 · Applications | Rides the transport | Zoom, Maps, browsers |

### Why one tunnel per link

All tunnels terminate at the same home endpoint on the same UDP port. This gives the
scheduler N paths with identical addressing, so steering becomes "which tunnel do I
send out of" rather than a re-addressing problem. Without it, a link failover changes
the source IP and breaks every TCP session.

Path identity lives in the daemon's own header, not in the port number.

### Why everything is tunneled

Decided explicitly. See `decisions.md` D-004. Costs a hairpin on public SaaS traffic;
buys a single measurement domain, stable source IP for every flow, consistent DNS and
NAT behavior, and one policy surface to debug.

## Endpoint roles

The two ends are not symmetric, and this shapes install.

**Home is the responder.** Fixed location, stable power, publicly reachable. Never
initiates. Needs one forwarded UDP port and dynamic DNS.

**RV is the initiator.** Behind carrier CGNAT on every link, never directly reachable.
Always dials out on every path and keeps sessions alive with `PersistentKeepalive`
at 25 seconds. CGNAT mappings expire in 30 to 60 seconds; without keepalives an idle
path dies silently.

## Hardware

**Home server** — 4 cores x86, 16 GB RAM, ZFS mirror. Wired connection. The home
upstream is on the critical path for every packet, so its upload capacity and
bufferbloat matter more than people expect. Run CAKE on the home side too.

**RV client** — fanless N100 mini PC, 16 GB RAM, 1–2 TB NVMe. Native 12 V DC input is
important: running an inverter to make 120 V AC to feed a 19 V brick wastes 15 to 20%
of battery. Budget 6–10 W idle, ~25 W under load. Needs clean shutdown when house
batteries sag.

A Pi 5 works and draws less, but the N100 gives x86 compatibility and better I/O for
similar real-world draw once storage is added.

**Operating system** — Debian stable on both ends. Minimal install. Unattended-upgrades
restricted to security only, so the system is not pulling packages over a metered LTE
link. Long support windows mean fewer forced updates in the field.

OpenWrt on the RV router if a separate router is used.

## Link characteristics

The two primary links fail in completely different ways, and both expose out-of-band
health signals that lead the packet-level measurements.

**Starlink** obstructs abruptly and binarily. A canyon wall or canopy cuts it with no
warning in the loss statistics. The dish exposes gRPC telemetry including an obstruction
map and current obstruction state — poll it and use it as a **demotion** trigger.
Starlink also does periodic satellite handovers producing latency spikes even under
clear sky, which is why percentile tracking matters and means do not.

**Cellular** degrades gradually. RSRP and SINR decline measurably as you approach an
obstruction, giving roughly 10 to 30 seconds of warning. `mmcli` (ModemManager) exposes
these.

Use out-of-band signals to demote early. Never use them to promote — promotion requires
measured performance.

## Home-side networking

Routed subnet, **not double-NAT**. Give the RV LAN its own prefix (e.g. 10.20.0.0/24) and
route it at home, so home can always reach an RV device directly by its LAN address —
that reachability is never NATed away in either direction.

For the RV LAN's own traffic to the wider internet, NAT **once**, at the home internet
edge, by default. This is what makes "no split tunneling" (see `CLAUDE.md`) actually mean
something: an RV LAN client's default route goes into the tunnel, home forwards and
masquerades it out its own connection, and the client never touches its local WAN links
directly for anything but the tunnel itself.

Double NAT (i.e. NATing again at the RV before the tunnel) breaks reaching RV devices
from home, breaks peer-to-peer, and makes packet captures much harder to read — that stays
disallowed regardless of the internet-egress NAT setting above. Keep the internet-egress
NAT boundary configurable; it defaults to **on**. See D-013 for how to turn it off.

## Traffic classes

Two classes. Classification described in `protocol.md`.

**Real-time** — conferencing media. Single path, no resequencing, no hold buffer.
Delivered as fast as possible; out-of-order is fine because the application has its own
jitter buffer. Make-before-break on path changes. Optional duplication across paths.

**Bulk** — everything else. Multipath with resequencing (deferred to v2, see
`scope-v1.md`). Elastic, deferrable, and explicitly sacrificial when capacity is short.

### What each application needs

|  | Zoom audio | Zoom video | Maps | Web |
|---|---|---|---|---|
| Latency | critical | matters | tolerant | tolerant |
| Loss | duplicate it | conceal | retry | retry |
| Bandwidth | trivial (~40 kbps) | significant | small bursts | elastic |
| On degradation | protect at all cost | let it shrink | cached | starve it |

## MTU

Underlying link MTU varies and changes in flight — carriers alter it on tower handover
and on 5G-to-LTE fallback.

- Measure per path with **PLPMTUD** (RFC 8899). Do not rely on classic PMTUD; cellular
  networks and CGNAT drop the ICMP that it depends on, producing silent blackholes.
- Probe by padding control packets and confirming receipt via the existing echo channel.
- Re-probe on path state transitions, not just at boot.
- **Use the minimum across all eligible paths as a single global tunnel MTU.** A packet
  sized for a large path cannot be moved to a small one, which would break steering and
  make-before-break exactly when needed.
- Exclude `down` paths from the minimum. A dead modem should not cost efficiency on a
  healthy link.
- Asymmetric hysteresis: **lower immediately, raise slowly.** Require a larger MTU to
  hold for several minutes before growing the tunnel.
- **Floor at 1280** (IPv6 minimum link MTU). Never go below. A path that cannot carry
  1280 is broken and should be flagged, not accommodated.
- Overhead budget: outer IPv4+UDP 28 B, WireGuard 32 B, daemon header ~16–20 B. Roughly
  80 B total. A 1420 B path leaves ~1340 B inner.
- Clamp TCP MSS at tunnel ingress. QUIC does its own DPLPMTUD. RTP audio is small enough
  that MTU never binds it.
- **Never rely on IP fragmentation.** Carriers drop fragments unpredictably. If an
  oversized inner packet must be carried, fragment at the daemon layer where reassembly
  is under our control.

## Cost-aware path roles

Roles are inputs to the scoring penalty, **not a static ranking**.

- **Primary** — Starlink Roam. Best performance, hard 100 GB cap on the non-throttled tier.
- **Secondary** — 5G. Plan-dependent cap, often lower latency than Starlink, coverage-dependent.
- **Backup** — campground/public wifi. Free, unpredictable, frequently behind a captive portal.

Track per link per billing cycle (cycle start date configurable per link, carriers do
not align):

```
burn_rate = used / days_elapsed
projected = burn_rate * days_in_cycle
headroom  = cap - projected
```

Three bands driving `penalty_i`:

- **Green** (>20% projected headroom) — normal. Duplicate freely, bulk goes anywhere.
- **Yellow** (projected to exceed) — real-time still allowed, duplication disabled on
  this link, bulk excluded from it.
- **Red** (cap effectively spent) — emergency only. Real-time allowed if it is the sole
  viable path; a working call beats an overage. Nothing else.

**Sacrifice order: duplication first, bulk second, real-time last.** Duplication is by
definition redundant, so cutting it costs resilience but not function.

`vnstat` provides the accounting.

### Free wifi is a budget recovery mechanism

When parked with usable wifi, drain deferred bulk transfers onto it and rest the metered
links. This means bulk should be **deferrable**, not merely deprioritized — backups,
updates, and large downloads queue until an unmetered path appears.

Two cautions: captive portals will trip the tunnel-everything design, so portal detection
and pre-tunnel authentication are needed. And campground wifi is often worse than LTE, so
it must never win the scheduler on performance alone. Free but suspect.

## Fallback

If the daemon dies or the tunnel is unrecoverable, dump traffic directly onto the
best link. Not a corporate scenario, so unencrypted direct egress is acceptable — no
fail-closed traffic class is needed.

- Trigger requires **sustained** tunnel failure (15–30 s), not a transient.
- Exit requires longer (~60 s of stable tunnel). Every transition breaks NAT state and
  kills in-flight sessions, so flapping in and out is worse than staying in fallback.
- **Link choice must be deterministic.** The scheduler is the thing that died, so it
  cannot be asked. The scheduler continuously writes its current ranking to a file;
  the fallback script reads that file. Stale or missing file falls back to a static
  configured order. Never leave the choice undefined.
- Implement in nftables rules that persist independently of the daemon.

## Management UI

Local web interface. Must remain useful when the scheduler has crashed, because that is
exactly when it is needed.

- **Separate process**, supervised independently.
- **Reads from a state file**, not IPC to a live daemon. Show a staleness timestamp.
  A dead scheduler yields stale-but-visible data, which is what diagnosis requires.
- **Bound to a fixed LAN IP** on the bridge. Reachable with no routing or tunnel working.
- Can restart the scheduler, force a link state, and trigger fallback manually.
- **Log access from the UI** — reading the last few minutes of path-state transitions
  without SSH is the difference between diagnosing and guessing.
- Small Go binary serving static HTML plus a JSON endpoint. No framework, no build step.
- Expose the same state as a Prometheus endpoint. Nearly free on top of the JSON, and
  gives historical graphing from the home server when connectivity permits.

## Prior art worth reading

Not for reuse, for design lessons.

- **mlvpn** (GPL) — multi-link VPN with reordering, built by a French ISP.
- **ZeroTier multipath bonding** — has link-quality scoring.
- **MPTCP schedulers** — minRTT, BLEST, ECF solve exactly this decision function.
- **babeld** — routing protocol for lossy wireless mesh; its metric hysteresis is a good
  model for the state machine.
- **VMware VeloCloud DMPO** — the closest commercial equivalent. Confirms the hybrid
  active/passive approach, sub-second steering, per-packet steering with owned endpoints,
  MOS-based composite scoring, adaptive (not always-on) error correction, and first-packet
  classification with a flow cache. Note the product has changed corporate hands recently;
  verify current status if it matters.

The one thing VeloCloud does that cannot be copied: a global network of gateways sitting
near major SaaS destinations. Our far end is a house, so we eat a hairpin. A cheap VPS
near the usual conferencing region could serve as an alternative tunnel head later
without changing the architecture.
