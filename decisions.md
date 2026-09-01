# Decision log

Decisions made during scoping, with rationale and rejected alternatives. **Read this
before proposing an alternative approach.** If reopening one, say which decision and why
the reasoning no longer holds.

---

## D-001 · Build a custom path selector rather than adopt an existing one

**Decision.** Layer 3 is custom. Everything else is assembled from existing components.

**Rationale.** mwan3 does health-check failover but not continuous quality-based steering.
babeld has good metric hysteresis but is a routing protocol, not a per-flow scheduler.
Neither combines passive data-plane measurement, inferred queue depth, and traffic-class-aware
steering. That combination is the gap.

**Rejected.** mwan3 alone (too coarse), babeld alone (wrong layer), commercial SD-WAN
(not open source).

---

## D-002 · No sync layer, no queue layer

**Decision.** Dropped from the design.

**Rationale.** Initially scoped when the project looked like data replication. Syncthing
and NATS solve application-layer problems. SD-WAN provides a transport that applications
ride on; it does not move specific data itself.

---

## D-003 · One WireGuard tunnel per WAN link, same home endpoint and port

**Decision.** N tunnels, one endpoint, one UDP port. Path identity in the daemon header.

**Rationale.** Gives the scheduler N paths with identical addressing. Without it, failover
changes the source IP and breaks every TCP session. One port keeps the firewall simple.

---

## D-004 · Tunnel everything, no split tunneling

**Decision.** All traffic through the tunnel. No direct egress for public SaaS.

**Rationale.** Owner's explicit choice, made with the cost understood. One policy surface,
one measurement domain, stable source IP for every flow, consistent DNS and NAT behavior.
Debugging simplicity matters a great deal for a system running unattended in a moving
vehicle.

**Cost accepted.** A hairpin on public SaaS traffic — RV → home → Zoom rather than
RV → Zoom. Roughly 40–60 ms round trip depending on geography, against a 150 ms one-way
budget already partly consumed by codec and jitter buffer. Home upstream capacity and
bufferbloat now sit on the critical path for every packet; run CAKE on the home side too.

**Rejected.** Split policy (hairpin corporate, direct SaaS) — better latency, but two
measurement domains and a likely source of bugs.

**Future option that preserves the decision.** A cheap VPS near the usual conferencing
region as the tunnel head, home as a spoke. Same architecture, better geography.

---

## D-005 · Two sequence numbers, global and per-path

**Decision.** Both in the header.

**Rationale.** Global alone cannot distinguish loss on one path from delayed arrival via
another, because cross-path reordering is normal. Per-path sequence is strictly monotonic,
so gaps are unambiguous loss.

**Note.** Expensive to retrofit. Get it in from the start.

---

## D-006 · Real-time traffic bypasses the resequencer

**Decision.** Real-time class gets single-path delivery with no reorder hold.

**Rationale.** Conferencing apps have their own jitter buffers and packet loss concealment
and prefer losing a packet to waiting for it. A reorder hold stacked on top of their
jitter buffer directly degrades call quality.

---

## D-007 · No FEC

**Decision.** Excluded from v1 and not currently planned.

**Rationale.** Zoom, Teams and WebRTC already run adaptive FEC informed by things the
tunnel cannot see (keyframes, codec concealment behavior). Block FEC costs latency — a
5-packet block over 20 ms audio adds 100 ms before the repair can be sent, most of the
remaining budget. Cellular loss is bursty, which is what block FEC handles worst.

**What to do instead.** Use the congestion-versus-radio-loss discriminator (free from
existing measurements) to drive **bulk shedding**. Shedding costs nothing and fixes
congestion loss, which will be most of the loss seen.

**If reconsidered.** Gate on queue delay: elevated + loss = congestion, where FEC is
actively harmful. Baseline + loss = radio-layer, where it could help. And prefer
**temporal duplication** for audio (each packet twice, offset 30–40 ms) over block FEC —
simpler, no encoding, survives bursts shorter than the offset, 40 kbps cost. Same
mechanism as multipath duplication, offset in time rather than across paths.

**Genuine remaining cases.** Traffic with no protection of its own (SIP softphone, VPN'd
desk phone), and the daemon's own control and measurement packets — losing a path-state
report exactly when a link degrades is the worst time to lose it.

---

## D-008 · No off-the-shelf link bonding

**Decision.** No MPTCP, glorytun, or OpenMPTCProuter.

**Rationale.** Redundant with the custom scheduler. Note this is distinct from D-009 —
this rejects adopting a bonding product, not the concept of using multiple paths for
bulk.

---

## D-009 · Bulk multipath aggregation deferred to v2

**Decision.** v1 bulk uses a single best path. The resequencer comes later.

**Rationale.** The resequencer is the hardest component and the likeliest source of subtle
bugs. Bulk is elastic; single-path bulk is fine for web and updates. Deferring also buys
telemetry that will show how often paths actually land within the delta window where
aggregation pays.

**Status.** A real decision, revisitable once field data exists.

---

## D-010 · Global MTU at minimum across eligible paths

**Decision.** One tunnel MTU, set to the minimum of all non-down paths.

**Rationale.** A packet sized for a large path cannot be moved to a small one. Per-path
MTU would pin oversized packets to one path, destroying make-before-break exactly during
a failover.

**Cost accepted.** One bad link degrades everyone. Campground wifi at 1400 pulls the whole
tunnel down while Starlink sits idle at 1500. Roughly 7% header overhead delta — small.

**Escape valve if it ever matters.** Exclude a path from the MTU minimum and mark it
bulk-only, so it never receives steered real-time packets and never needs to accept a
packet sized for another path. **Do not build this now.**

---

## D-011 · Fallback dumps traffic directly onto links, unencrypted

**Decision.** On sustained tunnel or daemon failure, install a default route out the best
link. No fail-closed traffic class.

**Rationale.** Not a corporate scenario, so unencrypted direct egress is acceptable.
Simpler than per-class fallback policy.

**Constraints that still apply.** Deterministic link choice from a scheduler-written
ranking file with a static configured fallback order. Sustained trigger (15–30 s), longer
recovery delay (~60 s). Implemented in persistent nftables rules independent of the daemon.

---

## D-012 · Local web UI for management, independent of the daemon

**Decision.** Separate supervised process, reads a state file, fixed LAN IP, no framework.

**Rationale.** The UI is needed most when the scheduler has crashed. IPC to a live daemon
would make it useless in exactly that case. A state file yields stale-but-visible data,
which is what diagnosis requires.

---

## D-013 · Routed subnet at home, no double NAT, internet-egress NAT on by default

**Decision.** RV LAN gets its own prefix, routed at home — never double-NATed, so home can
always reach an RV device directly. Separately, the RV LAN's traffic to the wider internet
is NATed once, at the home edge, and this is **on by default**, not off. It is what "no
split tunneling" actually requires in practice: without it, an RV LAN client's own default
route has nowhere useful to send general internet traffic except back out its own local
WAN link, defeating the tunnel for exactly the traffic that most needs steering.

**Rationale.** Double NAT (NATing again at the RV) breaks reaching RV devices from home,
breaks peer-to-peer, and makes packet captures much harder to read — that stays disallowed
regardless of the internet-egress setting. The internet-egress NAT default was flipped
from off to on (2026-09-01) once it was clear that "off" left the RV's own LAN traffic
silently split-tunneling by default, which is the one thing this project must never do.

**Current implementation** (until D-014's provisioning system exists to manage this
properly): on the RV, the WireGuard peer's `AllowedIPs` is `0.0.0.0/0` and a default route
via `wg0` (low metric) sends general traffic into the tunnel. On the home end, an nftables
`masquerade` rule NATs `{RV LAN prefix, tunnel prefix}` out the home uplink. Watch for
DHCP-injected host routes on a WAN link overriding specific destinations back out that
link directly (seen with `1.1.1.1`/`8.8.8.8` on a real network) — override with an explicit
`ip route` via `wg0` at a lower metric, in the tunnel interface's own `PostUp`, not by
disabling DHCP-provided routes wholesale (that would also remove the WAN interface's own
default gateway, which the daemon's per-path sockets need).

**To turn it off:** remove `0.0.0.0/0` from the RV's peer `AllowedIPs` (narrow it back to
the tunnel and home-LAN prefixes only) and remove the low-metric default route via `wg0`
on the RV. The home-side masquerade rule can stay; it does nothing without matching
traffic reaching it.

---

## D-014 · Provisioning file install

**Decision.** Home installer generates both keypairs and emits one bundle for the RV.
Bootstrap on the same LAN in the driveway.

**Rationale.** Avoids needing internet connectivity during setup, and avoids the user
handling keys.

---

## D-015 · No LAN-based per-device blocking

**Decision.** Out of scope for now.

**Note.** Was raised as a small feature with outsized payoff (a smart TV pulling 4K can end
a 100 GB month in an afternoon). Deferred by owner. Per-device visibility may still be
worth having in the UI without enforcement.

---

## D-016 · Percentiles, not means

**Decision.** Track p95/p99 per path; use p95 OWD in scoring.

**Rationale.** Starlink's periodic satellite handovers produce latency spikes that a mean
completely hides, and the tail is what sizes the receiver's jitter buffer.

---

## D-017 · Out-of-band signals demote but never promote

**Decision.** Starlink obstruction telemetry and cellular RSRP/SINR can trigger demotion
early. Promotion requires measured packet-level performance.

**Rationale.** Out-of-band signals lead the loss statistics, which is valuable for getting
ahead of a degradation. But they do not prove a path works. Promoting on them would steer
calls onto paths that have not demonstrated anything.

---

## D-018 · Not all UDP is real-time

**Decision.** Behavioral classification within UDP, not a blanket UDP rule.

**Rationale.** QUIC/HTTP-3 runs on UDP/443 and carries large bulk volume. A blanket rule
would give YouTube the duplicated low-latency treatment and burn metered bandwidth.

**Kept.** The inverse — all TCP is definitively not real-time — as a free first-pass
exclusion.

---

## D-019 · STUN watching as the primary classifier

**Decision.** Watch for STUN binding requests to learn media 5-tuples before media flows.

**Rationale.** Protocol-based rather than vendor-based. Works for apps never configured,
survives vendor IP range changes, needs no feed. Vendor prefix lists become a hint rather
than a foundation, which is a much better role for them given how fast they rot.
