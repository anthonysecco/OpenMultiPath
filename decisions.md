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

## D-020 · The daemon moves above WireGuard for classification

**Decision.** The daemon takes a TUN device and reads plaintext inner packets. Each WAN
link gets its own WireGuard interface on the RV, pinned to that link by fwmark and policy
routing; home keeps one interface on one public port with one peer per link.

**Rationale.** The daemon currently sits *below* WireGuard, relaying already-encrypted
UDP, which means it never sees an inner packet. Step 7 is impossible from there: STUN
watching needs a 5-tuple, the behavioural heuristic needs per-flow size and inter-packet
gap, and all flows are multiplexed into one WireGuard session so even the packet sizes
that survive encryption cannot be attributed to a flow. A class cannot cross a crypto
boundary; either you do not cross it, or you run one crypto channel per class.

This also settles where later steps live. Admission control (step 9) is described as "the
part that saves the meeting" and wants to sit where queue delay is measured, in one
process rather than split between the daemon and a separate tc/CAKE layer. MSS clamping
returns in-house too - `architecture.md` asks for it at tunnel ingress, and it has been
sitting in nftables because the daemon had no TCP header to clamp.

**Rejected.** One WireGuard tunnel per class (class known from which loopback socket a
packet arrives on): cheapest option preserving per-flow steering, but the class decision
lives permanently in nftables and policy routing on both boxes, and two tunnel IPs mean a
flow reclassified mid-life changes source address, so the behavioural catch-all could only
ever tag future flows. Also rejected: no per-packet class at all, inferring size through
the encryption and duplicating small packets during a call - cheapest of the three, but it
gives up per-class path splitting permanently, which is the canyon walkthrough.

**Cost accepted.** A data-path rewrite, per-link fwmark routing on the RV, and the loss of
the daemon's own bind/rebind visibility (it currently distinguishes "bound but silent" from
"not bound", which wants recovering by reading interface state).

**Note.** Supersedes the single-tunnel relay shape the daemon was built with, and restores
what `CLAUDE.md` and `architecture.md` always described. Not yet implemented: step 6 was
built first, and is independent of this.

---

## D-021 · Composite E-model scoring, in R points, not a weighted sum

**Decision.** Paths are scored with the ITU-T G.107 E-model. Every scoring threshold and
penalty in the configuration is expressed in R points.

**Rationale.** `protocol.md` asks for this directly: the relative weight of loss against
jitter against delay for perceived quality is well-researched, and hand-tuning
coefficients would produce something worse after a month. With no field data to tune
against, borrowing a researched model matters more than usual. R rather than MOS because
impairments are additive in R and not in MOS - subtracting "half a MOS point" means
different things at either end of the scale. MOS is derived for display only.

**Consequences worth knowing.** The model measures *impairment*, so two paths both
comfortably under the delay knee both score the maximum and tie. Ties break on lower
effective delay; without that they broke on path id, and path 0 is the metered satellite
link. The model is a voice model applied to all traffic, which is the right bias for the
primary use case but does mean bulk is scored on criteria it does not care about.

**Note.** The state machine deliberately does *not* score. It judges each path against its
own absolute thresholds, so a steadily slow satellite link stays stable rather than being
demoted for being a satellite link.

---

## D-022 · Duplication defaults to handovers only

**Decision.** Four policies - off, switching, unstable, always. The default is
**switching**: one copy, except during a make-before-break handover.

**Rationale.** Unconditional duplication was scaffolding, and it has a measured cost. With
every packet riding every path, any real load saturates the weakest link: a 10 MB copy
produced 8000+ lost packets on the Starlink path, almost all in runs longer than 16, while
the other path stayed clean. That link is on the 512k standby plan, so duplication is not
the negligible cost `protocol.md` assumes when it reasons about 40 kbps of audio.

Duplicating during a handover is where the redundancy actually buys something - it is what
makes the switch gapless - and it is time-bounded.

**Revisit when classification lands.** The right policy is per class and per budget band:
audio duplicated whenever a second path exists and budget is green, video only when a link
is unstable or an unmetered path is available. That cannot be expressed until packets
carry a class, so **unstable** and **always** exist as manual escape hatches until then.

**Note.** Duplication should become capacity-aware, not just budget-aware. The docs assume
duplication is nearly free; on a 512k link, 40 kbps of audio is 8% of capacity and the
1.5 Mbps video case is simply impossible.

---

## D-023 · Reactive bandwidth ceiling, not active probing

**Decision.** Estimate each path's usable capacity from queue-delay onset during real
traffic, not from dedicated bandwidth probes. Track a rolling baseline (quiet) delay per
path; when delay pulls away from baseline while the path is carrying load, record the
send rate at that moment as the observed ceiling. A path that has never carried enough
load to trigger an onset has no estimate and falls back to a configured
`max_bitrate_kbps`, default unset.

**Rationale.** Active bandwidth probing - packet trains, pair dispersion - is unreliable
on a variable-bandwidth link and directly counterproductive on a metered one: the probe
itself spends the capacity it is trying to measure. Queue delay is already computed for
every path from the echo channel for the state machine; reusing it as a capacity signal
adds no wire format, no probe cadence, and no cost beyond bookkeeping.

**Revision.** Downward revision, on an observed onset, is trusted immediately. Upward
revision only creeps up a little per clean interval carrying real load - additive
increase, not an instant reset - so one bad reading doesn't permanently cap a path that
has since recovered. An estimate for a path that has gone back to idle ages in
confidence, not in value: the number is not discarded, but it is no longer treated as
current.

**Consequence for D-022.** This is the capacity-awareness that decision's closing note
asked for. Duplication targets and primary handovers should reject a candidate whose
ceiling (or configured fallback, if unconfirmed) cannot cover the load already being
offered to it. This is a soft gate, never a hard veto - a link-starved RV must still be
able to fail over to its only remaining option, however capacity-poor.

**After classification (step 7).** Splits further: real-time stays duplicated broadly,
since its bandwidth needs are small enough that ceiling rarely excludes anything. Bulk
should never be a duplication target at all, ceiling aside - TCP already retransmits, so
duplicating a bulk stream buys nothing. Ceiling's main job after step 7 narrows to
choosing bulk's single best path (headroom-driven) independently of real-time's primary
(quality-driven), so a saturating download no longer drags a live call's path down with
it.

**Deferred.** Using the ceiling to actively pace or shape the daemon's own outbound
writes - inducing backpressure on the sender's TCP stack rather than only informing path
choice - is a distinct, larger capability and is not part of this decision.

---

## D-019 · STUN watching as the primary classifier

**Decision.** Watch for STUN binding requests to learn media 5-tuples before media flows.

**Rationale.** Protocol-based rather than vendor-based. Works for apps never configured,
survives vendor IP range changes, needs no feed. Vendor prefix lists become a hint rather
than a foundation, which is a much better role for them given how fast they rot.
