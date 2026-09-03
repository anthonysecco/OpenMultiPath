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
what `CLAUDE.md` and `architecture.md` always described.

**In progress** (2026-09-02). The RV already carries the routing half of this: `ip rule`
sends fwmark `0x2001` to table 2001 and `0x2002` to table 2002, whose default routes are
`enp2s0` and `enp1s0` respectively, which is exactly the per-link pinning above. What was
missing entirely was any way to read a plaintext packet, so `internal/tun` was built
first: it opens the device, addresses and sizes it, brings it up, and hands back one raw
IP packet per read. Verified on the RV itself, not only in a build sandbox.

Two things surfaced there that the rewrite has to account for, and both are now handled or
recorded. The kernel autoconfigures an IPv6 link-local address on any device the moment it
comes up and starts emitting router solicitations, which the daemon would have read back
out of its own tunnel as inner packets to classify - so the device disables IPv6 before
going up, per D-026. And the kernel emits IPv4 housekeeping regardless: an IGMP membership
report for 224.0.0.22 arrives on a freshly created device before any routed traffic does.
Nothing to fix there, but a consumer that assumed every packet was routed user traffic
would be wrong from the first read.

**Data path built** (2026-09-02), behind `-tun`, alongside the loopback relay rather than
replacing it. Naming a device runs above WireGuard; omitting the flag runs the original
shape. Same binary either way, so the way back from a bad update 800 miles away is a
restart with an argument removed rather than a recovery trip - principle 5.

The rewrite turned out to be much smaller than "data-path rewrite" suggested, because
`pathSet` was already generic. It binds a UDP socket to an interface's IPv4 address with
`SO_BINDTODEVICE` and sends to one shared remote; nothing in it assumes a *physical* NIC.
So pointing `-paths` at `wg1,wg2` and `-remote` at home's tunnel address makes the whole
path layer work unchanged, with WireGuard's own fwmark doing the per-link pinning. The
only real change was the local endpoint - a seam named `localEndpoint` with two
implementations, loopback and TUN - and everything between them (header, sequencing,
measurement, scoring, scheduling) is untouched and does not know which is in use.

**Proven end to end** in two network namespaces joined by a veth pair: a packet routed
into the RV's TUN crossed the tunnel and came out of home's TUN 103 us later with its
source intact, and home's reply came back the other way 57 us after that. Both daemons
logged no errors.

**Provisioned and proven on the real boxes** (2026-09-02), with production left running
throughout. `wg1` and `wg2` exist at `/etc/wireguard/` on the RV with their own keypairs,
addresses and fwmarks; `wgm` exists at home with one peer per link. None are enabled - see
the blockers below.

Two things were demonstrated on the hardware rather than in a sandbox:

*Per-link pinning works.* With `wg1` marked `0x2001` and `wg2` marked `0x2002`, their
handshake initiations left `enp2s0` (from `192.168.225.3`) and `enp1s0` (from
`100.110.247.30`) respectively, and `wg0` carried none of it. That last part matters: the
RV's default route is `dev wg0`, so without the fwmark this traffic would have recursed
into the production tunnel. The staged `ip rule` plumbing does exactly what it was put
there for.

*The data path carries real load.* Running both daemons with `-tun` over a real WireGuard
interface between the two boxes: ping across the tunnel addresses returned 5 of 5 at
28-38 ms, and a 20 MB transfer ran at 40.7 Mbps with the daemon reporting `mos 4.4
PRIMARY, rtt 25.4 ms, jitter 1.6 ms, lost 0`. That figure is not a throughput result worth
quoting - the test had to nest inside the production tunnel, so it was triple-encapsulated
- but it establishes that the path carries sustained traffic and measures it correctly.

**Blocker 1: only one port reaches home.** Probing 51821, 51900, 48220 and 51822 from the
RV, none arrived; a control probe to 48219 did, alongside 321 packets of live production
traffic. So the only forwarded UDP port is the one the production responder already owns.
A staged cutover needs a second port forwarded to the home box - the configs are written
for 51822 - or it has to take 48219 at the moment production releases it, which is not a
staged cutover at all.

**Blocker 2 - RESOLVED (2026-09-02).** The RV was only reachable *through the tunnel it
would be cutting over*: home routes `10.0.0.0/24` down `wg0`, so stopping the production
responder to free 48219 would have stranded the vehicle and the person doing it in the
same instant. That is the failure `scope-v1.md` names under field upgrades - "unrecoverable
without fallback working" - and it was true of the *cutover itself*, not merely of a bad
build.

There is now an out-of-band path. The dev box's Wi-Fi adapter is associated to the RV's
LAN at a static `10.0.0.237/24`, which puts an on-link route to `10.0.0.0/24` in front of
the tunnel path on longest prefix, so `ssh omp-remote1` takes it automatically. It is
independent by construction - the RV answers on `eth0`, nothing in the path touches `ompd`
or `wg0` - and that was verified rather than assumed: `ompd` was stopped on the RV for 30
seconds behind a self-restarting unit, and the box stayed reachable 3 times out of 3 with
the tunnel down.

The link is marginal and should be treated as an emergency console rather than a working
link: 2.4 GHz only, -65 dBm, negotiating MCS 0-2, roughly 17% packet loss, SSH connect
times between 0.4 and 12 seconds. It is enough to restart a service or remove a flag,
which is exactly what a rollback needs, and not enough for anything else.

**Cutover rehearsed on the real boxes** (2026-09-02), taking 48219 in place rather than
forwarding a second port, with the Wi-Fi path as the way back. It worked, and the whole
sequence is now a known quantity.

Two things made it safe enough to attempt. A `/usr/local/sbin/omp-restore` script on each
box returns it to the production shape unconditionally, and a `systemd-run` dead-man
timer runs that script after fifteen minutes unless cancelled - so losing the Wi-Fi
mid-cutover costs a wait, not a vehicle. Both are worth keeping.

One trick removed most of the need for the second port. Bringing `wg1` and `wg2` up while
the *production* responder still held 48219 makes home log their handshakes as `bad packet
from ...` - which proved both links reach home, on the real WAN, from the two expected
public addresses, before anything was stopped. Reachability was the part worth rehearsing
and it can be rehearsed for free.

What ran, for the first time: `wgm` at home with one peer per link on 48219, `wg1` and
`wg2` handshaking to it over their own physical links, and the daemon above them on a TUN
device with **two** paths. Both were scored independently - path 0 at 31.8 ms picked
PRIMARY over path 1 at 38.4 ms - and traffic crossed at 0% loss. Path selection had never
run over two real links before.

A config correction came out of it. Both per-link configs originally carried
`AllowedIPs = 10.20.1.0/24`, and `wg-quick` would have failed installing the same route
twice on the second interface up. Because the daemon carries one remote for every path,
both links must dial the *same* home address, so the fix is `Table = off` plus an explicit
per-interface route at differing metrics, with `SO_BINDTODEVICE` constraining the lookup.

**Run end to end on the real boxes** (2026-09-03), both daemons above WireGuard over two
real WAN links. Traffic crossed the TUNs at 0% loss over five round trips, 23.7-50.9 ms;
the two paths were scored independently (30.5 ms against 35.1 ms) and the scheduler ran a
make-before-break handover onto the better one, confirmed after 201 ms; both ends
discovered a 1408 byte path MTU. Eight STUN binding requests sent through the tunnel came
back out classified 8 real-time, 0 bulk - step 7 and step 8 working in the shape they were
written for, rather than in the loopback relay where they cannot.

**The flag shape, which is the part that is easy to get wrong.** Home:

    ompd -role responder -tun omp0 -tun-addr 10.30.0.1/24 -public 10.20.1.1:51830

RV:

    ompd -role initiator -tun omp0 -tun-addr 10.30.0.2/24 \
         -remote 10.20.1.1:51830 -paths wg1,wg2

Three invariants sit behind that, and getting any of them wrong on the first attempt cost
an evening:

*There are two subnets, not one.* `10.20.1.0/24` is the **transport**: the WireGuard
interfaces themselves (`wgm` .1, `wg1` .2, `wg2` .3), carrying omp-protocol packets
between the daemons. The TUN devices are the **inner** network the user's plaintext rides,
and need a range of their own - `10.30.0.0/24` above. Handing `-tun-addr` a transport
address collides with the WireGuard interface already holding it.

*`-remote` takes home's tunnel address.* The path sockets are bound to `wg1`/`wg2`, whose
`AllowedIPs` is `10.20.1.1/32`. Aiming them at home's public endpoint means no peer covers
the destination and WireGuard refuses with `ENOKEY`, which the kernel words as "required
key not available" - it reads as a crypto fault and is a routing one. `paths.go` now
appends a hint saying so on that specific errno.

*`-public` must not be `wgm`'s port.* The responder always opens a public UDP socket; that
is true in both shapes and is not gated on `-tun`. Under D-020 the socket carries omp
packets *inside* the tunnel, so it binds the tunnel address on any free port. Leaving it at
the default `0.0.0.0:48219` binds the exact port `wgm` holds and the daemon exits with
"address already in use", which looks like `-tun` having been ignored and is not.

**Blocker 1 does not apply to an in-place cutover.** Only UDP 48219 being forwarded still
blocks running D-020 *beside* production, but the omp port lives inside the tunnel and
needs no forward of its own. The second port is a convenience for staging, not a
prerequisite.

**Blocker 2's fallback needs bringing up, not just existing.** The out-of-band Wi-Fi was
configured and idle: NetworkManager held a correct `Rigatony Outdoor` profile with a static
`10.0.0.237/24`, but the interface was down, so the only route to the RV ran through the
tunnel being cut. Taking home's `wg0` down stranded the vehicle exactly as this blocker
predicted, and recovering meant reverting home. **Bring the lifeline up and confirm
`ip route get 10.0.0.1` names the Wi-Fi device before touching either tunnel.** Once up it
is genuinely independent - the RV stayed reachable throughout with home's `wg0` down - and
still marginal: -69 dBm, MCS 0, ~33% loss, 15 s to open an SSH session.

**Still blocking a real cutover:** nothing structural. What remains is moving the RV's
default route onto the TUN and giving home egress for it, which is the part that changes
what LAN clients experience and wants its own window.

---

## D-029 · Link-down detection bounds failover, not the scheduler

**Decision.** Recorded, not yet fixed. The scheduler is not the slow part of a failover
and tuning it will not help.

**Measured** (2026-09-02, on the RV, two real WAN links under D-020). With traffic running
at 250 ms intervals, the primary link's interface was taken down. 13 packets were lost,
roughly 3.25 seconds. The log says where they went:

```
18:52:46 path 0: write failed ...
18:52:46 path 0 (wg1): down (interface wg1 is down)
18:52:46 scheduler: primary -> path 1 (no usable primary)
```

The scheduler moved the flow in the *same second* it was told. Every one of those three
seconds was spent before that - discovering the link was gone. `paths.go` reconciles on a
`rebindInterval` of two seconds, so a link that disappears cleanly stays "up" for up to
one full poll, and `EvalIntervalMs` at 200 ms never gets a chance to matter.

**Why it matters.** `protocol.md` sets a 100-200 ms reaction target. Three seconds of dead
audio ends a call, and no amount of adjusting the state machine's thresholds will recover
it, because the state machine is not the thing that is late.

**Scope, honestly.** This is the clean interface-down case - a modem unplugged, a dish
losing power. Gradual degradation, which is the canyon case and the more common one, is
caught by quality scoring within a couple of evaluation intervals and is not affected.
So this is one failure mode arriving late, not all of them.

**Fixed** (2026-09-02) in `internal/relay/linkwatch.go`, with measurements below.

Link state is an event, not a thing to poll. A netlink socket subscribed to `RTMGRP_LINK`
and `RTMGRP_IPV4_IFADDR` wakes the existing reconcile as interfaces and addresses change.
Addresses matter as much as links: a lease renewal under CGNAT moves a path's source
address without the interface ever going down.

Three things now drive a reconcile - a netlink event, a poke from the data path when a
write fails, and the old periodic sweep. The sweep is kept at two seconds rather than
relaxed, because it is what still works when events do not, and making it lazier on the
strength of the fast path would trade away the fallback. This is deliberately a
notification only: it carries no detail and the message body is not parsed, so reconcile
remains the single place that decides what a path should do rather than there being two
interpretations of link state to keep in agreement.

The write-failure poke covers what events cannot see at all - a route withdrawn while the
address stays put, which is an attached modem with no PDP context and an ordinary dead-zone
state. It fires only on the transition into failure, so a path failing every write asks
once rather than continuously.

**A second latency, found while testing the first.** Events made link *removal* prompt
immediately, but a link *appearing* still took a full sweep about one run in five. An
interface is built in steps - created, then addressed, then brought up - and each step is
its own event. A reconcile woken by the first sees a half-built interface, finds nothing
bindable, and the wakeup that would have caught it finished has already been coalesced
away. The same shape covers a bind refused a moment too early, and a modem sitting up
with no address while DHCP finishes.

So reconcile now reports whether anything is still converging, and the loop looks again in
100 ms when it is. The distinction that matters is "not ready yet" against "not there":
an interface that exists but cannot be bound is worth retrying hard, while one that is
simply absent is a link in a dead zone, where polling at 100 ms for hours would cost power
on a box running off a battery to discover nothing. Only the first is pending.

**Measured after the fix**, against a 2 s sweep, over eight consecutive runs: a link
disappearing is acted on in **5.5-6 ms**, and a link appearing in **11-14 ms**. Both were
previously bounded by the sweep, and the interface-down case cost roughly 3 s in the
field. That is now comfortably inside protocol.md's 100-200 ms target with two orders of
magnitude to spare.

If the netlink subscription fails at startup the daemon logs it and carries on with the
sweep alone, which is exactly how it behaved before events existed. Principle 5: slower,
and working.

Verified on the RV itself as well as in the sandbox - `6.12.107+deb13-cloud-amd64`, the
kernel flavour that ships without most physical-NIC drivers - at 11.96 ms to bind and
15.40 ms to drop.

**A latent bug found by the test that would not stop flaking** (2026-09-02). The read loop
treated every error but `EINTR` as fatal and returned, which silently ended event-driven
detection for the life of the process. `ENOBUFS` on a netlink multicast socket does not
mean that: it means the kernel dropped messages because the socket was not drained fast
enough, which is a burst rather than a fault - and several links registering at once on a
cold boot, the case `scope-v1.md` opens with, is exactly such a burst. The watcher now
treats it as "something changed and I no longer know what", asks for a reconcile, and
keeps reading; the reconcile reads interface state directly, so it does not depend on
having seen the message that was lost. The receive buffer was raised to a megabyte to make
the drop rarer in the first place.

The test that surfaced it was also wrong, in an instructive way. It required *every* trial
to beat the sweep, which asserts that a notification is never lost - a stronger guarantee
than this design makes, since the backstop sweep exists precisely because one can be. It
now runs several trials and requires most to be event-fast, which still fails loudly if
events stop working altogether and does not fail for the reason the design already
accounts for.

**Still owed by the code:** recovering the bind/rebind visibility D-020 costs by reading
interface state, and making the TUN MTU track the daemon's own recommendation rather than
the flag default.

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

**Revisited and changed** (2026-09-02). Step 7 landed and step 8 made the transmit set a
per-class decision, so the reasoning that forced handovers-only no longer holds: bulk now
rides a single path whatever this is set to, and duplication can only ever cost a second
copy of the real-time flow. The default moves to `unstable` - duplicating real-time while
the path carrying it is degraded, onto a path measured to have room for it. Insurance
bought when the risk appears rather than continuously, which is the canyon approach in
`scope-v1.md`. `switching` remains available for a link where even that is too expensive.

The original note follows, and its shape still stands. The right policy is per class and
per budget band:
audio duplicated whenever a second path exists and budget is green, video only when a link
is unstable or an unmetered path is available. That cannot be expressed until packets
carry a class, so **unstable** and **always** exist as manual escape hatches until then.

**Note.** Duplication should become capacity-aware, not just budget-aware. The docs assume
duplication is nearly free; on a 512k link, 40 kbps of audio is 8% of capacity and the
1.5 Mbps video case is simply impossible.

---

## D-023 · Reactive bandwidth ceiling, not active probing

**Decision.** Estimate each path's usable capacity from queueing onset during real
traffic, not from dedicated bandwidth probes. When a path is carrying real load and the
link underneath starts to fill, record the send rate at that moment, less a margin, as
the observed ceiling. A path that has never been seen to queue has no estimate and falls
back to a configured `bw_fallback_kbps`, default 0, which means unknown and applies no
limit at all.

**Rationale.** Active bandwidth probing - packet trains, pair dispersion - is unreliable
on a variable-bandwidth link and directly counterproductive on a metered one: the probe
itself spends the capacity it is trying to measure. Delay is already measured on every
path for the state machine; reusing it as a capacity signal adds no wire format, no probe
cadence, and no cost beyond bookkeeping.

**The signal is the round trip, not the receive-side queue delay.** This was the first
thing implementation changed. `queue_delay_ms` is built from arrival timestamps and is
therefore the *receive* direction only, while the scheduler decides where to *send* - so
it cannot answer the question on its own. What can is the round trip against its own
floor, less the receive-side queue delay we can already see. One subtraction, and it is
what keeps a large download arriving on a path from being misread as that path's uplink
filling up, which is exactly the scenario that prompted this decision.

**Superseded in part by D-024** (2026-09-02). That subtraction was always an inference,
and a difference of two noisy numbers degrades badly when both directions are busy at
once. Path reports now carry the peer's own measurement of our send direction, so when a
report is in hand the outbound queue delay is simply read rather than derived. The
subtraction survives as the fallback for a peer that is not reporting - an older build,
or a path it has not heard from - which is also why it was worth building first: the
ceiling was measurable before the wire could carry a report, and a node that loses its
peer's reports degrades to a working estimate rather than to none.

The round-trip floor is re-armed on a far longer window than the ten seconds `stats.go`
uses for transit. Ten seconds is right for "is this path degraded now", a question about
the present. Capacity is a question about the link, and a standing queue lasting a minute
is precisely the evidence being looked for - absorbing it into the baseline would turn a
badly congested link into one that reads as clean at whatever rate is being forced into
it.

**Two numbers, not one.** The second thing implementation changed. Carrying a rate with
the link still empty proves the path can do *at least* that much; it says nothing about
the maximum. Recording that as a ceiling would make a path ineligible for traffic merely
because nothing larger had happened to flow through it yet. So a clean rate is kept as a
floor (`proven`) and only an observed onset sets a ceiling. Only the ceiling gates
anything.

**Revision.** The ceiling is taken at the *transition* into queueing, and afterwards may
only ratchet down. Once a buffer is filling, what is being pushed in is no longer what is
coming out the far side: a sender that keeps shoving 8 Mbps into a link that has
collapsed to 2 would otherwise have that 8 recorded as its capacity, which is the
opposite of the truth. A lower rate that is still queueing is direct evidence the wall
moved in and is trusted at once.

Upward revision needs a clean reading. A path carrying more than its recorded ceiling
with the link empty has demonstrated that ceiling wrong, and it is lifted to what has
actually flowed - never above it, so no headroom is ever invented.

An estimate for a path that has gone back to idle ages in confidence, not in value. The
number is not discarded and not decayed - an hour of quiet is not evidence that a link
shrank, and a decaying number would read as a degrading link in the interface while
nothing at all had been measured. What slides is how much of it the scheduler leans on:
full weight while fresh, down to a floor of 70% once nothing has confirmed it for a
quarter of an hour, and no further. A stale estimate still beats no estimate.

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

Also deferred: `bw_fallback_kbps` is global rather than per-path, because path
configuration is currently a command-line list of interface names and the responder has
no path configuration at all - it learns its paths from what arrives. A per-path figure
is what is actually wanted, since the case it exists for is one specific link with a
known 512k tier, and it belongs with the provisioning file rather than bolted onto a
flag.

**Built** (2026-09-01), with the estimate visible per path in the state file and web
interface: what is going onto the path now, the most it has carried clean, the measured
ceiling if there is one, how long ago that was confirmed, and what the scheduler is
currently willing to assume. The three cases are shown apart rather than as one number,
because a measured ceiling can be acted on, a floor only says "at least this", and never
having loaded a path says nothing at all.

**Field result** (2026-09-01). On the vehicle it measured the Starlink standby path at
506 kbps, against a documented 512k tier - within one percent, from ordinary traffic,
with no probe. It also found the limit of the "clean carriage proves a floor" rule the
same evening: the cellular path sat at a stale 1023 kbps estimate while actually
carrying 84 Mbps, because nothing had ever pushed it hard enough to queue. The estimate
tracks demand as much as capacity, and reads low until something real loads the link.
That is the safe direction to be wrong in, and worth remembering before trusting the
number as a capacity figure rather than as a floor.

---

## D-024 · Score the send direction, from what the peer reports

**Decision.** Each end tells the other, once a second per path, what it measured on the
other's transmissions: p95 spread, queue delay, jitter, recent loss, burst ratio. A
sender scores a path for transmission on those figures rather than on its own inbound
statistics. Wire version 2, a new block on standalone reports only.

**The bug this fixes.** Every measurement a node can take locally describes packets
*arriving*. Round trip cannot say which direction the delay was in. So a sender choosing
where to transmit was making an outbound decision entirely from inbound evidence, and on
2026-09-01 that did exactly what it sounds like: a 107 Mbps download saturated the
cellular path's downlink, the resulting bufferbloat drove that path's R below the floor,
and the scheduler evacuated the flow onto the 512 kbps Starlink standby link. The
cellular *uplink* was carrying 19 kbps and was perfectly healthy throughout. Upload fell
to 0.45 Mbps and stayed there.

**Clocks.** Absolute one-way delay needs synchronised clocks and this project
deliberately has none. It is also not what the decision turns on, so the delay is split:

    outbound  ~=  rttFloor/2  +  what the peer reports queueing

The floor rather than the live round trip, because an instantaneous round trip contains
queueing from both directions - which is the contamination being removed. Everything the
peer reports is a difference against its own floor, so the unknown offset cancels and no
synchronisation is required. The symmetric half is still an assumption, and wrong on some
links; it is the *stable* half. The part that moves is now measured on the correct side.

**Rejected: shared NTP.** Suggested, and it does tighten the offset, but not to the
precision that matters: a few milliseconds of residual error is the same size as the
differences being resolved. It would add a dependency and a failure mode to buy an
accuracy the design does not need, since ranking paths and detecting change are both
differences, and differences cancel the offset exactly.

**Fallback.** No report, or one older than ten seconds, and the path is scored exactly as
before - half a round trip and the inbound figures. That is the wrong direction and known
to be, but it is what a lone node can see, and an old peer or a path the far end has not
heard from still has to be scored somehow. Principle 5.

**Rolling upgrade.** Version 1 is still accepted, and version 2 is emitted only once the
peer has been heard to speak it, so either end can be upgraded first with no outage.
Negotiation deadlocked on the first attempt - both ends start at version 1, so neither
ever sends a version 2 packet and neither ever learns the other could read one. The fix
is a capability bit in a flags field that version 1 already ignores, advertised on every
packet whatever version it is encoded as. Tested one end at a time on the vehicle.

**Cost.** Ten bytes per path per second, on packets that carry no payload. Reports ride
only on standalone reports, never on data, so a data packet's header stays small and the
tunnel MTU does not have to budget for them; that is why `MaxDataHeaderLen` is split from
`MaxHeaderLen`.

**Field result** (2026-09-02). Asymmetry that was previously invisible showed up
immediately - one path reading 69 ms of inbound spread against 5.6 ms outbound. The
regression test passed on the vehicle: a 93 Mbps download drove the primary's inbound
queue delay to 47 ms and 0.49% loss while its outbound stayed at 4.7 ms and 0%, and the
flow did not move. Zero handovers.

---

## D-025 · Authenticate the wire header

**Decision.** An 8-byte truncated HMAC-SHA256 over the header, keyed by a shared secret,
carried on version 2 packets when a key is configured. The key lives in a file of its
own, never in the settings file.

**Why now.** It was parked deliberately while the header carried only sequence numbers
and timestamps. D-024 changes the stakes: path reports are an input to path selection, so
anyone able to inject a packet could steer the vehicle's traffic onto a link of their
choosing. It also shares D-024's version bump, and shipping two flag days to a vehicle
rather than one is a bad trade.

**Scope, deliberately narrow.** This does not protect the payload - WireGuard already
does, and protocol.md is firm about not writing crypto here. It raises the cost of
injecting *metadata* from one packet to 2^64 of them. Eight bytes is short for a MAC and
is the right length for that job; against an attacker who can already read the traffic it
is the wrong defence anyway, and the bytes come out of every packet.

**The key is not in config.json.** The web interface serves that file over HTTP to
anything on the LAN. A shared secret has no business in a response a browser can fetch,
so it is read from `/etc/openmultipath/auth.key` at startup instead. Absent means
unauthenticated, which is what every unit in the field is running today.

**Enabling it is a flag day, unlike the upgrade.** Once one end has the key it rejects
the other's untagged version 2 packets, so both ends must be restarted together. The
code upgrade rolls safely one end at a time; turning authentication on does not. It is a
parked-in-the-driveway change, and it belongs in the provisioning bundle so a unit is
built with its key rather than having one added later.

**Rejected: accepting untagged packets during a grace period.** It would make enabling
authentication rolling, at the cost of leaving the door open for exactly as long as
nobody noticed the grace period had never ended. A window that closes when someone
remembers is not a security control.

---

## D-026 · No IPv6, for now

**Decision.** The RV does not carry IPv6. Drop it on the WAN interfaces rather than carry
it inside the tunnel.

**Why this came up.** A speedtest on the RV read far better than the same test from a LAN
client behind it, and the reason was that the RV's own IPv6 was leaving straight out the
cellular modem - `wg0` has no IPv6 address at all, and two router advertisements were
installing IPv6 default routes on the WAN interfaces. Anything resolving to a AAAA record
bypassed WireGuard, the daemon, and every measurement in it. The LAN client has no IPv6
and so was using the tunnel correctly; it was never slow, it was simply the only one
being measured.

**Rationale.** This is a split tunnel, which D-004 rules out in plain terms. IPv6 traffic
was getting no multipath, no make-before-break, no measurement and no failover - pinned to
whichever interface won the RA metric race, with the source address changing when that
link dropped, which is the exact property the tunnel exists to provide. It also meant the
field telemetry understated what the vehicle actually carries, by however much of the
traffic was AAAA.

Dropping it is the simpler of the two fixes and matches principle 2. The cost is real but
small: a handful of v6-only services become unreachable from the RV.

**Not rejected, deferred:** carrying IPv6 inside the tunnel - a v6 prefix on `wg0`, `::/0`
routed into it, egress at home. That is the right long-term answer and it needs working
v6 at the home end plus a change to the provisioning bundle. Revisit when either the
provisioning flow is being touched anyway or something the RV needs turns out to be
v6-only.

**Implemented** (2026-09-02) on the RV, in `/etc/netplan/60-wan-i226.yaml`, as two
settings on each WAN interface:

```yaml
      accept-ra: false
      link-local: []
```

which netplan renders as `IPv6AcceptRA=no` and `LinkLocalAddressing=no`. After this the
WAN interfaces carry no IPv6 at all - no global address, no link-local, no default route
- so a v6 connect fails with `ENETUNREACH` in about a millisecond and Happy Eyeballs
falls back to v4 with nothing perceptible. `eth0` is untouched and keeps its link-local;
`net.ipv6.conf.all.forwarding` is 0, so the LAN has no v6 path through the box either.

**The trap, for whoever checks this next.** `net.ipv6.conf.enp1s0.accept_ra` was *already*
0 before the fix, and the leak was wide open anyway. That sysctl is not the control here:
systemd-networkd sets it to 0 precisely because it does RA processing itself, in
userspace, and then installs what it learns - which is why the leaked routes read
`proto ra` and the addresses read `noprefixroute mngtmpaddr`. Reading the sysctl and
concluding IPv6 was already handled is the obvious wrong turn, and setting it by hand in
`/etc/sysctl.d` would change nothing at all. The control is networkd's configuration.

Two related things worth knowing. The leaked addresses were `valid_lft forever`, so they
would never have aged out on their own; `netplan apply` removed them, no manual flush was
needed. And the symptom that started this was measured again on the way in: before the
fix, `curl -6` egressed from `2600:380:8769:9ad9::...` straight out `enp2s0`, while after
it, google.com, cloudflare.com and netflix.com all resolve dual-stack and all leave from
`10.20.0.2` - through the tunnel, where they can be measured.

**Note.** IPv6 appeared nowhere in these documents before this entry. It was not a
decision that went wrong; it was one nobody had made.

---

## D-019 · STUN watching as the primary classifier

**Decision.** Watch for STUN binding requests to learn media 5-tuples before media flows.

**Rationale.** Protocol-based rather than vendor-based. Works for apps never configured,
survives vendor IP range changes, needs no feed. Vendor prefix lists become a hint rather
than a foundation, which is a much better role for them given how fast they rot.

---

## D-027 · An unclassified flow is bulk-ish, never real-time

**Decision.** A flow the classifier has not identified is `ClassUnknown`, and the
behavioural heuristic requires *both* of protocol.md's signals - small mean packet size
and low inter-packet-gap variance - before it will say real-time. Either signal alone
leaves the flow bulk.

**Rationale.** The two mistakes are not symmetric. Calling a download real-time
duplicates it across a metered link and reserves admission-control capacity for it,
which is the failure that saturated the 512k standby link once already (D-023). Calling
a call bulk for a few hundred milliseconds costs some quality at the start of the flow.
The cheap mistake is the one to make by default.

This costs less than it appears to, because the signal that actually protects a call
fires first: ICE sends binding requests from the exact port pair the media will use, so
a WebRTC conference is real-time from its first packet and never sits in the unknown
state at all (D-019). The behavioural path only has to catch native clients that speak
no ICE and have no usable vendor prefix, and for those, arriving at the right answer 24
packets in is a good outcome.

**Rejected.** Defaulting unknown UDP to real-time and demoting on evidence. It inverts
the cost: every QUIC flow gets the expensive treatment for its first packets, and QUIC
is the majority of UDP by volume - D-018's whole point.

**Also rejected.** Requiring only one of the two signals. Small alone matches DNS,
keepalives, and game control channels; metronomic alone matches a constant-bitrate
download. Both together is what protocol.md claims separates RTP from QUIC "almost
perfectly", and a replay of real captured traffic agrees: of 21.3 MB captured off the
tunnel interface, 0.27% came out real-time, and that 0.27% was the metronomic test
stream.

---

## D-028 · The multi-stream tunnel throughput ceiling is deferred, not accepted

**Decision.** Bulk throughput through the tunnel degrades as concurrent flows rise. It is
recorded here with its measurements and left alone for now.

**Measured** (2026-09-02, RV to Cloudflare, `enp2s0` carrying the tunnel, home uplink
measured separately at 364 Mbps so it is not the constraint):

| Concurrency | Tunnel | Direct | Cost |
|---|---|---|---|
| 1 stream | 104.4 Mbps | 108.1 Mbps | 3% |
| 6 streams | 81 Mbps | 122 Mbps | 34% |
| Ookla speedtest | 44 Mbps | 128 Mbps | 65% |

Upload is much cheaper than download: 72.8 against 82.4 Mbps, 12%. Idle latency costs
about 5 ms. `ompd` used 7% of one core while carrying 104 Mbps, so this is not crypto and
not raw compute.

**What it is not.** Not the home uplink, not CPU, and not the IPv6 leak of D-026, which
was fixed first and separately. Single-stream cost of 3% says the data path is sound; the
penalty appears only with concurrency, which points at a per-packet or serialisation
ceiling - the initiator reads the WireGuard loopback from one goroutine and allocates the
global sequence there. That is a hypothesis. It has not been profiled and should not be
repeated as fact.

**Why defer.** Two reasons. The first is that the same comparison shows the tunnel is
*better* where this project says it cares: 92 ms of loaded latency with 19 ms jitter
against 318 ms and 69 ms jitter going direct, about 3.5x. Bulk peak throughput is
explicitly sacrificial (`scope-v1.md`), conferencing quality is not, and some of the
missing throughput is the tunnel declining to fill the modem's queue - which is the
behaviour admission control is being built to produce deliberately.

The second is sequencing. D-020 rewrites this exact data path: the daemon moves above
WireGuard onto a TUN device and the loopback relay goroutine that is the leading suspect
stops existing in its current form. Profiling a component scheduled for replacement, to
fix a symptom that partly overlaps with what step 9 will address on purpose, is work
done twice.

**Revisit** after D-020 lands and step 9 is in, by re-running the table above. If the
concurrency penalty survives both, it is real and structural rather than incidental, and
that is the point to profile it properly.

---

## D-030 · Identify media from the RTP header, not from its shape

**Decision.** Detect RTP directly, confirmed by three packets agreeing on a 32-bit SSRC,
and place it second in the classification order - after STUN, ahead of vendor prefixes.

**Why this came up.** The classifier was validated against the traffic the project exists
to protect, and failed it. Audio classified real-time; 720p video, 1080p video and screen
share all classified **bulk**. The primary use case in `CLAUDE.md` is a teleworker on a
video call, and the behavioural test called every video stream a download.

The cause is in `protocol.md`, which tabulates "RTP media" as 60-250 bytes at a metronomic
20 ms. That is Opus, and only Opus. Video RTP is MTU-sized, because a frame is fragmented
across as many packets as it takes, and frame-bursty, because those packets go out
together and then nothing happens until the next frame - so it fails the size test and the
gap-variance test both. The table was right about audio and was read as being about media.

**Rationale.** The RTP header identifies media directly instead of inferring it from
shape, so packet size stops mattering and video is caught like anything else. It is
protocol-based rather than vendor-based, which is D-019's argument applied again. And it
works on SRTP: the payload is encrypted, the header is not, because the receiver's jitter
buffer and any middlebox in between have to read it.

It also closes a gap STUN cannot. STUN is better when it fires, because ICE announces the
5-tuple before media exists - but it only fires at the start of a call. **A daemon that
starts in the middle of an existing call never sees the ICE exchange**, and a restart
during a canyon transit is exactly that. RTP evidence arrives on every packet, so it
recovers a call already in progress.

**Why it is safe ahead of the behavioural test.** The version bits separate RTP from
everything that shares these ports without ambiguity: RTP begins `10`, QUIC's long header
`11`, QUIC's short header `01`, and STUN and DTLS both `00`. Payload types 72-76 are
excluded because RFC 3551 reserves them so RTCP can share a port. One packet matching
would still be weak - a quarter of random payloads have the right two bits - so three
consecutive packets must agree on the SSRC, which a 32-bit random value does not do by
chance. Confirmed on real captured traffic: no Cloudflare QUIC flow was mistaken for
media.

**Ordered ahead of vendor prefixes**, which `protocol.md` had at position two. A vendor
prefix is a guess that an address range carries media; an RTP header is the media saying
so. Strictly better evidence belongs strictly earlier.

**Latency, which is the point.** Media now settles at packet 3 rather than packet 24 - 60
ms at audio cadence, less than one frame of video, against roughly half a second before.
On real captured traffic the same stream that took 24 packets to identify now takes 3.

**Consequence for D-027.** The behavioural test is no longer how media is found; it is a
last resort for media carrying no RTP framing, which is rare. So its gap-variance
threshold was tightened from 10 ms to 5 ms. At 10 ms a stream of small QUIC
acknowledgements passed as real-time, which is D-027's expensive mistake - a duplicated
download on a metered link - and genuine audio sits nowhere near either bound.
