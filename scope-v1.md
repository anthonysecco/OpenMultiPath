# v1 scope

## In scope

- WireGuard overlay, one tunnel per WAN link, all terminating on one home UDP port
- Userspace multipath daemon with the header from `protocol.md`
- Passive measurement from data packets; active probes scaled inversely to path traffic
- Queue delay inferred from delay above rolling minimum (no clock sync required)
- Reactive per-path bandwidth ceiling from queueing onset during real traffic, taken from
  the peer's reported queue delay in our send direction. No active bandwidth probes; gates
  duplication targets and primary handovers, never a hard veto (see D-023, D-024)
- Per-path reports in both directions, so each end scores its own *send* direction from
  what the peer measured rather than from half a round trip (see D-024)
- Authenticated wire header, keyed from a file, once a shared secret is provisioned (D-025)
- Three-state path machine with asymmetric hysteresis and flap penalty
- Real-time class: single path, duplication, make-before-break, heavy stickiness
- Bulk class: **single best path** for v1 (multipath deferred, see below)
- Classification: STUN watching → vendor prefixes → behavioral heuristic, with flow cache
- Global MTU at minimum across eligible paths, PLPMTUD probing, floor 1280
- Admission control to starve bulk when down to one degraded path
- Cost-aware penalties from projected billing-cycle burn rate
- Routed subnet at home, no double NAT
- Independent web UI reading a state file; direct-link fallback on daemon failure
- Provisioning file install flow

## Deferred to v2

**Bulk multipath aggregation and the resequencer.** This is the hardest single component:
hold-timer tuning, delta gate, buffer management, and the subtlest bugs. Bulk traffic is
elastic and single-path bulk on the best link is genuinely fine for web and updates.

Deferring also buys information. After a few weeks of telemetry you will know how often
the paths actually land within the ~20–30 ms delta window where aggregation pays. If
Starlink and 5G rarely do on your routes, the resequencer buys very little.

When it is built, the key constraint is the **delta gate**: only spread a flow across
paths whose estimated delivery times are within ~20–30 ms. Outside that window the
reorder buffer makes the fast path as slow as the slow one — 40 ms Starlink bonded with
120 ms LTE needs an 80 ms hold, so everything becomes 120 ms. The slow path should carry
traffic only when the fast one is saturated or down.

## Explicitly out of scope

- IPv6 (D-026) - dropped on the WAN rather than carried in the tunnel, for now
- FEC (D-007)
- Off-the-shelf link bonding: MPTCP, glorytun, OpenMPTCProuter (D-008)
- Split tunneling (D-004)
- Fail-closed traffic classes — not a corporate scenario (D-011)
- LAN-based per-device blocking

## Build sequence

**Get the tunnel carrying traffic with full per-path telemetry and the web UI showing it,
before writing any scheduling logic at all.** Watch real link behavior through a few
canyons first. Thresholds will be better with a week of actual data than with any amount
of reasoning up front.

1. **Tunnels and plumbing.** WireGuard per link, home responder, routed subnet, keepalives,
   dynamic DNS. Verify a link can drop and recover without session loss.
2. **Header and echo channel.** Both sequence numbers, timestamps, echo. No scheduling —
   static path selection is fine here.
3. **Measurement.** Loss, burst distribution, jitter, queue delay, percentiles, sample
   counts. Per-path and bidirectional.
4. **Web UI and state file.** Live per-path telemetry, historical graphs, log access.
   This is the instrument for everything after it.
5. **Field data collection.** Drive. Collect. Look at what the links actually do.
   **Deferred, deliberately** (2026-09-01): there was no time for the drive. Recording
   runs continuously on both ends, so this can happen later without further code. Every
   threshold below was therefore set from reasoning rather than measurement, and all of
   them are adjustable at runtime precisely because they are expected to be wrong.
6. **State machine.** Thresholds informed by step 5. **Built** (2026-09-01) without them.
6b. **Bandwidth ceiling.** Reactive, from queueing onset under real traffic; no active
    probes. Feeds duplication-target and handover eligibility ahead of classification, and
    ahead of it being usable to split bulk's path choice from real-time's once step 7
    lands. **Built** (2026-09-01). See D-023.
6c. **Outbound measurement.** Path reports each way, so a send decision stops being made
    from inbound evidence. Wire version 2, rolling upgrade, header authentication
    alongside it. **Built** (2026-09-02). See D-024 and D-025.
7. **Classification.** STUN watching first; it is the highest-value piece.
   **Classifier built** (2026-09-02), **not yet wired in**: `internal/classify` implements
   the full precedence - STUN, vendor prefixes, behavioural catch-all - behind a bounded
   per-flow cache, and is validated against a real capture off the RV's tunnel interface.
   It is still unwired, but the reason has changed. D-020's data path is **built**
   (2026-09-02) behind `-tun` and proven on the real boxes, so the daemon can now read
   plaintext inner packets - which is what a classifier needs and what the loopback relay
   could never give it. What remains of step 7 is calling the classifier from the TUN read
   path and carrying its verdict in the header's class field, plus provisioning the
   per-link WireGuard interfaces for good rather than for a rehearsal. See D-020.
8. **Scheduling and real-time handling.** Duplication, make-before-break, stickiness.
9. **Admission control.** Alongside the scheduler, not after.
10. **Cost tracking and budget bands.**
11. **Fallback, watchdog, rollback.**

Steps 1–5 produce no cleverness and are the most valuable part of the project.

## Install design

The hard part is not the software. It is key exchange, and the fact that the RV needs
config before it has connectivity.

**Bootstrap at home, on the same LAN.** Set up the RV unit in the driveway. Home generates
both keypairs, writes both configs, hands the RV its config over the local network.
Nothing needs to work over the internet during setup.

**A single provisioning file.** The home installer produces one bundle containing:

- Home public key
- Home FQDN and UDP port
- RV private key
- Assigned RV subnet
- Any non-default tunables

One file to copy, one command to run on the RV.

**Auto-detect links, do not configure them.** Enumerate interfaces at startup and
classify by type — ModemManager for cellular, the dish's known address for Starlink,
anything else as generic. Assign default roles by type. The user confirms a list; they
do not name interfaces.

**Ship opinionated defaults for every tunable.** Thresholds, hysteresis windows, probe
cadence, hold timers. All have working defaults, all adjustable in the UI, none required
at install.

**Reaching home:** dynamic DNS, not a static IP. Assume the home IP changes. Cache the
last known good IP to disk and try it in parallel with resolution — a cold boot in a dead
zone must not hang on DNS. Pick a high, unremarkable UDP port; some carriers deprioritize
known VPN ports.

## Operational concerns that must not be skipped

**Startup ordering with slow-appearing links.** The single most likely thing to bite.
Modems take 30+ seconds to register; Starlink takes a minute or two to acquire. The daemon
must start before its links exist and handle them appearing one at a time. Do not
enumerate once at boot and assume that is the world. This happens every single power-on.

**Field upgrades and rollback.** You will change scheduler parameters and find bugs on the
road. A bad update that breaks the tunnel from 800 miles away is unrecoverable without
fallback working. Keep the previous version, boot into it on watchdog failure, and **test
the rollback before needing it.** Highest-value reliability investment in the project.

**Daemon failure behavior.** Watchdog plus static fallback route. Fail to a dumb working
state, never to nothing.

**Persistence across reboots.** Data usage counters, path reputation, learned MTU, flap
history. Losing these on every power cycle means relearning at exactly the moment the RV
is likely moving.

**Clock at cold boot.** Timestamps are meaningless until time is sane. GPS if the RV has
it, otherwise NTP over whatever link comes up first. Hold off trusting measurements until
sync completes.

**DNS.** Where it resolves, behavior during outages, and caching so a dead link does not
stall every lookup. Small thing, very confusing symptoms when wrong.

**Captive portal detection** for campground wifi, with a path to authenticate before the
tunnel comes up.

## Scenario walkthrough: canyon transit

The behavioral spec. Use these as integration test cases.

**Open road, both stable.** Audio duplicated on both paths, de-duplicated at home taking
whichever lands first. Video on the better path alone. Bulk on the best path.

**Canyon approach, Starlink degrading.** Dish obstruction telemetry fires before loss
appears. Demote Starlink to unstable. Do **not** move video immediately — start
duplicating onto 5G, confirm delivery, then stop on Starlink. Pull bulk off Starlink
immediately; a stalled web page costs nothing and every byte not sent on a dying path is
a byte not retransmitted.

**Deep canyon, 5G only.** Scheduler is irrelevant with one path. Admission control is
everything. Drop audio duplication (waste on a link with no spare). Shape video down and
let Zoom's congestion control downshift resolution. Starve bulk.

**Dead zone, both down.** The call drops; nothing to be done. But the source IP never
changed, so TCP sessions do not reset — the page mid-load resumes when connectivity
returns 90 seconds later. This is the payoff of tunneling everything. Set keepalives and
TCP timeouts to survive realistic dead zones: minutes, not seconds.

**Emerging.** The flapping trap. Starlink returns, scores well on a handful of probes,
wins, takes the video, then gets cut again 20 seconds later. Asymmetric hysteresis plus
sample-count gating prevents this. Steering a real-time flow onto a newly recovered path
should require the current path to be genuinely inadequate, not merely worse.

**Forest canopy.** Intermittent obstruction rather than clean blockage — sustained
flapping for an hour. Correct behavior is to **stop trying**: pin real-time to 5G for the
duration and use Starlink only for bulk, where intermittency costs nothing. This is what
the flap penalty exists for.
