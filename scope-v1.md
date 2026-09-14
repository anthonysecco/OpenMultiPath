# v1 scope

## In scope

- WireGuard overlay, one tunnel per WAN link, all terminating on one home UDP port
- Userspace multipath daemon with the header from `protocol.md`
- Passive measurement from data packets; active probes scaled inversely to path traffic
- Queue delay inferred from delay above rolling minimum (no clock sync required)
- Per-path link speed measured on demand by the flow test, never estimated; each end shapes
  its sends to 90% of it, and an unmeasured link is unlimited. Gates duplication targets
  and primary handovers, never a hard veto (see D-055, which replaced D-023's reactive
  ceiling)
- Per-path reports in both directions, so each end scores its own *send* direction from
  what the peer measured rather than from half a round trip (see D-024)
- Authenticated wire header, keyed from a file, once a shared secret is provisioned (D-025)
- Three-state path machine with asymmetric hysteresis and flap penalty
- Real-time class: single path, duplication, make-before-break, heavy stickiness
- Bulk class: **single best path** for v1 (multipath deferred, see below)
- Classification: STUN watching → vendor prefixes → behavioral heuristic, with flow cache
- Three classes: real-time, **transactional** (page loads, DNS, API calls) and bulk,
  with transactional split from bulk by sustained rate over a dwell (D-037)
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

*(The above was written before D-052 built bulk's per-packet cascade + resequencer.
It is done for bulk. What follows is a new, still-open gap found afterward.)*

## Future enhancement: give transactional traffic a relief valve (built as D-064)

*(Built 2026-09-14 as direction 2 below; `decisions.md` D-064 is the as-built record and
overrides this note where they disagree.)*

**The gap, found 2026-09-14 investigating a real VoWiFi call (UDP/4500) with an upload
speed test running concurrently.** In `bulk_scheduler: cascade` mode, D-052's per-packet
cascade (`internal/relay/cascade.go`) is bulk-only — D-052 says explicitly it "supersedes
D-031's gate and D-044's per-flow spread **in cascade mode**." Transactional gets neither:
`scheduler.buildTx` pins it rigidly to the primary (`d.txTrans = []uint8{s.primary}`), with
no spread and no cascade. A speed test's many parallel TCP connections mostly classify as
*transactional*, not bulk (most individual connections don't sustain
`classify_bulk_kbps` for the full `classify_bulk_dwell_ms` dwell even though their
aggregate is large) — so that whole aggregate has nowhere to go but the primary.

That became a real problem because Starlink was primary at the time (slightly lower
latency than the AT&T LTE link at that moment — an ordinary, expected tie-break, not a
bug). With transactional pinned to primary and no relief valve, the speed test's
transactional load piled entirely onto Starlink's ~562 kbps shaped budget with nowhere
else to go, visibly maxing out Starlink's send rate and degrading the concurrent
VoWiFi call sharing that path — even though real-time duplication onto both paths was
confirmed still working correctly throughout.

**Two designs were discussed, and the second is the one to build:**

1. **Rejected direction: mirror bulk's per-packet cascade for transactional, reversed.**
   Bulk fills highest-latency-first because it doesn't care about latency. Transactional
   could analogously fill lowest-latency-first (primary) and spill onto higher-latency
   paths under pressure, flipping to bulk's ordering if/when the classifier promotes the
   flow to bulk mid-flight (classification is already decided fresh per packet, so this
   transition would fall out naturally with no special-casing). **Risk:** this needs the
   same far-end resequencer bulk uses, and the resequencer's hold budget
   (`resequencer_max_hold_ms`, 200 ms default) would tax exactly the latency-sensitive
   traffic transactional exists to protect — `scheduler.admit()`'s own comment on why
   transactional is never gated is "withholding it was the daemon destroying the traffic
   the user is watching in order to protect the traffic they are listening to." Trading a
   drop for an up-to-200ms reorder hold is a smaller version of the same harm, not an
   escape from it.

2. **Chosen direction: per-flow migration, not per-packet spreading.** Track each
   transactional flow's *currently assigned* path (new state — today's per-flow hash
   spread, `txFor`'s `txBulkSpread` lookup, is stateless and is superseded by the cascade
   in cascade mode anyway per D-052). When a flow's current path runs out of room in its
   *transactional* band specifically, migrate the whole flow — not per-packet — to the
   next-best (lowest-latency, among paths with room) path, and stay there until it too
   runs out. Because a flow lives entirely on one path at any moment, this needs no
   resequencer: at most one brief reordering event at the migration instant (which TCP
   already tolerates from an ordinary route change), never sustained interleaving. This
   sidesteps D-044's original spread failure too ("spreading a flow into a receiver that
   cannot reorder it... fell to 4 Mbit").

**What building direction 2 needs:**
- A transactional-band-specific room check, parallel to `pathShaper.hasRoom()` (which
  today only looks at the *bulk* band's backlog — D-060 gave transactional its own band
  but nothing reads its backlog yet).
- A per-flow "current path" table for transactional flows (doesn't exist today).
- Stickiness matching D-033's reasoning for bulk: migrate only when the current path is
  actually out of room, never chasing a marginally better one — D-033: "a scheduler
  chasing the better link each time two scores crossed would pay for the move repeatedly
  in exactly the traffic it was trying to speed up."
- A decision on the ranking metric for "next best": probably live/scoring delay (which
  reflects current congestion), not `baseDelayMs` (bulk's cascade metric, chosen
  specifically to *ignore* self-inflicted queue) — the trigger here is congestion, so the
  candidate check should care whether the destination is also congested.
- Sharing a path that also carries a real-time duplicate is already fine, per D-056 (the
  shaper protects real-time regardless of what else is queued behind it) — no new
  precedent needed there.

**Read before starting:** D-033 (stickiness rationale, and the original "same for
duplication targets" exclusion that D-056 already reopened for cascade mode), D-044/045/046
(the old per-flow spread's membership rules — a similar health/membership gate may be
needed for migration candidates), D-052 (bulk's cascade — the mechanism *not* to copy
wholesale here), D-056 (path-sharing with real-time is settled), D-060 (transactional's
shaper band). Code: `internal/relay/scheduler.go` (`buildTx`, `txFor`),
`internal/relay/cascade.go` (bulk's cascade, for contrast), `internal/relay/shaper.go`
(`hasRoom`, band definitions).

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
    lands. **Built** (2026-09-01). See D-023. **Replaced** (2026-09-13) by measured link
    speed and shaping to 90% of it; see D-055.
6c. **Outbound measurement.** Path reports each way, so a send decision stops being made
    from inbound evidence. Wire version 2, rolling upgrade, header authentication
    alongside it. **Built** (2026-09-02). See D-024 and D-025.
7. **Classification.** STUN watching first; it is the highest-value piece.
   **Classifier built** (2026-09-02), **not yet wired in**: `internal/classify` implements
   the full precedence - STUN, vendor prefixes, behavioural catch-all - behind a bounded
   per-flow cache, and is validated against a real capture off the RV's tunnel interface.
   **Wired in and done** (2026-09-02). The classifier runs on every packet read from the
   TUN device and its verdict is carried in the header's class field, on both ends. It
   runs only where payloads are plaintext: below WireGuard they are ciphertext, and a
   5-tuple parser pointed at an encrypted blob does not fail, it finds plausible garbage -
   so the loopback relay says plainly in its log that it is not classifying.
   Counters for what was decided go to the log, because "saw no real-time traffic" and
   "was not classifying" otherwise look identical from a campground.

   Verified end to end in the running daemon: six STUN binding requests came out six
   real-time, and sixty QUIC-shaped packets came out twenty-three unclassified - the
   behavioural sampling window - then thirty-seven bulk.

   Nothing reads the class yet. That is step 8.
8. **Scheduling and real-time handling.** Duplication, make-before-break, stickiness.
   **Class-aware scheduling built** (2026-09-02). The scheduler publishes a transmit set
   per class rather than one for everything, so redundancy goes where it is worth paying
   for: real-time is duplicated by policy, bulk rides a single path whatever the policy
   says, and make-before-break overlap is real-time only. Anything not positively
   identified as real-time is carried as bulk. The duplication default moves from
   handovers-only to duplicating real-time while its path is degraded, which D-022 could
   not do while nothing could tell a call from a download. Verified on the wire: sixty
   real-time packets went out both paths, sixty bulk packets went out one.
   **Bulk steering built** (2026-09-05, D-033), which completes this step. Bulk takes the
   best eligible path real-time is not using, and shares the primary only when real-time
   is on all of them. One rule covers two walkthrough cases: "pull bulk off Starlink
   immediately" on a canyon approach, and "use Starlink only for bulk" under forest
   canopy - the latter is why an unstable path is still a valid target. Real-time's whole
   transmit set is avoided, not just the primary, so a download never lands on the path
   carrying a make-before-break overlap. Off entirely below WireGuard, where everything is
   unclassified and steering would move all traffic onto the second-best link.
9. **Admission control.** Alongside the scheduler, not after.
   **Built** (2026-09-04, D-031). Bulk stops being sent entirely when the path carrying
   real-time is also carrying it and the peer reports that path's send direction queueing
   past a threshold. Dropped at the ingress, so the sending stack backs off and the queue
   re-forms in a LAN client rather than in the WAN uplink. Real-time is never withheld,
   which is what lets this be a gate rather than a shaper - the class that must not be
   starved is the one too small to need pacing. Shuts on the first evaluation over the
   line, reopens only after five seconds clear, and never fires in blind mode or when the
   classes are already on separate paths.
   Still to come here: shaping video down within real-time so audio survives while video
   shrinks, which needs audio and video distinguished inside the class.
10. **Cost tracking and budget bands.**
    **Built** (2026-09-06, D-034). Per-link billing-cycle accounting from the kernel's
    own interface counters rather than vnstat, accumulated as deltas and persisted so a
    power cycle does not lose the month. Three bands from projected burn drive a scoring
    surcharge in R points, and the sacrifice order is architecture.md's: duplication
    stops on any non-green link, bulk prefers a green one and never rides a red one, and
    real-time is never blocked - a red link still carries the call when it is the only
    one left, because a working call beats an overage. A link nobody has configured is
    unmetered and green.
    Still to come here: deferrable bulk, so backups and updates queue for an unmetered
    link rather than merely preferring one.
11. **Fallback, watchdog, rollback.**
    **Built** (2026-09-06, D-035). Three shell tools sharing nothing with the daemon
    they watch: `omp-watchdog` decides, `omp-fallback` changes routing, `omp-deploy`
    installs a version on probation. Health needs both a state file that is still
    advancing - the one failure systemd cannot see - and a tunnel that answers.
    Fallback moves one ip rule and deliberately leaves the tunnel interface up, so the
    watchdog can still tell when it recovers; taking it down would make fallback a
    one-way door. A bad upgrade is rolled back by the vehicle itself against a deadline
    written at deploy time, and rollback is tried before fallback because it restores a
    working tunnel rather than a working workaround.

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
