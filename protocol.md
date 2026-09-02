# Protocol and algorithms

The daemon is a userspace UDP tunnel carrying WireGuard packets as payload. WireGuard
handles crypto and identity; this layer handles sequencing, measurement, and scheduling.

**Do not write crypto.**

## Header

Sits between the outer UDP header and the WireGuard packet.

| Field | Purpose |
|---|---|
| Global sequence | Assigned **before** path selection. Used to resequence bulk traffic. |
| Per-path sequence | Assigned **at transmit on a specific path**. Gaps are unambiguous loss on that path. |
| Path ID | Which tunnel this went out of. |
| Send timestamp | For delay measurement. |
| Echo field | Receiver reports back arrival times and per-path loss. |
| Class | Real-time or bulk. |

### Why two sequence numbers

This is the detail that is expensive to retrofit. With only a global sequence you cannot
distinguish "lost on path B" from "took slower path C and has not arrived yet."
Reordering across paths is normal, so global-sequence gaps mean almost nothing. Per-path
sequence is strictly monotonic per path, so any gap is real loss.

## Measurement

### Passive, from data packets

Use the four-timestamp model (as in NTP and TWAMP): sender transmit, receiver arrival,
receiver response transmit, sender arrival. Yields RTT with **no clock sync**, and
one-way delay if clocks are synced.

Derive per path:

- **Loss rate** from per-path sequence gaps.
- **Burst length distribution**, not just a rate. For voice, 1% loss in bursts of 20
  packets is far worse than 1% scattered — concealment handles isolated loss but not
  400 ms of silence.
- **Jitter** via the RFC 3550 interarrival estimator.
- **Queue delay** — see below.

### Queue delay without clock sync

The most important derived metric, and the reason local qdisc backlog is not enough:
a cellular carrier can hold two seconds of packets in its own buffer while the local
backlog reads near zero.

```
queue_delay = current_delay - rolling_min_delay   # 10 s window
```

Any constant clock offset cancels in the subtraction, so this needs no synchronization.
Same technique as BBR and Copa. **Re-arm the minimum periodically** or a persistently
congested path bakes its queue into the baseline.

### Statistics to keep

Keep **percentiles, not means**. Starlink's satellite handovers produce latency spikes
that a mean hides completely, and it is the tail that sizes the receiver's jitter buffer.

- Ring buffer of ~200 recent samples per path → p95, p99.
- EWMA alongside, as the fast signal driving state transitions.
- **Track sample count per window.** Ten packets tells you nothing about loss rate.
  Widen uncertainty accordingly and never promote a path on thin statistics.

### Active probing

Passive measurement is structurally blind on idle paths — which are exactly the paths
you need to know about before steering onto them.

- **Probe rate inversely proportional to data volume on that path.** Busy path, probe
  rarely. Idle path, full cadence. Down path, slow keepalive to detect recovery.
  **This has to be per path, and the reason only appears once scheduling exists.** While
  duplication was unconditional every path saw every packet, so a session-wide "have we
  sent recently" timer paced reports correctly. Once one path carries the traffic, that
  timer is held permanently fresh by the chosen path and the idle ones are never probed
  again — so they stop being measured, which loses exactly the paths a call might have to
  be moved onto.
- **Cadence must match the reaction target: roughly 100–200 ms per path.** Probing
  slower means a degraded path stays selected for the probe interval, which is audible.
- **Pad probes to typical data packet size.** A 60 B probe experiences different
  serialization delay than a 1300 B packet — about 5 ms difference on a 2 Mbps link,
  enough to bias comparisons.
- **Never give probes priority.** They must sit in the same queue as data. A probe that
  skips the queue reports a path that does not exist.
- **Cost:** ~100 B every 200 ms is ~4 kbps, trivial for bandwidth but ~40 MB/month/path
  against a cap. Back off idle-path probing when a link is metered and near its cap,
  accepting slower recovery detection.

### Feedback channel

Both directions need independent measurement — paths are asymmetric, and a congested
uplink with a clean downlink is common on cellular.

- Piggyback reports on reverse-direction data when it exists (free).
- Standalone reports only when the reverse direction is idle.
- ~10 reports/sec with a compact format is a few kbps.
- **One report covers all paths at once**, so the sender gets a consistent snapshot
  rather than measurements from slightly different moments.

### Path reports: telling the peer about its own send direction

The echo channel above yields a round trip, and a round trip cannot say which direction
the delay was in. Everything else a node measures — spread, jitter, queue delay, loss,
burst distribution — is taken from packets *arriving*. So a node choosing which path to
**transmit** on has only inbound evidence to choose from, which is the wrong direction
and, on 2026-09-01, sent a live upload onto a 512 kbps standby link because a download
had congested the chosen path's downlink.

The measurement already exists; it is simply on the other box. Each end therefore reports
back, once a second per path, what it observed on the peer's transmissions:

    p95 spread, queue delay, jitter — tenths of a millisecond, above that path's own floor
    recent loss — parts per thousand
    burst ratio — tenths

Ten bytes per path. These ride only on standalone reports, never on data, so a data
packet's header does not have to be budgeted for them.

**No clock sync is needed, and none would help.** Every figure is a difference against
the reporting path's own floor, so the unknown offset between the two clocks cancels
exactly as it does for queue delay. Absolute one-way delay would need synchronisation and
is not what the decision turns on; the delay used for scoring is instead

    outbound ≈ rttFloor/2 + reported queue delay

— the round-trip **floor**, not the live round trip, because the live figure contains
queueing from both directions and that is precisely the contamination being removed. The
symmetric half is an assumption and a wrong one on some links, but it is the stable half.
The part that moves is measured on the correct side.

A node with no report in hand falls back to half a round trip and its inbound statistics,
which is what every build before wire version 2 did. See D-024.

### Header authentication

Once path reports feed path selection, an injected packet can steer the vehicle's
traffic. Version 2 headers carry an 8-byte truncated HMAC-SHA256 over the header when a
shared key is configured, read from a file rather than the settings the web interface
serves. It does not protect the payload — WireGuard does that — only the metadata. See
D-025.

## Path state machine

Three states with hysteresis. Without hysteresis this flaps constantly.

| State | Meaning |
|---|---|
| **Stable** | Meeting thresholds. Eligible for everything. |
| **Unstable** | Degraded. Still eligible, carries a penalty. Not cut off. |
| **Down** | Requires **both** probe failure and data-plane silence — a path with no traffic must not be declared dead on probe loss alone. |

Transitions:

- Stable → Unstable on sustained threshold breach (~3 consecutive probe intervals).
- Unstable → Stable requires a **longer** clean period than the breach that demoted it
  (~10 intervals). Asymmetric by design.
- Out-of-band signals (Starlink obstruction telemetry, cellular RSRP/SINR) may trigger
  **demotion** early. They may **not** trigger promotion.
- **Flap penalty:** a path that oscillates is penalized for oscillating, independently of
  its instantaneous score. Track transitions in a window and suppress after N. A path
  that flickers for an hour under forest canopy should be abandoned for real-time, not
  repeatedly retried.

Babel's metric hysteresis is a good documented model.

## Scoring

```
score_i = owd_p95_i
        + (local_backlog_i / drain_rate_i)
        + queue_delay_i
        + penalty_i
```

Send on `min(score)`.

- **Use p95 of one-way delay, not the mean.** Tail latency is what matters.
- For real-time, **jitter and loss burst length matter more than mean latency.** A 60 ms
  path with 5 ms jitter beats a 40 ms path with 40 ms jitter, because the jitter buffer
  sizes to the tail.
- Consider a **composite quality score** rather than summing raw components. Estimated
  MOS from loss, latency and jitter via the ITU-T G.107 E-model gives a single number per
  path and largely eliminates the weighting-tuning problem. The relative weight of loss
  versus jitter for perceived voice quality is already well-researched — do not re-derive it.

`penalty_i` encodes: metered-link surcharge (from budget band), flow affinity stickiness,
recent instability, and flap suppression.

**Stickiness is mandatory.** Without it, established flows oscillate between paths every
time scores cross.

### Latency budget context

ITU-T G.114 puts 150 ms one-way mouth-to-ear as the threshold for unimpaired conversation
and roughly 400 ms as the limit of usability. Codec and jitter buffer consume 40–60 ms
before the network is touched. The hairpin through home consumes more. Path selection has
to be good to compensate for a handicap that was deliberately accepted.

## Real-time handling

**Bypass the resequencer entirely.** Zoom, Teams and Meet run UDP with their own jitter
buffers and packet loss concealment. They would rather lose a packet than wait for it.
Adding a reorder hold on top of their jitter buffer directly degrades call quality.

### Duplication

Audio is ~40 kbps. Sending it down two paths and de-duplicating by sequence number at the
far end gives seamless failover with **zero switchover gap** plus the best-case latency of
both paths on every packet. Cost is negligible.

Video at ~1.5 Mbps is a harder call on a metered link. Make duplication a policy decision
per class and per budget band: audio always duplicated when a second path exists and
budget is green; video duplicated only when a link is unstable or an unmetered path is
available.

Drop duplication entirely when down to one path — pure waste on a link with none to spare.

### Make-before-break

Never cut then connect. When the scheduler wants to move a flow: start duplicating onto
the new path, confirm delivery, then stop sending on the old one. A gap is audible.

**Heavy stickiness on real-time flows.** A conference flow should move only when its
current path degrades below an absolute quality floor, not because another path scored
marginally better.

**Freeze during instability.** If two paths are both flapping, pick the least bad and
hold. Oscillation is worse than a mediocre path.

## Classification

Needed to identify conferencing traffic. Run in precedence order, first match wins.

1. **STUN watching — the primary signal.** Every WebRTC-based app (Meet, Teams, Zoom
   browser path) runs ICE candidate exchange over STUN before media flows. STUN binding
   requests are trivially identifiable and reveal the exact 5-tuple the media will use
   **before the first media packet arrives.** This is a flow-birth announcement. It is
   protocol-based rather than vendor-based, so it works for apps never configured,
   survives IP range changes, and needs no vendor feed.
2. **RTP header detection.** Media saying what it is. Confirmed after three packets
   agreeing on a 32-bit SSRC, which takes 60 ms of audio and less than one video frame.
   This is what identifies **video**, which the behavioural test below cannot — see the
   warning under that table. It also covers the case STUN cannot: a daemon that started
   mid-call never saw the ICE exchange. Works on SRTP, where the payload is encrypted but
   the header is not. See D-030.
3. **Vendor prefix matching**, for non-WebRTC paths such as Zoom's native client.
4. **Behavioral heuristic**, as catch-all.

Cache classification per 5-tuple in a flow cache so subsequent packets are not
re-inspected.

### Vendor feeds

Quality varies significantly.

- **Microsoft** — a real REST API at `endpoints.office.com` returning JSON, with a
  `/changes/` delta endpoint and RSS for change notification. Endpoint sets are tagged by
  category, and the **Optimize** category is specifically the latency-sensitive traffic,
  mapping directly onto the real-time class. Poll the version endpoint, refetch on change.
  Microsoft explicitly intends this for SD-WAN devices.
- **Zoom** — plain-text IP range files split by product. No versioned API, no clean change
  feed. Scrape and diff; you own the staleness problem.
- **Google Meet** — weakest. Published netblocks are not Meet-specific in a useful way and
  media shares ranges with everything else Google. Prefix matching will not isolate it.

Treat vendor lists as a **hint**, not a foundation. They rot fast.

### Behavioral heuristic

Do **not** treat all UDP as real-time. That was reasonable until QUIC. HTTP/3 runs over
UDP/443 and carries enormous bulk volume. Under an all-UDP rule a YouTube stream gets
duplicated low-latency treatment and burns metered bandwidth.

The **inverse holds**: all TCP is definitively not real-time. Use it as a free first-pass
exclusion.

Within UDP, discriminate on behavior rather than port:

| Signal | RTP **audio** | QUIC bulk |
|---|---|---|
| Packet size | 60–250 B, tight distribution | MTU-sized, 1200–1400 B |
| Inter-packet gap | ~20 ms, very low variance | bursty |
| Direction | symmetric bidirectional | heavily asymmetric |
| Flow rate | flat, codec-determined | ramps to fill available bandwidth |

Inter-packet-gap variance plus mean packet size separates these almost perfectly. A
conferencing audio flow is metronomic and small; nothing else looks like that.

> **This table describes audio only, and reading it as "media" is a mistake this project
> already made.** Video RTP is MTU-sized, because a frame is fragmented across as many
> packets as it takes, and frame-bursty, because those go out together and then nothing
> happens until the next frame. It therefore fails *both* columns and a classifier built
> on this table alone calls a 1080p stream bulk — the wrong answer to the one question
> that matters, given the primary use case is a video call. Video is identified from the
> RTP header instead (signal 2 above, D-030). What remains for this table is media
> carrying no RTP framing at all, which is rare, so its thresholds are set conservatively:
> a missed flow gets bulk treatment, while a false positive duplicates a download over a
> metered link.

## Admission control

**When down to one degraded path, the scheduler stops helping — there is nothing to
schedule. Queue management becomes the entire game.**

The failure mode is specific: web browsing and map tile fetches fill the uplink queue,
and the standing queue adds hundreds of milliseconds to the call. One person loading a
webpage destroys the meeting.

Single-path degraded mode needs admission control, not just prioritization:

- Real-time class gets an absolute reservation.
- Bulk is shaped down aggressively to whatever remains.
- **If measured queue delay on the sole path exceeds a threshold, stop admitting bulk
  entirely** and let it queue at the ingress where it costs nothing.

Video is the honest casualty. Zoom's encoder cannot be controlled directly, but its flow
can be shaped, and its congestion control will downshift resolution. That is the correct
outcome: audio survives, video degrades.

**Build admission control alongside the scheduler, not after it.** It is the part that
saves the meeting.

## Deliberately excluded

- **FEC.** See `decisions.md` D-007. If it is ever reconsidered, gate it on the
  congestion-versus-radio-loss discriminator: queue delay elevated + loss means congestion
  (FEC is actively harmful, adds traffic to an overfull queue); queue delay at baseline +
  loss means radio-layer loss (FEC could help). That discriminator is free from the
  existing measurements.
- **Bulk multipath aggregation and the resequencer.** Deferred to v2. See
  `scope-v1.md`.
