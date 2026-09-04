// Package config holds the daemon's adjustable settings.
//
// Every value has a working default, so a missing or partial file is not
// an error and nothing has to be set for the daemon to run correctly. The
// file exists to let the web interface change a setting on a running
// system, not to make configuration a prerequisite.
//
// Values are clamped rather than trusted. They are edited through a web
// form by a person who may be tired, in a campground, diagnosing
// something else, and a mistyped zero that turned a report interval into
// a busy loop would be a poor way to find that out.
package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Config is the set of settings that can be changed on a running daemon.
//
// The scheduler's thresholds are here alongside the measurement cadences,
// and every one of them is a guess. They were chosen from the reasoning in
// protocol.md rather than from field data, because the drive that would
// have produced the data has not happened. That is the whole reason they
// are adjustable at runtime: the expectation is that they are wrong and
// will be corrected from the passenger seat, not that they are right.
type Config struct {
	// EchoIntervalMs is how often measurement feedback is sent. It bounds
	// how quickly a change in a path can be noticed, so protocol.md ties
	// it to the 100-200 ms reaction target.
	EchoIntervalMs int `json:"echo_interval_ms"`

	// ProbeIntervalSeconds is how often path MTU is probed. Path MTU
	// changes on tower handover and 5G-to-LTE fallback, so probing has to
	// continue, but it changes rarely enough not to want a fast cadence.
	ProbeIntervalSeconds int `json:"probe_interval_seconds"`

	// StateIntervalMs is how often the state file is rewritten for the
	// web interface.
	StateIntervalMs int `json:"state_interval_ms"`

	// StatsIntervalSeconds is how often measurements are written to the
	// log.
	StatsIntervalSeconds int `json:"stats_interval_seconds"`

	// RecordIntervalSeconds is how often a snapshot is appended to the
	// history log. Finer than this buys little for the questions the
	// field data has to answer - how long an outage lasted, how often a
	// link flapped - and costs disk on a box nobody visits for months.
	RecordIntervalSeconds int `json:"record_interval_seconds"`

	// RecordMaxMegabytes is the size at which the history log rotates,
	// and RecordKeepFiles how many older generations are kept. The two
	// together are a hard ceiling on disk: the default 32 MB across 8
	// generations is 256 MB, which at the default cadence holds roughly
	// a fortnight of driving.
	RecordMaxMegabytes int `json:"record_max_megabytes"`
	RecordKeepFiles    int `json:"record_keep_files"`

	// EvalIntervalMs is how often the path state machine runs. protocol.md
	// ties the reaction target to 100-200 ms: a degraded path stays
	// selected for one of these, and that delay is audible.
	EvalIntervalMs int `json:"eval_interval_ms"`

	// The thresholds that separate a stable path from a degraded one.
	// Breaching any of them counts as a breach; none of them is a
	// comparison against another path, because "unstable" means degraded
	// against its own floor, not worse than its neighbour. Which path wins
	// is a scoring question, kept deliberately separate.
	UnstableLossPercent  int `json:"unstable_loss_percent"`
	UnstableQueueDelayMs int `json:"unstable_queue_delay_ms"`
	UnstableJitterMs     int `json:"unstable_jitter_ms"`

	// DemoteIntervals and PromoteIntervals are the asymmetric hysteresis.
	// Promotion deliberately takes longer than demotion: a path that has
	// just come back has proved much less than a path that has just
	// broken.
	DemoteIntervals  int `json:"demote_intervals"`
	PromoteIntervals int `json:"promote_intervals"`

	// DownSilenceMs and DownProbePackets are both required before a path
	// is called down. protocol.md is explicit that a path with no traffic
	// must not be declared dead on probe loss alone, so silence only
	// counts once we have actually sent something into it.
	DownSilenceMs    int `json:"down_silence_ms"`
	DownProbePackets int `json:"down_probe_packets"`

	// The flap penalty. A path that oscillates is penalised for
	// oscillating, independently of how good it looks at this instant.
	// This is what stops an hour under forest canopy turning into an hour
	// of steering the call back and forth.
	FlapWindowSeconds int `json:"flap_window_seconds"`
	FlapThreshold     int `json:"flap_threshold"`

	// Scoring penalties and margins, in E-model R points. R is used rather
	// than MOS because it is naturally an integer scale, and because the
	// impairments the model adds up are additive in R and not in MOS.
	FlapPenaltyR     int `json:"flap_penalty_r"`
	UnstablePenaltyR int `json:"unstable_penalty_r"`
	SwitchMarginR    int `json:"switch_margin_r"`
	MinAcceptableR   int `json:"min_acceptable_r"`

	// SwitchHoldIntervals is how long a challenger has to stay better
	// before the flow actually moves. Stickiness is mandatory: without it
	// an established flow oscillates every time two scores cross.
	SwitchHoldIntervals int `json:"switch_hold_intervals"`

	// BaseDelayMs is the mouth-to-ear delay the network is not responsible
	// for - codec framing, the far end's fixed buffer, the hairpin through
	// home. It is added to the measured delay before scoring so the
	// G.107 curve is walked at roughly the right place on its knee rather
	// than from zero.
	BaseDelayMs int `json:"base_delay_ms"`

	// Make-before-break bounds. MBBMinMs is the shortest overlap worth
	// having, MBBMaxMs the point at which an unconfirmed new path stops
	// being worth paying double for.
	MBBMinMs int `json:"mbb_min_ms"`
	MBBMaxMs int `json:"mbb_max_ms"`

	// The reactive bandwidth ceiling of D-023.
	//
	// BWOnsetMs is how much queueing in our own send direction counts as the
	// link having started to fill. BWMinLoadKbps is the rate below which a
	// path is carrying too little for its behaviour to mean anything, so
	// nothing is concluded from it either way. BWHeadroomPercent is the
	// margin a path must have spare before traffic is steered onto it, since
	// arriving exactly at the estimated ceiling is arriving at the wall.
	BWOnsetMs         int `json:"bw_onset_ms"`
	BWMinLoadKbps     int `json:"bw_min_load_kbps"`
	BWHeadroomPercent int `json:"bw_headroom_percent"`

	// ReportIntervalMs is how often each end tells the other what it has
	// measured on the other's transmissions - the far end's only source of
	// truth about its own send direction. Slower than the echo cadence on
	// purpose: these are smoothed statistics that do not move packet to
	// packet, and on a 512 kbps standby link every header byte is counted.
	ReportIntervalMs int `json:"report_interval_ms"`

	// BWFallbackKbps is what a path is assumed to carry before it has ever
	// been seen to queue. Zero means "unknown", which is the default and
	// disables the gate rather than guessing: never having watched a path
	// fill up is not evidence that it is small. Set it where a plan's
	// ceiling is known in advance - a 512k satellite standby tier is the
	// case this exists for.
	BWFallbackKbps int `json:"bw_fallback_kbps"`

	// The classification thresholds of step 7. The two that matter are
	// ClassifyRTPMaxBytes and ClassifyGapVarianceMs: protocol.md's claim
	// is that mean packet size and inter-packet-gap variance separate RTP
	// media from QUIC bulk almost perfectly, and these are where that
	// claim is set. They only ever apply to the behavioural catch-all -
	// a flow identified by STUN is not subject to them.
	ClassifySamplePackets int `json:"classify_sample_packets"`
	ClassifyRTPMaxBytes   int `json:"classify_rtp_max_bytes"`
	ClassifyGapVarianceMs int `json:"classify_gap_variance_ms"`

	// ClassifyMaxFlows bounds the flow cache and ClassifyFlowIdleSeconds
	// is how long a silent conversation is kept in it. The ceiling is a
	// memory bound on a box with little of it; the idle timeout is what
	// stops a reused port pair inheriting the last flow's class.
	ClassifyMaxFlows        int `json:"classify_max_flows"`
	ClassifyFlowIdleSeconds int `json:"classify_flow_idle_seconds"`

	// DuplicateMode decides when a packet goes out more than one path.
	// See DuplicateModes for the meanings.
	DuplicateMode string `json:"duplicate_mode"`

	// Admission control, step 9. When the path carrying the call is also
	// carrying bulk and its queue is building, bulk stops being admitted:
	// it is dropped here at the ingress, where the cost is a stalled
	// download and the sending stack backing off on its own. Letting it
	// through instead feeds a queue that is already adding hundreds of
	// milliseconds to the call, which is protocol.md's "one person loading
	// a webpage destroys the meeting".
	//
	// AdmissionQueueDelayMs sits deliberately above UnstableQueueDelayMs.
	// Demoting a path and steering around it is the cheaper answer and
	// should be tried first; starving bulk is what is left when there is
	// nowhere to steer to.
	AdmissionQueueDelayMs int `json:"admission_queue_delay_ms"`

	// AdmissionRecoverIntervals is the asymmetric half, for the same
	// reason DemoteIntervals and PromoteIntervals differ. The gate shuts
	// on the first evaluation that sees the queue over the line, because
	// the call is being damaged as it is measured, and reopens only after
	// the queue has stayed clear this many evaluations running. Reopening
	// as eagerly as it shut would oscillate, and every oscillation is
	// another burst of standing queue through the call.
	AdmissionRecoverIntervals int `json:"admission_recover_intervals"`
}

// The duplication policies, in increasing order of cost.
const (
	// DuplicateOff sends one copy, always. Switching becomes
	// break-before-make, which is audible; this exists for a link where
	// every byte is counted.
	DuplicateOff = "off"

	// DuplicateSwitching duplicates only during a make-before-break
	// handover. No longer the default - see DuplicateUnstable - but kept
	// as the setting for a link where every byte is counted and even
	// insurance is too expensive.
	DuplicateSwitching = "switching"

	// DuplicateUnstable additionally duplicates while the chosen path is
	// degraded, and is the default.
	//
	// It became the right default when step 8 made duplication a per-class
	// decision. D-022 chose handovers-only because nothing could tell a
	// call from a download, so any broader policy mirrored bulk onto the
	// 512k standby link and collapsed it. Bulk now rides one path whatever
	// this is set to, so the cost of this setting is a second copy of the
	// real-time flow, taken only while the path carrying it is degraded,
	// and only onto a path with the measured capacity to hold it.
	//
	// Which is insurance bought exactly when the risk appears and not
	// before - the canyon approach in scope-v1.md, where the dish starts
	// to fail and audio wants a second route before the first one stops.
	DuplicateUnstable = "unstable"

	// DuplicateAlways is the old unconditional behaviour, kept as an
	// escape hatch.
	DuplicateAlways = "always"
)

// DuplicateModes is every accepted value, in the order the interface
// offers them.
var DuplicateModes = []string{DuplicateOff, DuplicateSwitching, DuplicateUnstable, DuplicateAlways}

// bound describes the permitted range of one setting, and is also what the
// web interface renders as the field's limits.
type bound struct {
	Min, Max, Default int
}

// Bounds are the accepted ranges. The lower limits are the point below
// which a setting would do more harm than good rather than merely being
// aggressive.
var Bounds = map[string]bound{
	"echo_interval_ms":       {Min: 20, Max: 5_000, Default: 100},
	"probe_interval_seconds": {Min: 5, Max: 3_600, Default: 15},
	"state_interval_ms":      {Min: 200, Max: 60_000, Default: 1_000},
	"stats_interval_seconds": {Min: 5, Max: 3_600, Default: 30},

	"record_interval_seconds": {Min: 1, Max: 3_600, Default: 5},
	"record_max_megabytes":    {Min: 1, Max: 4_096, Default: 32},
	"record_keep_files":       {Min: 1, Max: 100, Default: 8},

	// 200 ms puts the state machine at the slow end of protocol.md's
	// 100-200 ms reaction target, which is deliberate while every
	// threshold below it is still a guess: reacting slowly to a wrong
	// threshold is cheaper than reacting quickly to one.
	"eval_interval_ms": {Min: 20, Max: 5_000, Default: 200},

	"unstable_loss_percent":   {Min: 1, Max: 100, Default: 2},
	"unstable_queue_delay_ms": {Min: 5, Max: 5_000, Default: 100},
	"unstable_jitter_ms":      {Min: 1, Max: 1_000, Default: 30},

	// Above unstable_queue_delay_ms on purpose: a path is called unstable
	// at 100 ms, and bulk is starved at 150 ms only if it is still sharing
	// that path with the call. Twenty-five evaluations is five seconds at
	// the default cadence - long enough that a download does not stutter
	// back and forth across the threshold.
	"admission_queue_delay_ms":    {Min: 10, Max: 5_000, Default: 150},
	"admission_recover_intervals": {Min: 1, Max: 1_000, Default: 25},

	// Three intervals to demote, ten to promote, straight from
	// protocol.md. At the default cadence that is 600 ms down and 2 s up.
	"demote_intervals":  {Min: 1, Max: 100, Default: 3},
	"promote_intervals": {Min: 1, Max: 1_000, Default: 10},

	"down_silence_ms":    {Min: 200, Max: 60_000, Default: 3_000},
	"down_probe_packets": {Min: 1, Max: 1_000, Default: 5},

	"flap_window_seconds": {Min: 10, Max: 86_400, Default: 600},
	"flap_threshold":      {Min: 2, Max: 1_000, Default: 6},

	// 15 R points is roughly a whole MOS point in the middle of the scale,
	// which is the intent: a flapping path should lose to a steadily
	// mediocre one rather than merely be ranked below it.
	"flap_penalty_r":     {Min: 0, Max: 100, Default: 15},
	"unstable_penalty_r": {Min: 0, Max: 100, Default: 10},
	"switch_margin_r":    {Min: 0, Max: 100, Default: 5},

	// R 70 is the bottom of ITU-T G.109's "low" category and about MOS
	// 3.6. Below it a call is degraded enough that moving is worth the
	// risk of moving.
	"min_acceptable_r": {Min: 0, Max: 100, Default: 70},

	"switch_hold_intervals": {Min: 1, Max: 1_000, Default: 5},

	// G.114 gives 40-60 ms to codec and jitter buffer before the network
	// is touched, and D-004 knowingly added a hairpin on top.
	"base_delay_ms": {Min: 0, Max: 1_000, Default: 50},

	"mbb_min_ms": {Min: 0, Max: 10_000, Default: 200},
	"mbb_max_ms": {Min: 100, Max: 60_000, Default: 2_000},

	// 20 ms of queueing above the round trip's own floor is well clear of
	// ordinary scheduling noise on a cellular link and well below the
	// 100 ms at which the state machine starts calling a path unstable.
	// The ceiling is meant to be found before the path is called degraded.
	"bw_onset_ms": {Min: 2, Max: 2_000, Default: 20},

	// 300 kbps is above anything the measurement traffic itself produces
	// and below a single video call, so an idle path never sets a ceiling
	// and a real flow always can.
	"bw_min_load_kbps": {Min: 16, Max: 1_000_000, Default: 300},

	"bw_headroom_percent": {Min: 0, Max: 500, Default: 20},

	// One a second: fast enough that a path going bad outbound is noticed
	// within a couple of scheduler intervals, slow enough to be free.
	"report_interval_ms": {Min: 100, Max: 60_000, Default: 1_000},

	// Zero means unknown, and unknown means no gate. See BWFallbackKbps.
	"bw_fallback_kbps": {Min: 0, Max: 10_000_000, Default: 0},

	// Twenty-four packets is under half a second of an RTP flow at its
	// 20 ms cadence. Long enough for a gap variance to mean something,
	// short enough that a native conferencing client nobody has a prefix
	// for is caught early in the call rather than partway through it.
	"classify_sample_packets": {Min: 4, Max: 1_000, Default: 24},

	// The top of protocol.md's 60-250 byte RTP band. QUIC bulk sits at
	// 1200-1400, so there is most of a kilobyte of daylight between them
	// and this threshold does not need to be precise.
	"classify_rtp_max_bytes": {Min: 64, Max: 1_400, Default: 250},

	// A quarter of the 20 ms cadence, as a standard deviation, and
	// deliberately strict.
	//
	// This was 10 ms while the behavioural test was the only thing that
	// could identify media at all. RTP detection now does that job
	// directly and far better - it catches video, which no size-and-gap
	// test ever will - so what is left here is a last resort for media
	// that carries no RTP framing, which is rare. Its errors are not
	// symmetric: missing such a flow gives it bulk treatment, while a
	// false positive duplicates a download over a metered link, which is
	// the expensive mistake D-027 exists to avoid. At 10 ms a stream of
	// small QUIC acknowledgements passed as real-time; at 5 ms it does
	// not, and genuine audio is nowhere near either bound.
	"classify_gap_variance_ms": {Min: 1, Max: 200, Default: 5},

	// Eight thousand conversations is far more than a household behind
	// one RV generates, and costs a few megabytes if it ever fills.
	"classify_max_flows": {Min: 256, Max: 262_144, Default: 8_192},

	// Two minutes. Long enough to hold a call's class through a lull,
	// short enough that a port pair reused afterwards starts clean.
	"classify_flow_idle_seconds": {Min: 5, Max: 3_600, Default: 120},
}

// Defaults returns a configuration that is correct to run with as-is.
func Defaults() Config {
	return Config{
		EchoIntervalMs:       Bounds["echo_interval_ms"].Default,
		ProbeIntervalSeconds: Bounds["probe_interval_seconds"].Default,
		StateIntervalMs:      Bounds["state_interval_ms"].Default,
		StatsIntervalSeconds: Bounds["stats_interval_seconds"].Default,

		RecordIntervalSeconds: Bounds["record_interval_seconds"].Default,
		RecordMaxMegabytes:    Bounds["record_max_megabytes"].Default,
		RecordKeepFiles:       Bounds["record_keep_files"].Default,

		EvalIntervalMs:            Bounds["eval_interval_ms"].Default,
		UnstableLossPercent:       Bounds["unstable_loss_percent"].Default,
		UnstableQueueDelayMs:      Bounds["unstable_queue_delay_ms"].Default,
		UnstableJitterMs:          Bounds["unstable_jitter_ms"].Default,
		AdmissionQueueDelayMs:     Bounds["admission_queue_delay_ms"].Default,
		AdmissionRecoverIntervals: Bounds["admission_recover_intervals"].Default,
		DemoteIntervals:           Bounds["demote_intervals"].Default,
		PromoteIntervals:          Bounds["promote_intervals"].Default,
		DownSilenceMs:             Bounds["down_silence_ms"].Default,
		DownProbePackets:          Bounds["down_probe_packets"].Default,
		FlapWindowSeconds:         Bounds["flap_window_seconds"].Default,
		FlapThreshold:             Bounds["flap_threshold"].Default,
		FlapPenaltyR:              Bounds["flap_penalty_r"].Default,
		UnstablePenaltyR:          Bounds["unstable_penalty_r"].Default,
		SwitchMarginR:             Bounds["switch_margin_r"].Default,
		MinAcceptableR:            Bounds["min_acceptable_r"].Default,
		SwitchHoldIntervals:       Bounds["switch_hold_intervals"].Default,
		BaseDelayMs:               Bounds["base_delay_ms"].Default,
		MBBMinMs:                  Bounds["mbb_min_ms"].Default,
		MBBMaxMs:                  Bounds["mbb_max_ms"].Default,

		BWOnsetMs:         Bounds["bw_onset_ms"].Default,
		BWMinLoadKbps:     Bounds["bw_min_load_kbps"].Default,
		BWHeadroomPercent: Bounds["bw_headroom_percent"].Default,
		BWFallbackKbps:    Bounds["bw_fallback_kbps"].Default,
		ReportIntervalMs:  Bounds["report_interval_ms"].Default,

		ClassifySamplePackets:   Bounds["classify_sample_packets"].Default,
		ClassifyRTPMaxBytes:     Bounds["classify_rtp_max_bytes"].Default,
		ClassifyGapVarianceMs:   Bounds["classify_gap_variance_ms"].Default,
		ClassifyMaxFlows:        Bounds["classify_max_flows"].Default,
		ClassifyFlowIdleSeconds: Bounds["classify_flow_idle_seconds"].Default,

		DuplicateMode: DuplicateUnstable,
	}
}

// clamp brings one value inside its permitted range.
//
// A zero is treated as a value like any other, not as "unset". Several of
// the scoring settings have a legitimate zero - it is how a penalty is
// switched off - and reading that as "use the default" would silently
// restore the very penalty someone had just turned off, which is a
// miserable thing to work out from a campground. Absent settings are
// instead filled in with the defaults before Sanitised ever sees them; see
// Load, and note that anything decoding JSON into a Config must start from
// Defaults() for the same reason.
func clamp(v int, b bound) int {
	switch {
	case v < b.Min:
		return b.Min
	case v > b.Max:
		return b.Max
	}
	return v
}

// duplicateMode brings the duplication policy to something meaningful. An
// unrecognised value is not an error: it is a typo, and the default is a
// better answer to a typo than a daemon that will not start.
func duplicateMode(s string) string {
	for _, m := range DuplicateModes {
		if s == m {
			return s
		}
	}
	return DuplicateSwitching
}

// Sanitised returns the configuration with every value brought inside its
// permitted range. An out-of-range setting is corrected rather than
// refused, so a bad edit can never leave the daemon unable to start.
func (c Config) Sanitised() Config {
	return Config{
		EchoIntervalMs:       clamp(c.EchoIntervalMs, Bounds["echo_interval_ms"]),
		ProbeIntervalSeconds: clamp(c.ProbeIntervalSeconds, Bounds["probe_interval_seconds"]),
		StateIntervalMs:      clamp(c.StateIntervalMs, Bounds["state_interval_ms"]),
		StatsIntervalSeconds: clamp(c.StatsIntervalSeconds, Bounds["stats_interval_seconds"]),

		RecordIntervalSeconds: clamp(c.RecordIntervalSeconds, Bounds["record_interval_seconds"]),
		RecordMaxMegabytes:    clamp(c.RecordMaxMegabytes, Bounds["record_max_megabytes"]),
		RecordKeepFiles:       clamp(c.RecordKeepFiles, Bounds["record_keep_files"]),

		EvalIntervalMs:            clamp(c.EvalIntervalMs, Bounds["eval_interval_ms"]),
		UnstableLossPercent:       clamp(c.UnstableLossPercent, Bounds["unstable_loss_percent"]),
		UnstableQueueDelayMs:      clamp(c.UnstableQueueDelayMs, Bounds["unstable_queue_delay_ms"]),
		UnstableJitterMs:          clamp(c.UnstableJitterMs, Bounds["unstable_jitter_ms"]),
		AdmissionQueueDelayMs:     clamp(c.AdmissionQueueDelayMs, Bounds["admission_queue_delay_ms"]),
		AdmissionRecoverIntervals: clamp(c.AdmissionRecoverIntervals, Bounds["admission_recover_intervals"]),
		DemoteIntervals:           clamp(c.DemoteIntervals, Bounds["demote_intervals"]),
		PromoteIntervals:          clamp(c.PromoteIntervals, Bounds["promote_intervals"]),
		DownSilenceMs:             clamp(c.DownSilenceMs, Bounds["down_silence_ms"]),
		DownProbePackets:          clamp(c.DownProbePackets, Bounds["down_probe_packets"]),
		FlapWindowSeconds:         clamp(c.FlapWindowSeconds, Bounds["flap_window_seconds"]),
		FlapThreshold:             clamp(c.FlapThreshold, Bounds["flap_threshold"]),
		FlapPenaltyR:              clamp(c.FlapPenaltyR, Bounds["flap_penalty_r"]),
		UnstablePenaltyR:          clamp(c.UnstablePenaltyR, Bounds["unstable_penalty_r"]),
		SwitchMarginR:             clamp(c.SwitchMarginR, Bounds["switch_margin_r"]),
		MinAcceptableR:            clamp(c.MinAcceptableR, Bounds["min_acceptable_r"]),
		SwitchHoldIntervals:       clamp(c.SwitchHoldIntervals, Bounds["switch_hold_intervals"]),
		BaseDelayMs:               clamp(c.BaseDelayMs, Bounds["base_delay_ms"]),
		MBBMinMs:                  clamp(c.MBBMinMs, Bounds["mbb_min_ms"]),
		MBBMaxMs:                  clamp(c.MBBMaxMs, Bounds["mbb_max_ms"]),

		BWOnsetMs:         clamp(c.BWOnsetMs, Bounds["bw_onset_ms"]),
		BWMinLoadKbps:     clamp(c.BWMinLoadKbps, Bounds["bw_min_load_kbps"]),
		BWHeadroomPercent: clamp(c.BWHeadroomPercent, Bounds["bw_headroom_percent"]),
		BWFallbackKbps:    clamp(c.BWFallbackKbps, Bounds["bw_fallback_kbps"]),
		ReportIntervalMs:  clamp(c.ReportIntervalMs, Bounds["report_interval_ms"]),

		ClassifySamplePackets:   clamp(c.ClassifySamplePackets, Bounds["classify_sample_packets"]),
		ClassifyRTPMaxBytes:     clamp(c.ClassifyRTPMaxBytes, Bounds["classify_rtp_max_bytes"]),
		ClassifyGapVarianceMs:   clamp(c.ClassifyGapVarianceMs, Bounds["classify_gap_variance_ms"]),
		ClassifyMaxFlows:        clamp(c.ClassifyMaxFlows, Bounds["classify_max_flows"]),
		ClassifyFlowIdleSeconds: clamp(c.ClassifyFlowIdleSeconds, Bounds["classify_flow_idle_seconds"]),

		DuplicateMode: duplicateMode(c.DuplicateMode),
	}
}

func (c Config) EchoInterval() time.Duration {
	return time.Duration(c.EchoIntervalMs) * time.Millisecond
}

func (c Config) ProbeInterval() time.Duration {
	return time.Duration(c.ProbeIntervalSeconds) * time.Second
}

func (c Config) StateInterval() time.Duration {
	return time.Duration(c.StateIntervalMs) * time.Millisecond
}

func (c Config) StatsInterval() time.Duration {
	return time.Duration(c.StatsIntervalSeconds) * time.Second
}

func (c Config) RecordInterval() time.Duration {
	return time.Duration(c.RecordIntervalSeconds) * time.Second
}

// RecordMaxBytes is the rotation threshold in bytes.
func (c Config) RecordMaxBytes() int64 {
	return int64(c.RecordMaxMegabytes) << 20
}

func (c Config) ReportInterval() time.Duration {
	return time.Duration(c.ReportIntervalMs) * time.Millisecond
}

func (c Config) EvalInterval() time.Duration {
	return time.Duration(c.EvalIntervalMs) * time.Millisecond
}

func (c Config) DownSilence() time.Duration {
	return time.Duration(c.DownSilenceMs) * time.Millisecond
}

func (c Config) FlapWindow() time.Duration {
	return time.Duration(c.FlapWindowSeconds) * time.Second
}

func (c Config) MBBMin() time.Duration {
	return time.Duration(c.MBBMinMs) * time.Millisecond
}

// MBBMax is never allowed to fall below MBBMin. The two are edited
// independently through a web form, and a maximum under the minimum would
// otherwise end every handover before its overlap had run - turning
// make-before-break silently into the break-before-make it exists to
// prevent.
func (c Config) MBBMax() time.Duration {
	if c.MBBMaxMs < c.MBBMinMs {
		return c.MBBMin()
	}
	return time.Duration(c.MBBMaxMs) * time.Millisecond
}

// Load reads a configuration file. A missing file yields the defaults,
// since running without one is the expected case rather than a problem.
//
// Decoding starts from the defaults rather than from a zero Config, so a
// setting the file does not mention keeps its default while a setting the
// file explicitly sets to zero stays zero. A file written before a setting
// existed is the normal case after every upgrade - the boxes in the field
// are carrying one right now - and it must not silently zero the settings
// it predates.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Defaults(), nil
	}
	if err != nil {
		return Defaults(), err
	}
	c := Defaults()
	if err := json.Unmarshal(b, &c); err != nil {
		return Defaults(), fmt.Errorf("config: %s: %w", path, err)
	}
	return c.Sanitised(), nil
}

// Save writes a configuration file, replacing it atomically so a daemon
// reading it concurrently never sees a half-written file.
func Save(path string, c Config) error {
	b, err := json.MarshalIndent(c.Sanitised(), "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Holder carries the current configuration for readers on other
// goroutines.
type Holder struct {
	v atomic.Pointer[Config]
}

func NewHolder(c Config) *Holder {
	h := &Holder{}
	h.Set(c)
	return h
}

func (h *Holder) Get() Config {
	if c := h.v.Load(); c != nil {
		return *c
	}
	return Defaults()
}

func (h *Holder) Set(c Config) {
	sane := c.Sanitised()
	h.v.Store(&sane)
}

// Watch reloads the configuration whenever the file changes, so a setting
// altered through the web interface takes effect without a restart.
//
// The file's modification time is polled rather than watched. It changes
// about as often as a person clicks save, and polling avoids a watch that
// has to be re-established every time the file is atomically replaced.
func (h *Holder) Watch(path string) {
	var last time.Time
	for range time.Tick(2 * time.Second) {
		fi, err := os.Stat(path)
		if err != nil {
			continue // a missing file just means the defaults still stand
		}
		if !fi.ModTime().After(last) {
			continue
		}
		last = fi.ModTime()

		c, err := Load(path)
		if err != nil {
			log.Printf("config: reload failed, keeping current settings: %v", err)
			continue
		}
		h.Set(c)
		log.Printf("config: reloaded from %s", path)
	}
}
