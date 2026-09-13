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

	// BWHeadroomPercent is the margin a path must have spare, below its
	// shaped speed, before a duplicate copy or a handover is steered onto
	// it, since arriving exactly at the shaped speed is arriving at the
	// wall. A path whose speed was never measured always qualifies (D-055).
	//
	// The reactive ceiling's settings that sat beside it - bw_onset_ms,
	// bw_onset_dwell_ms, bw_min_load_kbps - went with the estimator in D-055.
	// A file still carrying them loads fine; unknown keys are ignored.
	BWHeadroomPercent int `json:"bw_headroom_percent"`

	// ReportIntervalMs is how often each end tells the other what it has
	// measured on the other's transmissions - the far end's only source of
	// truth about its own send direction. Slower than the echo cadence on
	// purpose: these are smoothed statistics that do not move packet to
	// packet, and on a 512 kbps standby link every header byte is counted.
	ReportIntervalMs int `json:"report_interval_ms"`

	// BulkSpreadMinSharePercent is the smallest share of the best
	// candidate's measured speed a path may have and still join the
	// per-flow load-balancing set of D-044. Below it the path is left out
	// of the spread, though it stays eligible for everything else.
	//
	// The spread is a set of peers: txFor hashes flows across it uniformly,
	// so a member takes its share of the flows whatever it can carry. That
	// is right between links of comparable size and ruinous between links
	// an order of magnitude apart, which is the normal case here. See
	// D-045.
	BulkSpreadMinSharePercent int `json:"bulk_spread_min_share_percent"`

	// SpreadMinR is the lowest measured quality, in E-model R points, a
	// path may have and still join the per-flow load-balancing set. It is
	// scored on the send direction the peer reports (D-024), so it is what
	// this end's traffic is actually experiencing rather than what is
	// arriving here.
	//
	// Deliberately far below MinAcceptableR: that is a call threshold, and
	// bulk is explicitly sacrificial. This one only has to separate a link
	// that is delivering from one that is not. See D-046.
	SpreadMinR int `json:"spread_min_r"`

	// The classification thresholds of step 7. The two that matter are
	// ClassifyRTPMaxBytes and ClassifyGapVarianceMs: protocol.md's claim
	// is that mean packet size and inter-packet-gap variance separate RTP
	// media from QUIC bulk almost perfectly, and these are where that
	// claim is set. They only ever apply to the behavioural catch-all -
	// a flow identified by STUN is not subject to them.
	ClassifySamplePackets int `json:"classify_sample_packets"`
	ClassifyRTPMaxBytes   int `json:"classify_rtp_max_bytes"`
	ClassifyGapVarianceMs int `json:"classify_gap_variance_ms"`

	// The transactional/bulk split. A flow is transactional until it
	// proves itself an elephant, and goes back when it stops.
	//
	// Rate with a dwell rather than cumulative bytes, because HTTP/2 and
	// HTTP/3 multiplex a whole page load and a large download onto one
	// connection - so total volume says almost nothing about whether the
	// user is waiting on it. What separates them is duration: a page load
	// is a burst of a second or two and then idle, a download is
	// sustained. ClassifyBulkDwellMs is therefore the load-bearing knob,
	// not the rate.
	//
	// ClassifyBulkBytes is a backstop for a transfer fast enough to move
	// serious volume inside the dwell window, and the clear pair is the
	// hysteresis: reusing one threshold would flap the class of a flow
	// every time a download paused.
	//
	// All of these are guesses. Nothing has been measured, the drive that
	// step 5 wants has not happened, and the demotions are logged
	// precisely so the field data can settle them later.
	ClassifyBulkKbps      int `json:"classify_bulk_kbps"`
	ClassifyBulkDwellMs   int `json:"classify_bulk_dwell_ms"`
	ClassifyBulkClearKbps int `json:"classify_bulk_clear_kbps"`
	ClassifyBulkClearMs   int `json:"classify_bulk_clear_ms"`
	ClassifyBulkBytes     int `json:"classify_bulk_bytes"`

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

	// BulkScheduler picks how bulk is placed, and it is the v0.2 kill
	// switch. "cascade" spreads bulk per packet: it fills the slowest usable
	// path first and spills onto faster ones only as each congests, down to
	// the path carrying the call, with the far end putting each flow back
	// in order. "flow" is v0.1 exactly - one flow to one path by a hash,
	// and admission control's binary gate protecting the call's path.
	//
	// Cascade needs a peer that can resequence, so against an older build
	// it quietly behaves as flow whatever this says. Flipping it takes
	// effect on the next evaluation. See v0.2-design.md.
	BulkScheduler string `json:"bulk_scheduler"`

	// The cascade's queue target, loss line and recovery count went with its
	// per-path controller in D-055: a path is full when its shaper backs up.

	// CascadeOrderHysteresisMs is how much slower a path must be before it
	// overtakes the one ahead of it in the fill order. Two links a few
	// milliseconds apart would otherwise swap every evaluation.
	CascadeOrderHysteresisMs int `json:"cascade_order_hysteresis_ms"`

	// CascadeReportIntervalMs is how often a node receiving spread bulk
	// tells the sender what its paths are doing. The ordinary cadence is a
	// second, and only on idle paths, which leaves a path carrying bulk
	// reported on least exactly while it is busiest.
	CascadeReportIntervalMs int `json:"cascade_report_interval_ms"`

	// ResequencerHoldMarginMs is added to the measured spread in delay
	// between paths to give how long the far end waits for a missing packet
	// before giving up on it. ResequencerMaxHoldMs caps that wait whatever
	// is measured, and a path further behind the call's path than the cap
	// is not spread onto at all - its packets would arrive after the wait
	// had given up on them.
	ResequencerHoldMarginMs int `json:"resequencer_hold_margin_ms"`
	ResequencerMaxHoldMs    int `json:"resequencer_max_hold_ms"`

	// Cost tracking, step 10. Links carries one entry per WAN interface
	// that has an allowance worth respecting; an interface with no entry
	// is unmetered, which is the default and the only sane one. A cap
	// nobody has set must mean "no opinion" rather than "no allowance",
	// or a fresh install would refuse to carry bulk on every link it has.
	//
	// Keyed by interface name because that is what the operator knows and
	// what -paths already names. Path ids are an internal ordering and
	// would silently re-point somebody's Starlink cap at their 5G modem
	// the first time a link came up in a different order.
	Links map[string]LinkBudget `json:"links,omitempty"`

	// BudgetGreenHeadroomPercent is how much of a cap must still be
	// projected spare for a link to count as green. architecture.md sets
	// it at 20.
	BudgetGreenHeadroomPercent int `json:"budget_green_headroom_percent"`

	// The scoring surcharge for a link that is spending too fast, in R
	// points off the E-model score - the same currency as
	// UnstablePenaltyR and FlapPenaltyR, and protocol.md's `penalty_i`
	// "metered-link surcharge (from budget band)".
	//
	// A penalty rather than a veto, and that distinction is the whole
	// design. architecture.md wants a red link used for real-time when it
	// is the only viable path, because a working call beats an overage;
	// a hard exclusion could not express that, while a large penalty
	// loses every comparison against a working path and wins by default
	// when there is nothing to compare against.
	BudgetYellowPenaltyR int `json:"budget_yellow_penalty_r"`
	BudgetRedPenaltyR    int `json:"budget_red_penalty_r"`
}

// LinkBudget is one WAN link's allowance and how it should be named. The
// zero value is an unmetered link with no label.
type LinkBudget struct {
	// Label is what this link is called in logs, the interface, and any
	// answer to "which one is broken". Empty falls back to the interface
	// name, which is what every message used before this existed.
	//
	// It is here rather than in a table of its own because this map is
	// already the one place keyed by the name the operator knows, and a
	// second map keyed the same way would be a second thing to keep in
	// step. "wg2" and "path 1" are internal facts; "Starlink" is the one
	// that answers the question actually being asked at 2am in a
	// campground, which is which physical link to go and look at.
	Label string `json:"label,omitempty"`

	// CapMB is the billing-cycle allowance in megabytes. Zero means
	// unmetered: no cap, no bands, no penalty, usage still counted.
	//
	// Megabytes rather than gigabytes because whole gigabytes cannot say
	// what several real plans say. A 2.5 GB tier and a 500 MB travel SIM
	// are both unrepresentable in integer GB, and the interface renders
	// human units from this anyway, so the coarser unit bought nothing.
	CapMB int `json:"cap_mb"`

	// CycleDay is the day of the month the carrier's cycle starts.
	// Carriers do not align, so this is per link. Restricted to 1-28: a
	// cycle starting on the 31st does not exist in February.
	CycleDay int `json:"cycle_day"`
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

// Bulk schedulers. See Config.BulkScheduler.
const (
	BulkCascade = "cascade"
	BulkFlow    = "flow"
)

// BulkSchedulers is every accepted value, default first.
var BulkSchedulers = []string{BulkCascade, BulkFlow}

// bulkScheduler brings the setting to something meaningful. A typo gets the
// default, as with the duplication policy.
func bulkScheduler(s string) string {
	for _, m := range BulkSchedulers {
		if s == m {
			return s
		}
	}
	return BulkCascade
}

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
	// Cost tracking, step 10. See LinkBudget and the budget penalties.
	"budget_green_headroom_percent": {Min: 0, Max: 90, Default: 20},

	// Yellow costs a link roughly what being unstable does: enough to
	// lose to any healthy alternative, not enough to look broken. Red is
	// larger than the whole usable R range, so a red link loses to
	// anything at all that still works and is chosen only when nothing
	// else is - which is architecture.md's "real-time allowed if it is
	// the sole viable path".
	"budget_yellow_penalty_r": {Min: 0, Max: 100, Default: 15},
	"budget_red_penalty_r":    {Min: 0, Max: 100, Default: 60},

	"link_cap_mb": {Min: 0, Max: 100_000_000, Default: 0},

	// The transactional/bulk split. Biased toward calling things
	// transactional, because the two mistakes are not symmetric: calling
	// a download transactional costs a few seconds of the shared path,
	// while calling a page load bulk costs every page load - which is the
	// thing the class exists to fix.
	"classify_bulk_kbps":       {Min: 64, Max: 1_000_000, Default: 2_000},
	"classify_bulk_dwell_ms":   {Min: 200, Max: 60_000, Default: 3_000},
	"classify_bulk_clear_kbps": {Min: 0, Max: 1_000_000, Default: 1_000},
	"classify_bulk_clear_ms":   {Min: 200, Max: 300_000, Default: 5_000},
	"classify_bulk_bytes":      {Min: 64 << 10, Max: 1 << 30, Default: 8 << 20},
	"link_cycle_day":           {Min: 1, Max: 28, Default: 1},

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

	// v0.2's cascade. Reasoned rather than measured, and the drive that
	// settles them is the next thing after deployment.
	"cascade_order_hysteresis_ms": {Min: 0, Max: 500, Default: 10},
	"cascade_report_interval_ms":  {Min: 50, Max: 5_000, Default: 200},

	// Enough to hold Starlink beside LTE (S2 in v0.2-design.md), and a cap
	// that stops one wild reading turning the hold into a stall.
	"resequencer_hold_margin_ms": {Min: 0, Max: 500, Default: 10},
	"resequencer_max_hold_ms":    {Min: 20, Max: 2_000, Default: 200},

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

	"bw_headroom_percent": {Min: 0, Max: 500, Default: 20},

	// One a second: fast enough that a path going bad outbound is noticed
	// within a couple of scheduler intervals, slow enough to be free.
	"report_interval_ms": {Min: 100, Max: 60_000, Default: 1_000},

	// An eighth, near enough. A link worth load-balancing onto has to be
	// able to carry a real fraction of what the best one does: at 12% a
	// 5 Mbps link still joins a 30 Mbps one, which is right - it is worth
	// having - while the 512k standby tier of D-022 and the 636 kbps
	// cellular link that produced D-045 do not, which is also right.
	//
	// Max is 100 on purpose, and it is an invariant rather than a taste:
	// the best candidate is always 100% of itself, so no setting inside
	// the bounds can empty a non-empty spread. Zero disables the gate.
	"bulk_spread_min_share_percent": {Min: 0, Max: 100, Default: 12},

	// R 50 is the floor of G.109's scale - below it the model stops having
	// a category, which is the right place to stop handing a link flows.
	// With loss scattered it admits about 20%; bursty loss pushes R down
	// much faster, which is what we want, because loss in runs is far worse
	// for a transfer than the same rate scattered. Ordinary cellular (a few
	// percent) scores 83-90 and is never near this. The link that produced
	// D-046 scored ~0. Zero disables the gate.
	"spread_min_r": {Min: 0, Max: 100, Default: 50},

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
		BulkScheduler:             BulkCascade,
		CascadeOrderHysteresisMs:  Bounds["cascade_order_hysteresis_ms"].Default,
		CascadeReportIntervalMs:   Bounds["cascade_report_interval_ms"].Default,
		ResequencerHoldMarginMs:   Bounds["resequencer_hold_margin_ms"].Default,
		ResequencerMaxHoldMs:      Bounds["resequencer_max_hold_ms"].Default,
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

		BWHeadroomPercent: Bounds["bw_headroom_percent"].Default,

		BulkSpreadMinSharePercent: Bounds["bulk_spread_min_share_percent"].Default,
		SpreadMinR:                Bounds["spread_min_r"].Default,
		ReportIntervalMs:          Bounds["report_interval_ms"].Default,

		ClassifySamplePackets:   Bounds["classify_sample_packets"].Default,
		ClassifyRTPMaxBytes:     Bounds["classify_rtp_max_bytes"].Default,
		ClassifyGapVarianceMs:   Bounds["classify_gap_variance_ms"].Default,
		ClassifyBulkKbps:        Bounds["classify_bulk_kbps"].Default,
		ClassifyBulkDwellMs:     Bounds["classify_bulk_dwell_ms"].Default,
		ClassifyBulkClearKbps:   Bounds["classify_bulk_clear_kbps"].Default,
		ClassifyBulkClearMs:     Bounds["classify_bulk_clear_ms"].Default,
		ClassifyBulkBytes:       Bounds["classify_bulk_bytes"].Default,
		ClassifyMaxFlows:        Bounds["classify_max_flows"].Default,
		ClassifyFlowIdleSeconds: Bounds["classify_flow_idle_seconds"].Default,

		DuplicateMode: DuplicateUnstable,

		BudgetGreenHeadroomPercent: Bounds["budget_green_headroom_percent"].Default,
		BudgetYellowPenaltyR:       Bounds["budget_yellow_penalty_r"].Default,
		BudgetRedPenaltyR:          Bounds["budget_red_penalty_r"].Default,
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
		BulkScheduler:             bulkScheduler(c.BulkScheduler),
		CascadeOrderHysteresisMs:  clamp(c.CascadeOrderHysteresisMs, Bounds["cascade_order_hysteresis_ms"]),
		CascadeReportIntervalMs:   clamp(c.CascadeReportIntervalMs, Bounds["cascade_report_interval_ms"]),
		ResequencerHoldMarginMs:   clamp(c.ResequencerHoldMarginMs, Bounds["resequencer_hold_margin_ms"]),
		ResequencerMaxHoldMs:      clamp(c.ResequencerMaxHoldMs, Bounds["resequencer_max_hold_ms"]),
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

		BWHeadroomPercent: clamp(c.BWHeadroomPercent, Bounds["bw_headroom_percent"]),

		BulkSpreadMinSharePercent: clamp(c.BulkSpreadMinSharePercent, Bounds["bulk_spread_min_share_percent"]),
		SpreadMinR:                clamp(c.SpreadMinR, Bounds["spread_min_r"]),
		ReportIntervalMs:          clamp(c.ReportIntervalMs, Bounds["report_interval_ms"]),

		ClassifySamplePackets:   clamp(c.ClassifySamplePackets, Bounds["classify_sample_packets"]),
		ClassifyRTPMaxBytes:     clamp(c.ClassifyRTPMaxBytes, Bounds["classify_rtp_max_bytes"]),
		ClassifyGapVarianceMs:   clamp(c.ClassifyGapVarianceMs, Bounds["classify_gap_variance_ms"]),
		ClassifyBulkKbps:        clamp(c.ClassifyBulkKbps, Bounds["classify_bulk_kbps"]),
		ClassifyBulkDwellMs:     clamp(c.ClassifyBulkDwellMs, Bounds["classify_bulk_dwell_ms"]),
		ClassifyBulkClearKbps:   clamp(c.ClassifyBulkClearKbps, Bounds["classify_bulk_clear_kbps"]),
		ClassifyBulkClearMs:     clamp(c.ClassifyBulkClearMs, Bounds["classify_bulk_clear_ms"]),
		ClassifyBulkBytes:       clamp(c.ClassifyBulkBytes, Bounds["classify_bulk_bytes"]),
		ClassifyMaxFlows:        clamp(c.ClassifyMaxFlows, Bounds["classify_max_flows"]),
		ClassifyFlowIdleSeconds: clamp(c.ClassifyFlowIdleSeconds, Bounds["classify_flow_idle_seconds"]),

		DuplicateMode: duplicateMode(c.DuplicateMode),

		Links:                      sanitisedLinks(c.Links),
		BudgetGreenHeadroomPercent: clamp(c.BudgetGreenHeadroomPercent, Bounds["budget_green_headroom_percent"]),
		BudgetYellowPenaltyR:       clamp(c.BudgetYellowPenaltyR, Bounds["budget_yellow_penalty_r"]),
		BudgetRedPenaltyR:          clamp(c.BudgetRedPenaltyR, Bounds["budget_red_penalty_r"]),
	}
}

// sanitisedLinks brings every per-link allowance inside its range.
//
// The map is copied rather than corrected in place: Sanitised is called on
// configuration that other goroutines may already be reading through the
// holder, and mutating a shared map under them would be a data race that
// only shows up under load on the box hardest to reach.
//
// A cycle day of zero is the one place a zero is filled in with the
// default rather than taken literally. Everywhere else in this file a zero
// is a real value - it is how a penalty is switched off - but there is no
// zeroth of the month, so it can only mean the field was omitted.
func sanitisedLinks(in map[string]LinkBudget) map[string]LinkBudget {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]LinkBudget, len(in))
	for name, l := range in {
		if l.CycleDay == 0 {
			l.CycleDay = Bounds["link_cycle_day"].Default
		}
		out[name] = LinkBudget{
			Label:    l.Label,
			CapMB:    clamp(l.CapMB, Bounds["link_cap_mb"]),
			CycleDay: clamp(l.CycleDay, Bounds["link_cycle_day"]),
		}
	}
	return out
}

// LinkFor returns the configured allowance for an interface, with the
// default cycle day filled in for anything absent. An interface with no
// entry comes back with a zero cap, which means unmetered - the only safe
// reading of a cap nobody set.
//
// This deliberately returns config's own type rather than the accounting
// package's. Keeping this package free of project imports is what lets
// every other package depend on it without thinking about cycles.
func (c Config) LinkFor(iface string) LinkBudget {
	l := c.Links[iface]
	if l.CycleDay <= 0 {
		l.CycleDay = Bounds["link_cycle_day"].Default
	}
	return l
}

// LabelFor is the human name for a link, falling back to the interface name
// when none is configured. Never returns empty: a log line with a blank where
// the link should be is worse than one naming an interface.
func (c Config) LabelFor(iface string) string {
	if l, ok := c.Links[iface]; ok && l.Label != "" {
		return l.Label
	}
	return iface
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

func (c Config) CascadeReportInterval() time.Duration {
	return time.Duration(c.CascadeReportIntervalMs) * time.Millisecond
}

func (c Config) ResequencerHoldMargin() time.Duration {
	return time.Duration(c.ResequencerHoldMarginMs) * time.Millisecond
}

func (c Config) ResequencerMaxHold() time.Duration {
	return time.Duration(c.ResequencerMaxHoldMs) * time.Millisecond
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
	var lastSize int64
	var seen bool
	for range time.Tick(2 * time.Second) {
		fi, err := os.Stat(path)
		if err != nil {
			continue // a missing file just means the defaults still stand
		}
		// Any change, not merely a newer one. Testing for "newer" looks
		// obviously right and silently ignores two things that happen on
		// a vehicle: a config restored from a backup with `cp -a`, which
		// preserves the older mtime, and a file written before NTP
		// stepped the clock backwards on a box with no RTC. Either
		// leaves the daemon running settings nobody can see, forever,
		// with no way to tell from the log.
		//
		// Size is compared alongside mtime because a rewrite inside the
		// same filesystem timestamp tick is possible, and the two
		// together are a good deal harder to collide with than either.
		if seen && fi.ModTime().Equal(last) && fi.Size() == lastSize {
			continue
		}
		last, lastSize, seen = fi.ModTime(), fi.Size(), true

		c, err := Load(path)
		if err != nil {
			log.Printf("config: reload failed, keeping current settings: %v", err)
			continue
		}
		h.Set(c)
		log.Printf("config: reloaded from %s", path)
	}
}
