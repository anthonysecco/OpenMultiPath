package relay

import (
	"math"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
)

// Path scoring, as a composite rather than a weighted sum of raw metrics.
//
// protocol.md asks for this directly: the relative weight of loss against
// jitter against delay for perceived voice quality is already
// well-researched, and re-deriving it by hand-tuning coefficients is a good
// way to spend a month producing something worse. So the ITU-T G.107
// E-model does the weighting, and the daemon's job is only to feed it
// honest measurements.
//
// The output is an R factor, 0 to 100, which is what the scheduler compares
// and what every penalty in the configuration is expressed in. R is used
// rather than MOS throughout because impairments are additive in R and not
// in MOS - subtracting "half a MOS point" means something different at
// either end of the scale, while subtracting ten R points does not. MOS is
// derived from it only for display, because a number between 1 and 5 is
// what a person can read at a glance.
//
// One caveat worth stating plainly: this is a voice model being used to
// rank paths for all traffic. Packets now carry a class (step 7), but
// scoring does not read it - one score per path is handed to every flow
// regardless. That is the right bias to have while it lasts, since the
// primary use case is a video call and a path good enough for audio is
// good enough for everything else, but it does mean a path is scored on
// criteria a bulk download would not care about. Step 8 is where the class
// starts to matter.

const (
	// r0Default is the basic signal-to-noise ratio with G.107's default
	// noise values. It is the ceiling: every impairment subtracts from it.
	r0Default = 93.2

	// ieCodec and bplCodec describe G.711 with packet loss concealment,
	// from G.113 Appendix I. G.711 is the reference codec rather than the
	// one actually in use - conferencing apps run Opus or similar, which
	// are more robust - so the absolute figures read pessimistically.
	// Paths are only ever compared against each other, and the comparison
	// is what matters, so the reference is left at the documented one
	// rather than invented.
	ieCodec  = 0.0
	bplCodec = 25.1
)

// rFactor scores one path. delayMs is the one-way mouth-to-ear delay,
// lossPercent the recent loss rate, and burstRatio how clustered that loss
// is: 1 means randomly scattered, higher means it arrives in runs.
func rFactor(delayMs, lossPercent, burstRatio float64) float64 {
	r := r0Default - delayImpairment(delayMs) - lossImpairment(lossPercent, burstRatio)
	return clampFloat(r, 0, 100)
}

// delayImpairment is G.107's Idd term: the cost of pure one-way delay,
// ignoring echo. It is flat below 100 ms and then climbs steeply, which is
// the G.114 knee - conversation stays unimpaired until about there and
// degrades quickly after.
func delayImpairment(delayMs float64) float64 {
	if delayMs <= 100 {
		return 0
	}
	x := math.Log(delayMs/100) / math.Log(2)
	return 25 * (math.Pow(1+math.Pow(x, 6), 1.0/6) -
		3*math.Pow(1+math.Pow(x/3, 6), 1.0/6) + 2)
}

// lossImpairment is G.107's Ie-eff term: the cost of packet loss, adjusted
// for how bursty that loss is.
//
// The burst ratio is why the burst distribution was worth collecting.
// protocol.md's example is the whole point: 1% loss in runs of twenty is
// far worse than 1% scattered, because concealment covers an isolated gap
// and cannot cover 400 ms of silence. A model fed only a loss rate would
// score those two paths identically.
func lossImpairment(lossPercent, burstRatio float64) float64 {
	if lossPercent <= 0 {
		return ieCodec
	}
	if burstRatio < 1 {
		burstRatio = 1
	}
	return ieCodec + (95-ieCodec)*lossPercent/(lossPercent/burstRatio+bplCodec)
}

// mosFrom converts an R factor to the 1-to-5 scale, for display only.
//
// The result is clamped as well as the input. G.107's polynomial is a fit,
// not an identity, and below about R 8 it dips under 1 - which is off the
// bottom of a scale that starts at 1. Left alone it would put "MOS 0.99" on
// the page for a thoroughly broken path, which invites the reader to wonder
// what is wrong with the instrument at the moment they should be looking at
// the link.
func mosFrom(r float64) float64 {
	switch {
	case r <= 0:
		return 1
	case r >= 100:
		return 4.5
	}
	return clampFloat(1+0.035*r+r*(r-60)*(100-r)*7e-6, 1, 4.5)
}

// effectiveDelayMs estimates one-way mouth-to-ear delay for a path.
//
// There is no synchronised clock, so one-way delay cannot be measured
// directly; half the round trip is the standard stand-in and is wrong
// exactly to the extent the path is asymmetric. The p95 spread is added on
// top because a receiver's de-jitter buffer sizes itself to the tail, so
// tail latency is paid on every packet whether or not that packet was late.
// baseMs covers what the network is not responsible for: codec framing, the
// far end's fixed buffer, and the hairpin through home that D-004 knowingly
// accepted.
func effectiveDelayMs(rttMs, p95SpreadMs, baseMs float64) float64 {
	return baseMs + rttMs/2 + p95SpreadMs
}

// outboundDelayMs estimates the one-way delay in the direction we send,
// which is the direction the scheduler is actually deciding about.
//
// Absolute one-way delay cannot be measured without synchronised clocks,
// and this project deliberately has none. So the delay is split in two:
//
//	outbound  ~=  rttFloor/2  +  what the peer says it is queueing
//	              ^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//	              symmetric      measured, in the right direction,
//	              assumption     against the peer's own floor so the
//	                             clock offset cancels
//
// The floor is used rather than the live round trip on purpose. An
// instantaneous round trip contains queueing from *both* directions, and
// letting inbound congestion into an outbound decision is exactly the bug
// this replaces: a download saturating a path's downlink drove the flow off
// that path's healthy uplink and onto a 512 kbps standby link.
//
// The symmetric half remains an assumption, and a wrong one on some links -
// but it is the *stable* half. Base delay does not move much, while the
// queueing does, and the queueing is now measured on the correct side.
func outboundDelayMs(rttFloorMs, txSpreadMs, baseMs float64) float64 {
	return baseMs + rttFloorMs/2 + txSpreadMs
}

func clampFloat(v, lo, hi float64) float64 {
	switch {
	case v < lo:
		return lo
	case v > hi:
		return hi
	}
	return v
}

// scoreInputs picks which direction's measurements a path is judged on.
//
// The scheduler decides where to *send*, so it wants the send direction.
// Every statistic a node gathers locally describes packets arriving, which
// is the other one - hence the path reports of D-024, where each end tells
// the other what it observed. When a report is in hand it wins outright.
//
// Without one, this falls back to exactly the old behaviour: half a round
// trip and the inbound statistics. That is the wrong direction and known to
// be, but it is what a lone node can see, and an old peer or a path nobody
// has been heard from still has to be scored somehow. Principle 5.
func scoreInputs(p pathMetric, c config.Config) (delayMs, lossPercent, burstRatio float64) {
	if p.haveTx {
		return outboundDelayMs(p.rttFloorMs, p.txSpreadMs, float64(c.BaseDelayMs)),
			p.txLoss, p.txBurstRatio
	}
	return effectiveDelayMs(p.rttMs, p.p95SpreadMs, float64(c.BaseDelayMs)),
		p.recentLoss, p.burstRatio
}

// scoringDelayMs is the delay half of scoreInputs, for the ranking
// tie-break and for display.
func scoringDelayMs(p pathMetric, c config.Config) float64 {
	d, _, _ := scoreInputs(p, c)
	return d
}
