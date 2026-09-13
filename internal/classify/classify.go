// Package classify decides whether an inner packet is real-time,
// transactional or bulk.
//
// This is step 7, and protocol.md sets out the shape: three signals in
// strict precedence, first match wins, with a per-flow cache so that the
// decision is made once per conversation rather than once per packet.
//
//  1. STUN watching      - primary, and the only one that fires before
//     the flow's first media packet (D-019)
//  2. Vendor prefixes    - a hint for non-WebRTC clients, never a
//     foundation, because the feeds rot (D-019)
//  3. Behavioural        - catch-all, from packet size and the variance
//     of the inter-packet gap (D-018)
//
// Two structural rules come ahead of all three. All TCP is definitively
// not real-time, which protocol.md offers as a free first-pass exclusion.
// And not all UDP is real-time - D-018 is emphatic, because QUIC put an
// enormous volume of bulk traffic on UDP/443, and a blanket UDP rule would
// hand YouTube the duplicated low-latency treatment and spend a metered
// link on it.
//
// # Transactional, and why it is a separate axis
//
// The three signals above answer one question: is this a call. Everything
// they reject then faces a second, independent question - is the user
// waiting on it. A download wants a fat pipe and does not care about
// round trips; a web request wants the shortest round trip and moves
// almost nothing. Carrying both as bulk meant a page load could be exiled
// onto a high-latency standby link and starved by admission control.
//
// That second question is answered by volume over time, not by a verdict
// taken once. One HTTP/2 or HTTP/3 connection carries a page load and
// then a large download, so the class has to move with the flow: rate
// above a threshold, held for a dwell, demotes it; falling quiet for
// longer promotes it back. The dwell is what separates a page load - a
// burst of a second or two, then idle - from a transfer.
//
// # The default when nothing is known
//
// A flow under observation is ClassTransactional, which reverses D-027's
// asymmetry on purpose. With two classes the safe guess was bulk, because
// guessing real-time duplicates an unidentified download over a metered
// link. With three the safe guess is the middle: a flow nobody has placed
// yet has by definition not moved much data, so treating it as small is
// both the accurate guess and the cheap one. It is never duplicated, and
// it leaves the low-latency path within a dwell if it turns out to be a
// download.
//
// ClassUnknown survives for the cases where the daemon genuinely cannot
// say: a payload that is ciphertext below WireGuard, and a packet that
// belongs to no flow at all.
package classify

import (
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// Classifier assigns a traffic class to inner packets and remembers what
// it decided, per flow. It is safe for concurrent use.
type Classifier struct {
	settings *config.Holder

	// now is time.Now except in tests, where a fake clock is the only way
	// to exercise a heuristic whose entire input is inter-packet timing.
	now func() time.Time

	mu        sync.Mutex
	flows     map[FlowKey]*flow
	vendors   []netip.Prefix
	nextSweep time.Time
}

// flow is what is remembered about one conversation.
type flow struct {
	class uint8

	// decided marks a class as settled, so the behavioural heuristic
	// stops running and cannot later overturn it. STUN and vendor
	// matches set this immediately; the heuristic sets it once it has
	// seen enough of the flow to commit.
	decided bool

	lastSeen time.Time

	// RTP evidence: the SSRC and sequence of the last packet that looked
	// like media, and how many in a row have agreed. See rtp.go.
	rtpSSRC uint32
	rtpSeq  uint16
	rtpRun  int

	// The behavioural sample. Mean packet size and the spread of the
	// inter-packet gap are the two signals protocol.md says separate RTP
	// from QUIC "almost perfectly", so they are the two collected.
	samples  int
	bytes    int64
	lastPkt  time.Time
	gapMean  float64 // milliseconds, Welford running mean
	gapM2    float64 // Welford sum of squared deviations
	gapCount int

	// The transactional/bulk split, which is a question about right now
	// rather than about the flow. One HTTP/2 connection carries a page
	// load and then a large download; the class has to move with it.
	//
	// total is everything the flow has carried, winBytes and winStart
	// the current rate window, and elephant whether it is currently
	// being treated as bulk. overSince and clearSince are when the rate
	// first crossed the demote and promote lines, which is what turns a
	// threshold into a dwell.
	total      int64
	winBytes   int64
	winStart   time.Time
	elephant   bool
	overSince  time.Time
	clearSince time.Time
}

// rateWindow is how often the flow's throughput is recomputed. The dwell
// is expressed in these, so it wants to be comfortably shorter than the
// shortest dwell worth configuring.
const rateWindow = 500 * time.Millisecond

// New returns a classifier reading its thresholds from settings, which may
// be nil in tests.
func New(settings *config.Holder) *Classifier {
	return &Classifier{
		settings: settings,
		now:      time.Now,
		flows:    make(map[FlowKey]*flow),
	}
}

// SetVendorPrefixes replaces the vendor hint list.
//
// D-019 puts these firmly below STUN, and protocol.md is blunt about why:
// Microsoft publishes a real API, Zoom publishes text files with no change
// feed, and Google Meet's published ranges do not isolate Meet in any
// useful way. They are a hint for native clients that never speak ICE. No
// feed is fetched here - keeping the package free of network access keeps
// it testable, and the staleness problem belongs to whoever supplies the
// list.
func (c *Classifier) SetVendorPrefixes(p []netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vendors = append(p[:0:0], p...)
}

// Classify returns the class of one inner IP packet.
//
// A packet that cannot be placed in a flow - a truncated header, a
// protocol that is neither TCP nor UDP, a trailing fragment - is
// ClassUnknown. The caller sends it regardless; an unclassified packet is
// a scheduling question, not a delivery one.
func (c *Classifier) Classify(pkt []byte) uint8 {
	p, ok := parse(pkt)
	if !ok {
		return protocol.ClassUnknown
	}

	cfg := c.config()
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	f := c.flows[p.flow]

	// An entry can outlive its idle timeout, because the sweep that
	// removes it runs periodically rather than on every packet. A flow
	// silent for longer than that is not this conversation: port pairs
	// get recycled, and inheriting the previous flow's class is how a
	// download would land on the class reserved for a call. Reset in
	// place rather than deleting and re-admitting - same effect, no map
	// churn, and it cannot fail on a full table.
	if f != nil && now.Sub(f.lastSeen) > time.Duration(cfg.ClassifyFlowIdleSeconds)*time.Second {
		*f = flow{class: protocol.ClassUnknown}
	}

	if f == nil {
		f = c.admit(p.flow, cfg, now)
		if f == nil {
			// The cache is full of live flows. Refusing to classify is
			// the honest answer; evicting a call to make room for a
			// packet would be a worse one.
			return protocol.ClassUnknown
		}
	}
	f.lastSeen = now

	// Volume is tracked for every non-real-time flow on every packet,
	// including ones whose real-time question is already settled: a QUIC
	// connection that was carrying a web page a moment ago can start
	// carrying a download, and the class has to move with it.
	if !f.decided || f.class != protocol.ClassRealtime {
		f.noteVolume(p.size, cfg, now)
	}

	if f.decided {
		if f.class == protocol.ClassRealtime {
			return protocol.ClassRealtime
		}
		return f.nonRealtime()
	}

	// protocol.md's free first-pass exclusion: no TCP flow is a call.
	//
	// It used to return here without a cache entry, on the reasoning that
	// nothing about a TCP flow needed remembering. That stopped being
	// true the moment transactional existed - web requests are the
	// traffic this class is for, and almost all of them are TCP - so TCP
	// now takes an entry and runs the volume detector like anything else.
	if p.flow.Proto == protoTCP {
		f.decided = true
		f.class = protocol.ClassBulk // the "not real-time" verdict; nonRealtime picks the class
		return f.nonRealtime()
	}

	// DNS resolution is felt directly in every page load and moves almost
	// nothing, so it is named rather than inferred. Waiting for the
	// behavioural sample to place a handful of 80-byte lookups is the
	// wrong answer for the one flow whose latency the user notices most.
	if p.flow.APort == portDNS || p.flow.BPort == portDNS {
		f.decided = true
		f.class = protocol.ClassBulk
		return protocol.ClassTransactional
	}

	// 1. STUN. Checked on every packet of an undecided flow rather than
	// only the first, because ICE checks are interleaved with whatever
	// else the port pair is carrying and the binding request is not
	// necessarily the packet that created the entry.
	if isSTUNBinding(p.payload) {
		f.class, f.decided = protocol.ClassRealtime, true
		return f.class
	}

	// 2. RTP. Direct evidence that this flow is carrying media, and the
	// only signal that identifies video - which is MTU-sized and bursty,
	// so the behavioural test below calls it bulk. Ordered ahead of vendor
	// prefixes deliberately: a prefix is a guess that an address range
	// carries media, while an RTP header is the media saying so.
	if f.noteRTP(p.payload) {
		f.class, f.decided = protocol.ClassRealtime, true
		return f.class
	}

	// 3. Vendor prefixes. Matched against both endpoints: a vendor range
	// will not collide with the RV's own LAN, so there is no need to work
	// out which end is remote.
	if c.vendorMatch(p.flow) {
		f.class, f.decided = protocol.ClassRealtime, true
		return f.class
	}

	// 4. Behavioural catch-all. It answers "is this a call", and anything
	// it does not call real-time falls through to the volume detector
	// rather than being carried as bulk outright.
	c.observe(f, p, now)
	if f.samples >= cfg.ClassifySamplePackets {
		f.class, f.decided = c.behavioural(f, cfg), true
		if f.class == protocol.ClassRealtime {
			return protocol.ClassRealtime
		}
		return f.nonRealtime()
	}

	// Still sampling. Unknown now means transactional rather than bulk,
	// which reverses D-027's asymmetry on purpose: with three classes the
	// safe default is the middle. A flow nobody has placed yet has by
	// definition not moved much data, so treating it as small is both the
	// accurate guess and the cheap one - it is never duplicated, and it
	// is off the low-latency path within a dwell if it turns out to be a
	// download.
	return protocol.ClassTransactional
}

// observe folds one packet into a flow's behavioural sample.
func (c *Classifier) observe(f *flow, p packet, now time.Time) {
	f.samples++
	f.bytes += int64(p.size)

	if !f.lastPkt.IsZero() {
		gap := float64(now.Sub(f.lastPkt)) / float64(time.Millisecond)

		// Welford, so the variance is available without keeping the
		// samples. The flow table is sized in thousands of entries on a
		// box with a modest amount of memory, and a slice of gaps per
		// flow would be the largest thing in the daemon.
		f.gapCount++
		d := gap - f.gapMean
		f.gapMean += d / float64(f.gapCount)
		f.gapM2 += d * (gap - f.gapMean)
	}
	f.lastPkt = now
}

// behavioural applies protocol.md's discriminator: mean packet size and
// the spread of the inter-packet gap.
//
// The table it comes from is stark. RTP media runs 60-250 bytes at a
// codec-determined 20 ms cadence with very low variance - metronomic and
// small, and protocol.md's claim is that nothing else looks like that.
// QUIC bulk runs MTU-sized and bursty. Both signals must agree before a
// flow is called real-time, so a small but ragged flow (DNS, a keepalive,
// a game's control channel) and a metronomic but fat one (a constant
// bitrate download) each stay bulk.
func (c *Classifier) behavioural(f *flow, cfg config.Config) uint8 {
	meanSize := float64(f.bytes) / float64(f.samples)
	if meanSize > float64(cfg.ClassifyRTPMaxBytes) {
		return protocol.ClassBulk
	}
	if f.gapCount < 2 {
		return protocol.ClassBulk
	}
	stddev := math.Sqrt(f.gapM2 / float64(f.gapCount-1))
	if stddev > float64(cfg.ClassifyGapVarianceMs) {
		return protocol.ClassBulk
	}
	return protocol.ClassRealtime
}

func (c *Classifier) vendorMatch(k FlowKey) bool {
	for _, p := range c.vendors {
		if p.Contains(k.A) || p.Contains(k.B) {
			return true
		}
	}
	return false
}

// admit makes room for a new flow and returns its entry, or nil if the
// table is full of flows that are all still live.
//
// The sweep is rate-limited rather than run per packet: at a few hundred
// packets a second a full scan of the table on every one of them would
// cost more than the classification it supports.
func (c *Classifier) admit(k FlowKey, cfg config.Config, now time.Time) *flow {
	// The sweep is on a timer and nothing else. Sweeping because the
	// table is full would be the obvious addition and is a trap: once it
	// is genuinely full of live flows, every subsequent packet would
	// trigger another full scan that frees nothing, turning a port scan
	// into an O(n) walk per packet. One scan per quarter-timeout is a
	// bound that holds whatever the traffic does.
	idle := time.Duration(cfg.ClassifyFlowIdleSeconds) * time.Second
	if now.After(c.nextSweep) {
		c.sweep(now, idle)
		c.nextSweep = now.Add(idle / 4)
	}
	if len(c.flows) >= cfg.ClassifyMaxFlows {
		return nil
	}
	f := &flow{class: protocol.ClassUnknown}
	c.flows[k] = f
	return f
}

func (c *Classifier) sweep(now time.Time, idle time.Duration) {
	for k, f := range c.flows {
		if now.Sub(f.lastSeen) > idle {
			delete(c.flows, k)
		}
	}
}

// Flows reports how many conversations are being tracked, for the web
// interface and for a test that wants to see the table bounded.
func (c *Classifier) Flows() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.flows)
}

func (c *Classifier) config() config.Config {
	if c.settings == nil {
		return config.Defaults()
	}
	return c.settings.Get()
}

// noteVolume folds one packet into the flow's rate window and decides
// whether it is currently an elephant.
//
// The window closes on a fixed cadence rather than on every packet, so a
// flow that goes completely silent stops being evaluated - which is
// correct. An idle flow is neither transactional nor bulk, and whatever
// it was last is the right answer until it says otherwise.
func (f *flow) noteVolume(size int, cfg config.Config, now time.Time) {
	f.total += int64(size)
	f.winBytes += int64(size)

	// A transfer fast enough to move serious volume inside the dwell
	// window would otherwise ride the low-latency path for the whole of
	// it. This is the backstop, and it is deliberately large: it is for
	// obvious elephants, not for close calls.
	if f.total >= int64(cfg.ClassifyBulkBytes) {
		f.elephant = true
	}

	if f.winStart.IsZero() {
		f.winStart = now
		return
	}
	elapsed := now.Sub(f.winStart)
	if elapsed < rateWindow {
		return
	}

	kbps := float64(f.winBytes*8) / elapsed.Seconds() / 1000
	f.winBytes, f.winStart = 0, now

	if !f.elephant {
		// Demote only on a rate held for the dwell. The dwell is what
		// separates a page load - a burst of a second or two, then idle -
		// from a download, and it is the reason this is not simply a
		// threshold on bytes.
		if kbps >= float64(cfg.ClassifyBulkKbps) {
			if f.overSince.IsZero() {
				f.overSince = now
			}
			if now.Sub(f.overSince) >= time.Duration(cfg.ClassifyBulkDwellMs)*time.Millisecond {
				f.elephant = true
				f.overSince = time.Time{}
			}
			return
		}
		f.overSince = time.Time{}
		return
	}

	// Promotion back, on its own lower threshold and its own longer
	// dwell. One line for both directions would flap the class of a flow
	// every time a download paused, and every flap moves it between
	// paths - which reorders it and costs the move twice.
	if kbps <= float64(cfg.ClassifyBulkClearKbps) {
		if f.clearSince.IsZero() {
			f.clearSince = now
		}
		if now.Sub(f.clearSince) >= time.Duration(cfg.ClassifyBulkClearMs)*time.Millisecond {
			f.elephant = false
			f.clearSince = time.Time{}
			f.total = 0
		}
		return
	}
	f.clearSince = time.Time{}
}

// nonRealtime is the class of a flow that is definitively not a call.
func (f *flow) nonRealtime() uint8 {
	if f.elephant {
		return protocol.ClassBulk
	}
	return protocol.ClassTransactional
}

// currentClass is what Classify would hand back for this flow's next
// packet, without feeding it one - the same three-way answer, reconstructed
// from state rather than a live decision.
func (f *flow) currentClass() uint8 {
	if f.decided {
		if f.class == protocol.ClassRealtime {
			return protocol.ClassRealtime
		}
		return f.nonRealtime()
	}
	// Still sampling: Classify's own default while undecided.
	return protocol.ClassTransactional
}

// FlowSnapshot is one tracked conversation, for the web interface's flow
// dump. It is a read-only copy - nothing about it feeds back into
// classification.
type FlowSnapshot struct {
	A, B            netip.Addr
	APort, BPort    uint16
	Proto           uint8
	Class           uint8
	Decided         bool
	Bytes           int64
	Samples         int
	LastSeenSeconds float64
}

// Snapshot returns every flow currently tracked, for a person to look at.
//
// It is not called on the hot path and must not be: the table is sized in
// thousands of entries (ClassifyMaxFlows), and copying it out under the
// lock is fine for something a button press asks for occasionally, not
// something computed per packet.
func (c *Classifier) Snapshot(now time.Time) []FlowSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]FlowSnapshot, 0, len(c.flows))
	for k, f := range c.flows {
		out = append(out, FlowSnapshot{
			A:               k.A,
			B:               k.B,
			APort:           k.APort,
			BPort:           k.BPort,
			Proto:           k.Proto,
			Class:           f.currentClass(),
			Decided:         f.decided,
			Bytes:           f.total,
			Samples:         f.samples,
			LastSeenSeconds: now.Sub(f.lastSeen).Seconds(),
		})
	}
	return out
}
