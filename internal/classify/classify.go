// Package classify decides whether an inner packet is real-time or bulk.
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
// # The default when nothing is known
//
// A flow under observation is ClassUnknown, not ClassRealtime. Guessing
// real-time is the expensive mistake in both directions that matter:
// duplication burns a metered link, and admission control would reserve
// capacity for a download. Guessing bulk is cheap by comparison, and the
// signal that actually protects a call - STUN - fires before the media
// does, so a real conference is rarely in the unknown state at all.
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
}

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

	// protocol.md's free first-pass exclusion. Nothing about a TCP flow
	// needs remembering, so this returns ahead of the cache and keeps
	// bulk transfers from occupying entries that real conversations want.
	if p.flow.Proto == protoTCP {
		return protocol.ClassBulk
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

	if f.decided {
		return f.class
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

	// 4. Behavioural catch-all.
	c.observe(f, p, now)
	if f.samples >= cfg.ClassifySamplePackets {
		f.class, f.decided = c.behavioural(f, cfg), true
	}
	return f.class
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
