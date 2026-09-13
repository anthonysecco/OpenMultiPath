package relay

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/linkspeed"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// Measured link speeds (D-055): where they come from at each end, how the
// vehicle tells home, and how they reach the shapers.
//
// Speeds are measured, never estimated. D-023's reactive ceiling and the
// cascade's queue-driven allowances are gone; a link's speed is whatever the
// flow test last measured, and unlimited until it has. A future enhancement
// is expected to detect speed dynamically from real traffic and loss,
// supplementing - not replacing - the measured figure.

// linkSpeedResend is how often the vehicle repeats a set home has not yet
// acknowledged. Once acknowledged, nothing is sent until the set changes.
const linkSpeedResend = time.Second

// linkSpeedPoll is how often the vehicle checks its measurement file, the
// same cadence the configuration is watched at.
const linkSpeedPoll = 2 * time.Second

// sendMeterWindow is how long one send-rate sample covers: short enough to
// catch a transfer starting, long enough that one video frame's burst is not
// read as a rate.
const sendMeterWindow = 500 * time.Millisecond

// sendMeter is how fast this end is sending on one path, in wire bytes. A
// meter, not an estimate of anything: the duplication gate compares it with
// the path's shaped speed.
type sendMeter struct {
	started  bool
	bytes    uint64
	winStart time.Duration
	kbps     float64
}

func (m *sendMeter) note(wireBytes int) { m.bytes += uint64(wireBytes) }

// observe closes the current window once it has run its length.
func (m *sendMeter) observe(now time.Duration) {
	if !m.started {
		// Start the window here rather than at zero, so a path first
		// sampled a minute after boot does not divide a handful of probe
		// bytes by that minute.
		m.started, m.winStart, m.bytes = true, now, 0
		return
	}
	elapsed := now - m.winStart
	if elapsed < sendMeterWindow {
		return
	}
	m.kbps = float64(m.bytes) * 8 / 1000 / elapsed.Seconds()
	m.bytes, m.winStart = 0, now
}

// setPathWriter installs how packets reach the network, and whether they
// cross a WireGuard interface on the way - which decides what a packet costs
// the link. Called once, before anything is sent.
func (s *session) setPathWriter(write func(id uint8, pkt []byte), throughWireGuard bool) {
	s.writePath = write
	s.throughWireGuard = throughWireGuard
}

// wireBytes is what a packet of n bytes occupies on the physical link.
func (s *session) wireBytes(n int) int {
	return protocol.IPWireBytes(n, s.throughWireGuard)
}

// shaperFor returns a path's shaper, creating it on first use.
func (s *session) shaperFor(id uint8) *pathShaper {
	if sh := s.shapers[id].Load(); sh != nil {
		return sh
	}
	sh := newPathShaper(s.elapsed,
		func(p *shapedPacket, buf []byte) []byte {
			return s.stampFlow(id, p.globalSeq, p.class, p.tag, p.payload, buf)
		},
		func(pkt []byte) {
			if s.writePath != nil {
				s.writePath(id, pkt)
			}
		},
		s.wireBytes,
	)
	// Created and given its rate under the lock that guards the speeds, so a
	// set arriving at the same moment cannot be applied to every shaper but
	// this one.
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.shapers[id].CompareAndSwap(nil, sh) {
		return s.shapers[id].Load()
	}
	sh.setRate(s.shapedKbpsLocked(id))
	return sh
}

// transmit sends one data packet on a path, through its shaper.
func (s *session) transmit(id uint8, globalSeq uint32, class uint8, tag flowTag, payload []byte) {
	s.shaperFor(id).send(class, globalSeq, tag, payload)
}

// sendControl sends measurement traffic at once, charged to the path's
// shaper so the data behind it waits its share.
func (s *session) sendControl(id uint8, pkt []byte) {
	if pkt == nil {
		return
	}
	s.shaperFor(id).charge(len(pkt))
	if s.writePath != nil {
		s.writePath(id, pkt)
	}
}

// localKbpsLocked is a path's measured speed in this end's send direction,
// or 0 when that has never been measured.
func (s *session) localKbpsLocked(id uint8) float64 {
	ls, ok := s.speeds[id]
	if !ok {
		return 0
	}
	if s.role == roleInitiator {
		return float64(ls.UpKbps)
	}
	return float64(ls.DownKbps)
}

// shapedKbpsLocked is what a path is shaped to, or 0 for unshaped.
func (s *session) shapedKbpsLocked(id uint8) float64 {
	return linkspeed.ShapedKbps(s.localKbpsLocked(id))
}

// installSpeedsLocked replaces the whole set and reshapes every path.
func (s *session) installSpeedsLocked(set []protocol.LinkSpeed) {
	s.speeds = make(map[uint8]protocol.LinkSpeed, len(set))
	for _, ls := range set {
		s.speeds[ls.PathID] = ls
	}
	s.speedDigest = protocol.LinkSpeedDigest(set)
	s.haveSpeeds = true
	for i := range s.shapers {
		if sh := s.shapers[i].Load(); sh != nil {
			sh.setRate(s.shapedKbpsLocked(uint8(i)))
		}
	}
}

// setLocalSpeeds is the vehicle taking a set from its own measurement file.
// A set different from the one held is installed and queued for home.
func (s *session) setLocalSpeeds(set []protocol.LinkSpeed) {
	digest := protocol.LinkSpeedDigest(set)
	s.mu.Lock()
	if s.haveSpeeds && digest == s.speedDigest {
		s.mu.Unlock()
		return
	}
	s.installSpeedsLocked(set)
	s.speedsAcked = false
	s.lastSpeedSent = 0
	s.speedPayload = protocol.AppendLinkSpeed(nil, set)
	desc := s.describeSpeedsLocked()
	s.mu.Unlock()
	log.Printf("link speeds: %s", desc)
}

// linkSpeedDue returns the payload to send home now, or nil. Only while home
// has not acknowledged the set held, at most once a linkSpeedResend, and only
// to a peer that will answer.
func (s *session) linkSpeedDue(now time.Duration) []byte {
	if s.role != roleInitiator || s.emitVersion() < 4 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.haveSpeeds || s.speedsAcked {
		return nil
	}
	if s.lastSpeedSent != 0 && now-s.lastSpeedSent < linkSpeedResend {
		return nil
	}
	s.lastSpeedSent = now
	return s.speedPayload
}

// noteLinkSpeedAck is the vehicle hearing which set home now holds.
func (s *session) noteLinkSpeedAck(payload []byte) {
	digest, err := protocol.ParseLinkSpeedAck(payload)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.haveSpeeds || s.speedsAcked || digest != s.speedDigest {
		return
	}
	s.speedsAcked = true
	log.Printf("link speeds: home acknowledged the current set")
}

// receiveLinkSpeeds is home taking the vehicle's set, returning the
// acknowledgement to send back. Every copy is answered, a repeat included:
// the repeat means the last acknowledgement was lost.
func (s *session) receiveLinkSpeeds(payload []byte) []byte {
	digest, set, err := protocol.ParseLinkSpeed(payload)
	if err != nil {
		log.Printf("link speeds: ignoring a malformed set: %v", err)
		return nil
	}
	s.mu.Lock()
	changed := !s.haveSpeeds || digest != s.speedDigest
	var desc string
	if changed {
		s.installSpeedsLocked(set)
		desc = s.describeSpeedsLocked()
	}
	s.mu.Unlock()
	if changed {
		log.Printf("link speeds from the vehicle: %s", desc)
	}
	return protocol.AppendLinkSpeedAck(nil, digest)
}

// describeSpeedsLocked renders the held set for the log.
func (s *session) describeSpeedsLocked() string {
	if len(s.speeds) == 0 {
		return "none measured, every link unshaped"
	}
	out := ""
	for id := 0; id < 256; id++ {
		ls, ok := s.speeds[uint8(id)]
		if !ok {
			continue
		}
		if out != "" {
			out += "; "
		}
		out += fmt.Sprintf("%s up %s down %s, shaped to %s",
			pathLabel(uint8(id), s.cfg.Get().LabelFor(s.names[uint8(id)])),
			kbpsText(float64(ls.UpKbps)), kbpsText(float64(ls.DownKbps)),
			kbpsText(s.shapedKbpsLocked(uint8(id))))
	}
	return out
}

func kbpsText(kbps float64) string {
	switch {
	case kbps <= 0:
		return "unmeasured"
	case kbps >= 1000:
		return fmt.Sprintf("%.1f Mbps", kbps/1000)
	}
	return fmt.Sprintf("%.0f kbps", kbps)
}

// watchLinkSpeeds keeps the vehicle's set in step with its measurement file.
// Polled on mtime and size, like the configuration, for the reasons given in
// config.Holder.Watch.
//
// A file that cannot be read keeps the set already held. Unreadable is not
// evidence the links changed, and dropping to unshaped on a transient error
// would flood the modems the shaping exists to protect.
func (s *session) watchLinkSpeeds(path string) {
	var last time.Time
	var lastSize int64
	seen := false
	check := func() {
		fi, err := os.Stat(path)
		switch {
		case os.IsNotExist(err):
			if seen || !s.holdsSpeeds() {
				seen = false
				s.setLocalSpeeds(nil)
			}
			return
		case err != nil:
			return
		}
		if seen && fi.ModTime().Equal(last) && fi.Size() == lastSize {
			return
		}
		f, err := linkspeed.Load(path)
		if err != nil {
			log.Printf("link speeds: %v; keeping the speeds already in use", err)
			return
		}
		last, lastSize, seen = fi.ModTime(), fi.Size(), true
		s.setLocalSpeeds(s.speedsFromFile(f))
	}
	check()
	for range time.Tick(linkSpeedPoll) {
		check()
	}
}

func (s *session) holdsSpeeds() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.haveSpeeds
}

// speedsFromFile maps the file's interface names onto path ids.
func (s *session) speedsFromFile(f linkspeed.File) []protocol.LinkSpeed {
	s.mu.Lock()
	defer s.mu.Unlock()
	var set []protocol.LinkSpeed
	for id, name := range s.names {
		m, ok := f.Links[name]
		if !ok || name == "" || (m.UpKbps <= 0 && m.DownKbps <= 0) {
			continue
		}
		set = append(set, protocol.LinkSpeed{
			PathID:       id,
			UpKbps:       kbpsWire(m.UpKbps),
			DownKbps:     kbpsWire(m.DownKbps),
			MeasuredUnix: uint32(m.MeasuredUnix),
		})
	}
	return set
}

func kbpsWire(kbps float64) uint32 {
	switch {
	case kbps <= 0:
		return 0
	case kbps >= 1<<32-1:
		return 1<<32 - 1
	}
	return uint32(kbps + 0.5)
}
