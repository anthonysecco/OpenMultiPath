package relay

import (
	"errors"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/lan"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/state"
)

// The vehicle's LAN subnets, told to home so home can route them back down
// the tunnel (D-068). The same exchange as the link speeds (D-055): the whole
// set, repeated until home acknowledges its digest, then silence until it
// changes. It differs in one way. It needs no wire version, so it may be
// talking to a home too old to answer, and it backs off rather than repeating
// once a second for as long as that home runs.

// lanRoutesResendMin and lanRoutesResendMax bound the repeat interval, which
// doubles with every unanswered copy. The first few repeats are as quick as a
// link speed's, so a set crossing a live tunnel lands in a second or two; the
// ceiling keeps an old home that never answers down to a packet a minute.
const (
	lanRoutesResendMin = time.Second
	lanRoutesResendMax = time.Minute
)

// lanRoutes is both ends' state for the exchange, under session.mu.
type lanRoutes struct {
	// The set held: the vehicle's from its LAN file, home's from the
	// vehicle. have is false until there is one, which on the vehicle means
	// the LAN is not managed from the LAN tab and nothing is sent.
	set    []netip.Prefix
	digest uint32
	have   bool

	// The vehicle's side of telling home.
	acked    bool
	routed   uint32 // the acknowledgement's mask of subnets home routed
	payload  []byte
	lastSent time.Duration
	backoff  time.Duration

	// Home's side: how a set is applied, and what came of the last one.
	apply     func([]netip.Prefix) []lan.RouteDecision
	decisions []lan.RouteDecision
}

// setLocalLANRoutes is the vehicle taking a set from its LAN file. A set
// different from the one held is queued for home.
func (s *session) setLocalLANRoutes(set []netip.Prefix) {
	set = protocol.SortLANRoutes(set)
	digest := protocol.LANRoutesDigest(set)
	s.mu.Lock()
	if s.lan.have && digest == s.lan.digest {
		s.mu.Unlock()
		return
	}
	s.lan.set, s.lan.digest, s.lan.have = set, digest, true
	s.lan.acked, s.lan.routed = false, 0
	s.lan.lastSent, s.lan.backoff = 0, lanRoutesResendMin
	s.lan.payload = protocol.AppendLANRoutes(nil, set)
	s.mu.Unlock()
	log.Printf("lan routes: vehicle LANs are %s", prefixText(set))
}

// lanRoutesDue returns the payload to send home now, or nil.
func (s *session) lanRoutesDue(now time.Duration) []byte {
	if s.role != roleInitiator {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l := &s.lan
	if !l.have || l.acked {
		return nil
	}
	if l.lastSent != 0 {
		if now-l.lastSent < l.backoff {
			return nil
		}
		l.backoff = min(l.backoff*2, lanRoutesResendMax)
	}
	l.lastSent = now
	return l.payload
}

// noteLANRoutesAck is the vehicle hearing which set home now holds, and which
// of its subnets home routed.
func (s *session) noteLANRoutesAck(payload []byte) {
	digest, routed, err := protocol.ParseLANRoutesAck(payload)
	if err != nil {
		return
	}
	s.mu.Lock()
	l := &s.lan
	if !l.have || l.acked || digest != l.digest {
		s.mu.Unlock()
		return
	}
	l.acked, l.routed = true, routed
	var refused []string
	for i, p := range l.set {
		if routed&(1<<i) == 0 {
			refused = append(refused, p.String())
		}
	}
	s.mu.Unlock()
	if len(refused) > 0 {
		log.Printf("lan routes: home acknowledged, but refused to route %s; see home's log", strings.Join(refused, ", "))
		return
	}
	log.Printf("lan routes: home acknowledged and routes every vehicle LAN")
}

// peerRestartedLANLocked makes the set due again after the peer restarts: a
// restarted home has only what it kept on disk, which may be older than the
// set held here.
func (s *session) peerRestartedLANLocked() {
	if s.role == roleInitiator && s.lan.have {
		s.lan.acked = false
		s.lan.lastSent, s.lan.backoff = 0, lanRoutesResendMin
	}
}

// receiveLANRoutes is home taking the vehicle's set, returning the
// acknowledgement. Every copy is answered: a repeat means the last
// acknowledgement was lost. Only a changed set is applied, so a repeat costs
// no route changes.
func (s *session) receiveLANRoutes(payload []byte) []byte {
	digest, set, err := protocol.ParseLANRoutes(payload)
	if err != nil {
		log.Printf("lan routes: ignoring a malformed set: %v", err)
		return nil
	}
	s.mu.Lock()
	changed := !s.lan.have || digest != s.lan.digest
	apply := s.lan.apply
	s.mu.Unlock()

	if changed {
		log.Printf("lan routes from the vehicle: %s", prefixText(set))
		var decisions []lan.RouteDecision
		if apply != nil {
			// Outside the lock: it runs ip and nft.
			decisions = apply(set)
		}
		s.mu.Lock()
		s.lan.set, s.lan.digest, s.lan.have = set, digest, true
		s.lan.decisions = decisions
		s.mu.Unlock()
	}

	s.mu.Lock()
	routed := routedMask(s.lan.set, s.lan.decisions, s.lan.apply != nil)
	s.mu.Unlock()
	return protocol.AppendLANRoutesAck(nil, digest, routed)
}

// routedMask sets bit i for each subnet in set that home routed. With no
// applier, which is a home not running on a TUN, nothing is routed.
func routedMask(set []netip.Prefix, decisions []lan.RouteDecision, applying bool) uint32 {
	if !applying {
		return 0
	}
	installed := map[netip.Prefix]bool{}
	for _, d := range decisions {
		installed[d.Prefix] = d.Installed
	}
	var mask uint32
	for i, p := range set {
		if installed[p] {
			mask |= 1 << i
		}
	}
	return mask
}

// setLANApplier installs home's route applier, and seeds the held set with
// what was restored from disk at startup, so a vehicle sending the same set
// again after a home restart changes nothing.
func (s *session) setLANApplier(apply func([]netip.Prefix) []lan.RouteDecision, restored []lan.RouteDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lan.apply = apply
	if len(restored) == 0 {
		return
	}
	set := make([]netip.Prefix, 0, len(restored))
	for _, d := range restored {
		set = append(set, d.Prefix)
	}
	set = protocol.SortLANRoutes(set)
	s.lan.set, s.lan.digest, s.lan.have = set, protocol.LANRoutesDigest(set), true
	s.lan.decisions = restored
}

// watchLANFile keeps the vehicle's set in step with the LAN tab's file,
// polled like the link speed file. A missing file sends nothing - the LAN is
// managed by hand and home was configured by hand to match - and a file that
// cannot be read keeps the set already held.
func (s *session) watchLANFile(path string) {
	var last time.Time
	var lastSize int64
	check := func() {
		fi, err := os.Stat(path)
		if err != nil {
			return
		}
		if fi.ModTime().Equal(last) && fi.Size() == lastSize {
			return
		}
		f, err := lan.Load(path)
		if errors.Is(err, lan.ErrNotConfigured) {
			return
		}
		if err != nil {
			log.Printf("lan routes: %v; keeping the set already held", err)
			return
		}
		last, lastSize = fi.ModTime(), fi.Size()
		s.setLocalLANRoutes(f.Subnets())
	}
	check()
	for range time.Tick(linkSpeedPoll) {
		check()
	}
}

// lanRoutesSnapshotLocked reports the exchange for the web interface.
func (s *session) lanRoutesSnapshotLocked() []state.LANRoute {
	l := &s.lan
	if !l.have {
		return nil
	}
	out := make([]state.LANRoute, 0, len(l.set))
	reasons := map[netip.Prefix]string{}
	for _, d := range l.decisions {
		reasons[d.Prefix] = d.Reason
	}
	for i, p := range l.set {
		r := state.LANRoute{Subnet: p.String()}
		if s.role == roleInitiator {
			r.Acknowledged = l.acked
			r.Routed = l.acked && l.routed&(1<<i) != 0
		} else {
			r.Acknowledged = true
			r.Routed = l.apply != nil && reasons[p] == ""
			r.Reason = reasons[p]
		}
		out = append(out, r)
	}
	return out
}

func prefixText(set []netip.Prefix) string {
	if len(set) == 0 {
		return "none"
	}
	s := make([]string, len(set))
	for i, p := range set {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}
