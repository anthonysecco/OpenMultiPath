package relay

import (
	"encoding/base64"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
	"github.com/anthonysecco/OpenMultiPath/internal/state"
	"github.com/anthonysecco/OpenMultiPath/internal/wan"
)

// The vehicle's WireGuard transports and their ISPs, told to home (D-070,
// D-071). The exchange is the LAN routes' (lanroutes.go): the whole list,
// repeated with backoff until home acknowledges it, sent again when the peer
// restarts. Home adds a wgm peer for any transport it lacks, and both ends
// name each path after its ISP when nobody has given it a label.

// transports is both ends' state for the exchange, under session.mu.
type transports struct {
	list   []protocol.Transport
	digest uint32
	have   bool

	// The vehicle's side.
	acked    bool
	peered   uint32
	payload  []byte
	lastSent time.Duration
	backoff  time.Duration

	// Home's side.
	apply     func([]protocol.Transport) []wan.PeerDecision
	decisions []wan.PeerDecision
}

// setLocalTransports is the vehicle taking its current list. A changed list is
// queued for home, and its ISP names become the paths' names here.
func (s *session) setLocalTransports(list []protocol.Transport) {
	// Sorted as home will hold it, so bit i of its acknowledgement is entry i here.
	list = protocol.SortTransports(list)
	digest := protocol.TransportsDigest(list)
	s.mu.Lock()
	if s.tr.have && digest == s.tr.digest {
		s.mu.Unlock()
		return
	}
	s.tr.list, s.tr.digest, s.tr.have = list, digest, true
	s.tr.acked, s.tr.peered = false, 0
	s.tr.lastSent, s.tr.backoff = 0, lanRoutesResendMin
	s.tr.payload = protocol.AppendTransports(nil, list)
	s.mu.Unlock()
	s.setISPs(list)
	log.Printf("transports: %s", describeTransports(list))
}

// setISPs names each path after its ISP, at both ends. The map is replaced
// whole and read through an atomic pointer, because paths are named from
// places that do not hold the session lock.
func (s *session) setISPs(list []protocol.Transport) {
	m := make(map[uint8]string, len(list))
	for _, t := range list {
		if t.ISP != "" {
			m[t.PathID] = t.ISP
		}
	}
	s.isps.Store(&m)
}

// ispFor is a path's ISP name, or empty.
func (s *session) ispFor(id uint8) string {
	if m := s.isps.Load(); m != nil {
		return (*m)[id]
	}
	return ""
}

// transportsDue returns the payload to send home now, or nil.
func (s *session) transportsDue(now time.Duration) []byte {
	if s.role != roleInitiator {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &s.tr
	if !t.have || t.acked {
		return nil
	}
	if t.lastSent != 0 {
		if now-t.lastSent < t.backoff {
			return nil
		}
		t.backoff = min(t.backoff*2, lanRoutesResendMax)
	}
	t.lastSent = now
	return t.payload
}

// noteTransportsAck is the vehicle hearing which transports home has a peer
// for.
func (s *session) noteTransportsAck(payload []byte) {
	digest, peered, err := protocol.ParseTransportsAck(payload)
	if err != nil {
		return
	}
	s.mu.Lock()
	t := &s.tr
	if !t.have || t.acked || digest != t.digest {
		s.mu.Unlock()
		return
	}
	t.acked, t.peered = true, peered
	var missing []string
	for i, tr := range t.list {
		if peered&(1<<i) == 0 {
			missing = append(missing, pathLabel(tr.PathID, ""))
		}
	}
	s.mu.Unlock()
	if len(missing) > 0 {
		log.Printf("transports: home acknowledged, but has no peer for %s; see home's log", strings.Join(missing, ", "))
		return
	}
	log.Printf("transports: home acknowledged and has a peer for every transport")
}

func (s *session) peerRestartedTransportsLocked() {
	if s.role == roleInitiator && s.tr.have {
		s.tr.acked = false
		s.tr.lastSent, s.tr.backoff = 0, lanRoutesResendMin
	}
}

// receiveTransports is home taking the vehicle's list. Only a changed list is
// applied; every copy is answered.
func (s *session) receiveTransports(payload []byte) []byte {
	digest, list, err := protocol.ParseTransports(payload)
	if err != nil {
		log.Printf("transports: ignoring a malformed list: %v", err)
		return nil
	}
	s.mu.Lock()
	changed := !s.tr.have || digest != s.tr.digest
	apply := s.tr.apply
	s.mu.Unlock()

	if changed {
		log.Printf("transports from the vehicle: %s", describeTransports(list))
		var decisions []wan.PeerDecision
		if apply != nil {
			decisions = apply(list) // runs wg; outside the lock
		}
		s.mu.Lock()
		s.tr.list, s.tr.digest, s.tr.have = list, digest, true
		s.tr.decisions = decisions
		s.mu.Unlock()
		s.setISPs(list)
	}

	s.mu.Lock()
	var peered uint32
	for i, d := range s.tr.decisions {
		if d.Present && i < 32 {
			peered |= 1 << i
		}
	}
	s.mu.Unlock()
	return protocol.AppendTransportsAck(nil, digest, peered)
}

// setTransportsApplier installs home's peer applier.
func (s *session) setTransportsApplier(apply func([]protocol.Transport) []wan.PeerDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tr.apply = apply
}

// labelFor is a path's human name: the label somebody configured, else its
// ISP as ipinfo.io named it (D-071), else empty.
func (s *session) labelFor(c config.Config, id uint8) string {
	if l := labelOrEmpty(c, s.names[id]); l != "" {
		return l
	}
	return s.ispFor(id)
}

// displayLabel is labelFor falling back to the interface name, for logs.
func (s *session) displayLabel(c config.Config, id uint8) string {
	if l := s.labelFor(c, id); l != "" {
		return l
	}
	return s.names[id]
}

// watchTransports keeps the vehicle's list in step with its transports and
// the ISP file. Public keys and addresses are read from the interfaces
// themselves, so a transport that is not up yet simply joins the list once it
// is; the ISP file is polled like the other files the daemon watches.
func (s *session) watchTransports(ispPath string) {
	keys := map[string][32]byte{}
	lastErr := ""
	check := func() {
		isps, err := wan.LoadISPs(ispPath)
		if msg := errText(err); msg != lastErr {
			if msg != "" {
				log.Printf("transports: %s; naming paths without it", msg)
			}
			lastErr = msg
		}
		s.mu.Lock()
		names := make(map[uint8]string, len(s.names))
		for id, n := range s.names {
			names[id] = n
		}
		s.mu.Unlock()

		var list []protocol.Transport
		for id, name := range names {
			if name == "" {
				continue
			}
			k, ok := keys[name]
			if !ok {
				if k, ok = publicKey(name); !ok {
					continue
				}
				keys[name] = k
			}
			addr, ok := interfaceAddr(name)
			if !ok {
				continue
			}
			list = append(list, protocol.Transport{PathID: id, PublicKey: k, Addr: addr, ISP: isps.Links[name].Name})
		}
		if len(list) > 0 {
			s.setLocalTransports(list)
		}
	}
	check()
	for range time.Tick(linkSpeedPoll) {
		check()
	}
}

func publicKey(iface string) ([32]byte, bool) {
	var k [32]byte
	out, err := exec.Command("wg", "show", iface, "public-key").Output()
	if err != nil {
		return k, false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(b) != 32 {
		return k, false
	}
	copy(k[:], b)
	return k, true
}

func interfaceAddr(iface string) (netip.Addr, bool) {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return netip.Addr{}, false
	}
	addrs, _ := i.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			ip, _ := netip.AddrFromSlice(n.IP.To4())
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// transportsSnapshotLocked reports the exchange for the web interface.
func (s *session) transportsSnapshotLocked() []state.TransportPeer {
	t := &s.tr
	if !t.have {
		return nil
	}
	out := make([]state.TransportPeer, 0, len(t.list))
	for i, tr := range t.list {
		p := state.TransportPeer{
			PathID:    tr.PathID,
			PublicKey: base64.StdEncoding.EncodeToString(tr.PublicKey[:]),
			Address:   tr.Addr.String(),
			ISP:       tr.ISP,
		}
		if s.role == roleInitiator {
			p.Acknowledged = t.acked
			p.Peered = t.acked && t.peered&(1<<i) != 0
		} else {
			p.Acknowledged = true
			if i < len(t.decisions) {
				p.Peered = t.decisions[i].Present
				p.Reason = t.decisions[i].Reason
			}
		}
		out = append(out, p)
	}
	return out
}

func describeTransports(list []protocol.Transport) string {
	if len(list) == 0 {
		return "none"
	}
	parts := make([]string, len(list))
	for i, t := range list {
		isp := t.ISP
		if isp == "" {
			isp = "ISP unknown"
		}
		parts[i] = pathLabel(t.PathID, isp) + " at " + t.Addr.String()
	}
	return strings.Join(parts, "; ")
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
