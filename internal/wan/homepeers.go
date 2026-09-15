package wan

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// Home's side of D-070: a peer on wgm for every transport the vehicle has.
//
// The list arrives inside an existing WireGuard transport, so it can only
// have come from the vehicle. Even so, home only ever adds: it never changes
// or removes a peer, never gives an address to a second key, and never hands
// out an address outside wgm's own subnet. The worst a bad list can do is
// fail to add a peer, and the vehicle's page says so.

// Peer is one peer as wgm holds it.
type Peer struct {
	Key        string
	AllowedIPs []netip.Prefix
}

// PeerDecision is what home did about one transport.
type PeerDecision struct {
	PathID uint8
	Key    string
	Addr   netip.Addr
	// Present is the peer existing at home once this is done.
	Present bool
	Added   bool
	Reason  string // why it was refused
}

// ScreenPeers decides, for each transport, whether home already has its peer,
// should add it, or must refuse it. own is wgm's address and subnet.
func ScreenPeers(list []protocol.Transport, existing []Peer, own netip.Prefix) []PeerDecision {
	byKey := map[string]Peer{}
	owner := map[netip.Addr]string{}
	for _, p := range existing {
		byKey[p.Key] = p
		for _, a := range p.AllowedIPs {
			if a.Bits() == 32 {
				owner[a.Addr()] = p.Key
			}
		}
	}
	var out []PeerDecision
	for _, t := range list {
		d := PeerDecision{PathID: t.PathID, Key: base64.StdEncoding.EncodeToString(t.PublicKey[:]), Addr: t.Addr}
		switch {
		case t.PublicKey == [32]byte{}:
			d.Reason = "no public key"
		case byKey[d.Key].Key != "":
			d.Present = true
			has := false
			for _, a := range byKey[d.Key].AllowedIPs {
				if a.Contains(t.Addr) {
					has = true
				}
			}
			if !has {
				// Existing peers are never changed. Say so rather than route
				// traffic somewhere it was not agreed.
				d.Present = false
				d.Reason = fmt.Sprintf("the peer exists at home without %s", t.Addr)
			}
		case !t.Addr.Is4() || !own.Contains(t.Addr):
			d.Reason = fmt.Sprintf("%s is outside home's transport subnet %s", t.Addr, own.Masked())
		case t.Addr == own.Addr() || t.Addr == own.Masked().Addr() || t.Addr == broadcastOf(own):
			d.Reason = fmt.Sprintf("%s is not a usable peer address", t.Addr)
		case owner[t.Addr] != "":
			d.Reason = fmt.Sprintf("%s already belongs to another peer", t.Addr)
		default:
			d.Added, d.Present = true, true
			owner[t.Addr] = d.Key
		}
		out = append(out, d)
	}
	return out
}

// HomePeers applies the vehicle's transports to wgm.
type HomePeers struct {
	Interface string // wgm
	ConfPath  string // /etc/wireguard/wgm.conf; empty skips persisting
}

// Apply adds the peers the screen allows, live and in wgm.conf.
func (h *HomePeers) Apply(list []protocol.Transport) []PeerDecision {
	existing, own, err := h.read()
	if err != nil {
		log.Printf("transports: reading %s: %v", h.Interface, err)
		out := make([]PeerDecision, len(list))
		for i, t := range list {
			out[i] = PeerDecision{PathID: t.PathID, Addr: t.Addr, Reason: "home could not read " + h.Interface}
		}
		return out
	}
	decisions := ScreenPeers(list, existing, own)
	for i, d := range decisions {
		switch {
		case d.Added:
			if out, err := exec.Command("wg", "set", h.Interface, "peer", d.Key, "allowed-ips", d.Addr.String()+"/32").CombinedOutput(); err != nil {
				decisions[i].Added, decisions[i].Present = false, false
				decisions[i].Reason = "wg set failed: " + strings.TrimSpace(string(out))
				log.Printf("transports: adding path %d's peer %s: %v: %s", d.PathID, d.Key, err, out)
				continue
			}
			log.Printf("transports: added path %d's peer %s at %s to %s", d.PathID, d.Key, d.Addr, h.Interface)
			h.persist(list[i], d)
		case !d.Present:
			log.Printf("transports: not adding path %d's peer: %s", d.PathID, d.Reason)
		}
	}
	return decisions
}

func (h *HomePeers) read() ([]Peer, netip.Prefix, error) {
	i, err := net.InterfaceByName(h.Interface)
	if err != nil {
		return nil, netip.Prefix{}, err
	}
	var own netip.Prefix
	addrs, _ := i.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			ip, _ := netip.AddrFromSlice(n.IP.To4())
			bits, _ := n.Mask.Size()
			own = netip.PrefixFrom(ip, bits)
		}
	}
	if !own.IsValid() {
		return nil, own, fmt.Errorf("%s has no IPv4 address", h.Interface)
	}
	out, err := exec.Command("wg", "show", h.Interface, "allowed-ips").Output()
	if err != nil {
		return nil, own, err
	}
	return ParseAllowedIPs(string(out)), own, nil
}

// ParseAllowedIPs reads `wg show <if> allowed-ips`.
func ParseAllowedIPs(out string) []Peer {
	var peers []Peer
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		p := Peer{Key: fields[0]}
		for _, f := range fields[1:] {
			if pfx, err := netip.ParsePrefix(f); err == nil {
				p.AllowedIPs = append(p.AllowedIPs, pfx)
			}
		}
		peers = append(peers, p)
	}
	return peers
}

// persist appends the peer to wgm.conf, so it survives wgm being restarted.
// Appended rather than rewritten: the file is hand-kept, and its comments are
// its documentation.
func (h *HomePeers) persist(t protocol.Transport, d PeerDecision) {
	if h.ConfPath == "" {
		return
	}
	b, err := os.ReadFile(h.ConfPath)
	if err != nil {
		log.Printf("transports: %v; peer %s is live but not saved", err, d.Key)
		return
	}
	if strings.Contains(string(b), d.Key) {
		return
	}
	name := t.ISP
	if name == "" {
		name = "a new link"
	}
	stanza := fmt.Sprintf("\n# RV via %s, path %d. Added by ompd when the vehicle reported it (D-070).\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n",
		name, t.PathID, d.Key, d.Addr)
	f, err := os.OpenFile(h.ConfPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		log.Printf("transports: %v; peer %s is live but not saved", err, d.Key)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(stanza); err != nil {
		log.Printf("transports: saving peer %s: %v", d.Key, err)
	}
}
