package lan

import (
	"bufio"
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Lease is one line of dnsmasq's lease file.
type Lease struct {
	ExpiresUnix int64 // 0 is an infinite lease
	MAC         string
	IP          string
	Hostname    string
}

// ParseLeases reads dnsmasq's lease file:
//
//	<expiry unix> <mac> <ip> <hostname or *> <client id or *>
//
// A line that does not parse is skipped, not fatal. The file is written by
// another program, and one odd line is no reason to show no clients.
func ParseLeases(data string) []Lease {
	var out []Lease
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		exp, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if _, err := netip.ParseAddr(fields[2]); err != nil {
			continue // an IPv6 DUID line, or garbage
		}
		host := fields[3]
		if host == "*" {
			host = ""
		}
		out = append(out, Lease{ExpiresUnix: exp, MAC: strings.ToLower(fields[1]), IP: fields[2], Hostname: host})
	}
	return out
}

// Neighbor is one entry of the kernel's neighbour table: a device this box
// has recently exchanged packets with on a LAN.
type Neighbor struct {
	Interface string
	IP        string
	MAC       string
	State     string
}

// ParseNeighbors reads `ip -j neigh show`.
func ParseNeighbors(data []byte) []Neighbor {
	var raw []struct {
		Dst    string   `json:"dst"`
		Dev    string   `json:"dev"`
		LLAddr string   `json:"lladdr"`
		State  []string `json:"state"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return nil
	}
	var out []Neighbor
	for _, r := range raw {
		a, err := netip.ParseAddr(r.Dst)
		if err != nil || !a.Is4() || r.LLAddr == "" {
			continue
		}
		state := ""
		if len(r.State) > 0 {
			state = r.State[0]
		}
		out = append(out, Neighbor{Interface: r.Dev, IP: r.Dst, MAC: strings.ToLower(r.LLAddr), State: state})
	}
	return out
}

// Client is one device on a LAN, as the LAN tab lists it.
type Client struct {
	Interface string `json:"interface"`
	Segment   string `json:"segment"`
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Hostname  string `json:"hostname"`
	// Kind is how it got its address: "dhcp", "reserved", or "static" for a
	// device seen on the wire with an address it gave itself.
	Kind string `json:"kind"`
	// LeaseExpiresUnix is when a DHCP lease runs out; 0 for none.
	LeaseExpiresUnix int64 `json:"lease_expires_unix"`
	// Online is the kernel having heard from it recently.
	Online bool `json:"online"`
	// Reserved says the address is pinned to this device.
	Reserved bool `json:"reserved"`
}

// Clients merges leases, reservations and the neighbour table into one list
// per device, placed on whichever segment its address belongs to. A device
// outside every segment is left out: it is not on a LAN this box manages.
func Clients(f File, leases []Lease, neigh []Neighbor, nowUnix int64) []Client {
	type key struct{ mac, ip string }
	byKey := map[key]*Client{}
	segmentFor := func(ipStr string) (Segment, bool) {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return Segment{}, false
		}
		for _, s := range f.Segments {
			if p, err := s.Prefix(); err == nil && p.Contains(ip) {
				return s, true
			}
		}
		return Segment{}, false
	}
	get := func(mac, ip string) *Client {
		k := key{mac, ip}
		if c, ok := byKey[k]; ok {
			return c
		}
		s, ok := segmentFor(ip)
		if !ok {
			return nil
		}
		c := &Client{Interface: s.Interface, Segment: s.Name, IP: ip, MAC: mac, Kind: "static"}
		byKey[k] = c
		return c
	}

	for _, s := range f.Segments {
		for _, r := range s.DHCP.Reservations {
			if c := get(r.MAC, r.IP); c != nil {
				c.Kind, c.Reserved, c.Hostname = "reserved", true, r.Hostname
			}
		}
	}
	for _, l := range leases {
		if l.ExpiresUnix != 0 && l.ExpiresUnix < nowUnix {
			continue
		}
		c := get(l.MAC, l.IP)
		if c == nil {
			continue
		}
		if !c.Reserved {
			c.Kind = "dhcp"
		}
		if c.Hostname == "" {
			c.Hostname = l.Hostname
		}
		c.LeaseExpiresUnix = l.ExpiresUnix
	}
	for _, n := range neigh {
		switch n.State {
		case "FAILED", "INCOMPLETE", "NOARP", "PERMANENT":
			continue
		}
		// Only the segment's own interface: an address answered on another
		// is a misconfigured device, not a client of that LAN.
		if s, ok := segmentFor(n.IP); !ok || s.Interface != n.Interface {
			continue
		}
		c := get(n.MAC, n.IP)
		if c == nil {
			continue
		}
		if n.State == "REACHABLE" || n.State == "DELAY" || n.State == "PROBE" {
			c.Online = true
		}
	}

	out := make([]Client, 0, len(byKey))
	for _, c := range byKey {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return segmentOrder(f, out[i].Interface) < segmentOrder(f, out[j].Interface)
		}
		a, _ := netip.ParseAddr(out[i].IP)
		b, _ := netip.ParseAddr(out[j].IP)
		if a != b {
			return a.Less(b)
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

func segmentOrder(f File, iface string) int {
	for i, s := range f.Segments {
		if s.Interface == iface {
			return i
		}
	}
	return len(f.Segments)
}
