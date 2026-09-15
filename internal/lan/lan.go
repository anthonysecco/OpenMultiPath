// Package lan is the vehicle's own side of the network: the LAN segments
// its devices plug into, their addresses, and the DHCP and DNS service on
// them (D-067).
//
// Nothing here is novel, and that is the point. Addresses are netplan's job
// and DHCP and DNS are dnsmasq's - the same server OpenWrt uses - so this
// package does no networking at all. It holds one settings file, checks it,
// and renders it into the files those tools already read. ompui is the only
// writer, as it is of every other settings file (D-032); ompd reads the file
// too, for the subnets home has to route back to the vehicle (D-068).
//
// The render functions are pure so the whole path from settings to config
// can be tested on a bench, which is where a typo in a DHCP range belongs
// rather than in a campground.
package lan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// DefaultPath is where the LAN settings live. /etc rather than /var/lib:
// unlike a measurement, every value here is one somebody chose.
const DefaultPath = "/etc/openmultipath/lan.json"

// DNS modes: what a DHCP client is told to use for name lookups.
const (
	// DNSRouter hands out the segment's own address, where dnsmasq answers
	// and forwards through the tunnel. The default, because it is what
	// makes a device reachable by its hostname from the others.
	DNSRouter = "router"
	// DNSCustom hands out the servers listed on the segment, bypassing the
	// router's resolver. Still tunnelled - there is no split tunnel for
	// DNS any more than for anything else (D-004).
	DNSCustom = "custom"
)

// Defaults for anything left unset. Every tunable needs a working default.
const (
	DefaultDomain       = "lan"
	DefaultLeaseMinutes = 720
	MinLeaseMinutes     = 2
	MaxLeaseMinutes     = 7 * 24 * 60
)

// DefaultUpstreamDNS is where the router's resolver forwards. These two are
// already pinned into the tunnel by omp-tun-up, so the router's own lookups
// cannot leak out a carrier's link by way of a DHCP host route.
var DefaultUpstreamDNS = []string{"1.1.1.1", "1.0.0.1"}

// Reserved lists subnets a LAN must never overlap: the transport tunnels'
// subnet and the daemon's inner one (D-020). Taking either for a LAN would
// route the tunnel into itself.
var Reserved = []netip.Prefix{
	netip.MustParsePrefix("10.20.0.0/16"),
	netip.MustParsePrefix("10.30.0.0/24"),
}

// File is the whole LAN configuration.
type File struct {
	// Domain is the local DNS suffix, so a laptop is also laptop.lan.
	Domain string `json:"domain"`
	// UpstreamDNS is where the router's resolver forwards.
	UpstreamDNS []string  `json:"upstream_dns"`
	Segments    []Segment `json:"segments"`
}

// Segment is one LAN interface.
type Segment struct {
	// Interface is the kernel name, e.g. eth0.
	Interface string `json:"interface"`
	// Name is what a person calls it, e.g. "LAN 2".
	Name string `json:"name"`
	// MAC pins the interface by hardware address, so a virtual NIC that
	// enumerates in a different order after a reboot keeps its name - and
	// its address - instead of trading them with its neighbour.
	MAC string `json:"mac,omitempty"`
	// Address is the router's own address on the segment, in CIDR form,
	// e.g. 10.0.1.1/24. The prefix length is the segment's size.
	Address string `json:"address"`
	DHCP    DHCP   `json:"dhcp"`
}

// DHCP is a segment's DHCP service.
type DHCP struct {
	Enabled      bool          `json:"enabled"`
	RangeStart   string        `json:"range_start"`
	RangeEnd     string        `json:"range_end"`
	LeaseMinutes int           `json:"lease_minutes"`
	DNSMode      string        `json:"dns_mode"`
	DNSServers   []string      `json:"dns_servers,omitempty"`
	Reservations []Reservation `json:"reservations,omitempty"`
}

// Reservation always gives one device the same address.
type Reservation struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
}

// Prefix is the segment's subnet, e.g. 10.0.1.0/24.
func (s Segment) Prefix() (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s.Address))
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

// Label is how a segment is named in messages.
func (s Segment) Label() string {
	if s.Name != "" {
		return fmt.Sprintf("%s (%s)", s.Name, s.Interface)
	}
	return s.Interface
}

// Subnets lists every segment's subnet, in the file's order, skipping any
// that do not parse. It is what home has to route back to the vehicle.
func (f File) Subnets() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range f.Segments {
		if p, err := s.Prefix(); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// Segment returns the segment on an interface.
func (f File) Segment(iface string) (Segment, bool) {
	for _, s := range f.Segments {
		if s.Interface == iface {
			return s, true
		}
	}
	return Segment{}, false
}

// Load reads the settings. A missing file returns ErrNotConfigured: a box
// with no LAN settings is managed by hand, and nothing here should start
// rewriting its network until somebody saves from the LAN tab.
func Load(path string) (File, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return File{}, ErrNotConfigured
	}
	if err != nil {
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, fmt.Errorf("lan: %s: %w", path, err)
	}
	return f.WithDefaults(), nil
}

// ErrNotConfigured is Load finding no settings file.
var ErrNotConfigured = errors.New("lan: not configured")

// Save replaces the settings atomically, so ompd never reads half a file.
func Save(path string, f File) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(path, append(b, '\n'), 0o644)
}

// WriteAtomic replaces a file by renaming a synced temporary copy over it.
func WriteAtomic(path string, b []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
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
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// WithDefaults fills in whatever was left unset.
func (f File) WithDefaults() File {
	if strings.TrimSpace(f.Domain) == "" {
		f.Domain = DefaultDomain
	}
	if len(f.UpstreamDNS) == 0 {
		f.UpstreamDNS = append([]string(nil), DefaultUpstreamDNS...)
	}
	segs := make([]Segment, len(f.Segments))
	for i, s := range f.Segments {
		s.Interface = strings.TrimSpace(s.Interface)
		s.Address = strings.TrimSpace(s.Address)
		s.MAC = strings.ToLower(strings.TrimSpace(s.MAC))
		if s.DHCP.LeaseMinutes == 0 {
			s.DHCP.LeaseMinutes = DefaultLeaseMinutes
		}
		if s.DHCP.DNSMode == "" {
			s.DHCP.DNSMode = DNSRouter
		}
		if s.DHCP.Enabled && s.DHCP.RangeStart == "" && s.DHCP.RangeEnd == "" {
			s.DHCP.RangeStart, s.DHCP.RangeEnd = DefaultRange(s.Address)
		}
		res := make([]Reservation, len(s.DHCP.Reservations))
		for j, r := range s.DHCP.Reservations {
			r.MAC = strings.ToLower(strings.TrimSpace(r.MAC))
			r.IP = strings.TrimSpace(r.IP)
			r.Hostname = strings.TrimSpace(r.Hostname)
			res[j] = r
		}
		s.DHCP.Reservations = res
		segs[i] = s
	}
	f.Segments = segs
	return f
}

// DefaultRange suggests a DHCP pool for a router address: .100 to .199 on
// a /24, the consumer-router convention, and the middle of the subnet
// otherwise. Empty strings for an address that does not parse.
func DefaultRange(address string) (start, end string) {
	pfx, err := netip.ParsePrefix(address)
	if err != nil || !pfx.Addr().Is4() || pfx.Bits() > 29 {
		return "", ""
	}
	base := v4(pfx.Masked().Addr())
	size := uint32(1) << (32 - pfx.Bits())
	lo, hi := base+size/4, base+size/4*3
	if pfx.Bits() == 24 {
		lo, hi = base+100, base+199
	}
	if router := v4(pfx.Addr()); router >= lo && router <= hi {
		// Never hand out the router's own address.
		lo = router + 1
	}
	return fromV4(lo).String(), fromV4(hi).String()
}

func v4(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fromV4(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

var (
	ifaceRe    = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	domainRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidHostname says whether a name is usable as a single DNS label.
func ValidHostname(h string) bool { return hostnameRe.MatchString(h) }

// Validate checks the whole file and returns every problem at once, each
// phrased for the person who has to fix it. A file that fails is never
// applied: the network the vehicle has now is always better than one built
// from a half-valid description.
func (f File) Validate() []string {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	if !domainRe.MatchString(f.Domain) {
		add("Local domain %q must be a single lowercase DNS label, like \"lan\".", f.Domain)
	}
	for _, u := range f.UpstreamDNS {
		if a, err := netip.ParseAddr(u); err != nil || !a.Is4() {
			add("Upstream DNS server %q is not an IPv4 address.", u)
		}
	}
	if len(f.Segments) == 0 {
		add("At least one LAN is needed.")
	}

	seenIface := map[string]bool{}
	type claimed struct {
		p     netip.Prefix
		label string
	}
	var nets []claimed
	for _, s := range f.Segments {
		label := s.Label()
		if !ifaceRe.MatchString(s.Interface) {
			add("%s: interface name %q is not valid.", label, s.Interface)
			continue
		}
		if seenIface[s.Interface] {
			add("%s is listed more than once.", s.Interface)
			continue
		}
		seenIface[s.Interface] = true
		if s.MAC != "" {
			if _, err := net.ParseMAC(s.MAC); err != nil {
				add("%s: MAC address %q is not valid.", label, s.MAC)
			}
		}

		pfx, err := netip.ParsePrefix(s.Address)
		if err != nil || !pfx.Addr().Is4() {
			add("%s: address %q must be IPv4 with a prefix length, like 10.0.1.1/24.", label, s.Address)
			continue
		}
		if pfx.Bits() < 16 || pfx.Bits() > 30 {
			add("%s: a /%d is not a usable LAN size; use /16 to /30.", label, pfx.Bits())
			continue
		}
		subnet := pfx.Masked()
		if !subnet.Addr().IsPrivate() {
			add("%s: %s is not a private range (10/8, 172.16/12 or 192.168/16).", label, subnet)
		}
		router := pfx.Addr()
		if router == subnet.Addr() || router == broadcast(subnet) {
			add("%s: %s is the subnet's network or broadcast address, not a usable router address.", label, router)
		}
		for _, r := range Reserved {
			if r.Overlaps(subnet) {
				add("%s: %s overlaps %s, which the tunnel itself uses.", label, subnet, r)
			}
		}
		for _, other := range nets {
			if other.p.Overlaps(subnet) {
				add("%s: %s overlaps %s on %s. Each LAN needs its own subnet.", label, subnet, other.p, other.label)
			}
		}
		nets = append(nets, claimed{subnet, label})

		errs = append(errs, s.DHCP.validate(label, subnet, router)...)
	}
	return errs
}

func (d DHCP) validate(label string, subnet netip.Prefix, router netip.Addr) []string {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	inside := func(a netip.Addr) bool {
		return subnet.Contains(a) && a != subnet.Addr() && a != broadcast(subnet)
	}

	if d.LeaseMinutes < MinLeaseMinutes || d.LeaseMinutes > MaxLeaseMinutes {
		add("%s: lease time must be %d minutes to %d days.", label, MinLeaseMinutes, MaxLeaseMinutes/(24*60))
	}
	switch d.DNSMode {
	case DNSRouter:
	case DNSCustom:
		if len(d.DNSServers) == 0 {
			add("%s: custom DNS needs at least one server.", label)
		}
		for _, srv := range d.DNSServers {
			if a, err := netip.ParseAddr(srv); err != nil || !a.Is4() {
				add("%s: DNS server %q is not an IPv4 address.", label, srv)
			}
		}
	default:
		add("%s: DNS mode %q must be %q or %q.", label, d.DNSMode, DNSRouter, DNSCustom)
	}

	if d.Enabled {
		start, err1 := netip.ParseAddr(d.RangeStart)
		end, err2 := netip.ParseAddr(d.RangeEnd)
		switch {
		case err1 != nil || err2 != nil:
			add("%s: the DHCP range needs a start and end address.", label)
		case !inside(start) || !inside(end):
			add("%s: the DHCP range %s-%s must be inside %s.", label, d.RangeStart, d.RangeEnd, subnet)
		case end.Less(start):
			add("%s: the DHCP range ends before it starts.", label)
		case !router.Less(start) && !end.Less(router):
			add("%s: the DHCP range includes the router's own address %s.", label, router)
		}
	}

	seenMAC, seenIP, seenName := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range d.Reservations {
		if _, err := net.ParseMAC(r.MAC); err != nil {
			add("%s: reservation MAC %q is not valid.", label, r.MAC)
		} else if seenMAC[r.MAC] {
			add("%s: %s has more than one reservation.", label, r.MAC)
		}
		seenMAC[r.MAC] = true
		ip, err := netip.ParseAddr(r.IP)
		switch {
		case err != nil || !inside(ip):
			add("%s: reserved address %q must be inside %s.", label, r.IP, subnet)
		case ip == router:
			add("%s: %s is the router's own address and cannot be reserved.", label, r.IP)
		case seenIP[r.IP]:
			add("%s: %s is reserved for more than one device.", label, r.IP)
		}
		seenIP[r.IP] = true
		if r.Hostname != "" {
			if !ValidHostname(r.Hostname) {
				add("%s: hostname %q may use only letters, digits and hyphens.", label, r.Hostname)
			} else if seenName[strings.ToLower(r.Hostname)] {
				add("%s: hostname %q is used twice.", label, r.Hostname)
			}
			seenName[strings.ToLower(r.Hostname)] = true
		}
	}
	return errs
}

func broadcast(p netip.Prefix) netip.Addr {
	return fromV4(v4(p.Addr()) | (uint32(1)<<(32-p.Bits()) - 1))
}

// AddressingEqual says whether two files give every interface the same
// address. Only a change here can cut off the person making it, so only a
// change here goes on probation.
func AddressingEqual(a, b File) bool {
	key := func(f File) string {
		parts := make([]string, 0, len(f.Segments))
		for _, s := range f.Segments {
			parts = append(parts, s.Interface+"="+s.Address+"@"+s.MAC)
		}
		sort.Strings(parts)
		return strings.Join(parts, ",")
	}
	return key(a) == key(b)
}

// LANEnv renders /etc/default/openmultipath, which the shell scripts that
// know about the LAN (omp-pep-rules, omp-fallback) read.
func LANEnv(f File) string {
	subnets := make([]string, 0, len(f.Segments))
	for _, p := range f.Subnets() {
		subnets = append(subnets, p.String())
	}
	return "# Written by ompui from " + DefaultPath + "; edit the LAN tab, not this file.\n" +
		"# Every LAN segment on the vehicle, space-separated. Read by omp-pep-rules,\n" +
		"# omp-fallback and omp-tun-up.\n" +
		fmt.Sprintf("OMP_LAN=%q\n", strings.Join(subnets, " "))
}
