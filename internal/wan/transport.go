package wan

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// WGConf is the part of a wg-quick configuration a new transport is planned
// from.
type WGConf struct {
	Name      string
	Address   netip.Prefix
	FwMark    uint32 // 0 for none, which is not a per-link transport
	Metric    int    // of its route to home's tunnel address, from PostUp
	MTU       int
	PeerKey   string
	Endpoint  string
	AllowedIP string
	Keepalive int
}

var (
	wgNameRe   = regexp.MustCompile(`^wg(\d+)$`)
	postUpMet  = regexp.MustCompile(`metric\s+(\d+)`)
	sectionRe  = regexp.MustCompile(`^\[(\w+)\]$`)
	keyValueRe = regexp.MustCompile(`^(\w+)\s*=\s*(.*)$`)
)

// ParseWGConf reads one wg-quick configuration. Only the fields a plan needs
// are read; anything else is ignored.
func ParseWGConf(name, text string) (WGConf, error) {
	c := WGConf{Name: name}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			section = strings.ToLower(m[1])
			continue
		}
		m := keyValueRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		k, v := strings.ToLower(m[1]), strings.TrimSpace(m[2])
		switch section + "." + k {
		case "interface.address":
			first := strings.TrimSpace(strings.Split(v, ",")[0])
			p, err := netip.ParsePrefix(first)
			if err != nil {
				return c, fmt.Errorf("wan: %s: Address %q: %w", name, v, err)
			}
			c.Address = p
		case "interface.fwmark":
			if v != "off" {
				n, err := strconv.ParseUint(v, 0, 32)
				if err != nil {
					return c, fmt.Errorf("wan: %s: FwMark %q: %w", name, v, err)
				}
				c.FwMark = uint32(n)
			}
		case "interface.mtu":
			c.MTU, _ = strconv.Atoi(v)
		case "interface.postup":
			if mm := postUpMet.FindStringSubmatch(v); mm != nil {
				c.Metric, _ = strconv.Atoi(mm[1])
			}
		case "peer.publickey":
			c.PeerKey = v
		case "peer.endpoint":
			c.Endpoint = v
		case "peer.allowedips":
			c.AllowedIP = v
		case "peer.persistentkeepalive":
			c.Keepalive, _ = strconv.Atoi(v)
		}
	}
	return c, sc.Err()
}

// ReadWGConfs reads every wgN.conf in a directory. Backups and retired copies
// (wg1.conf.retired) are not configurations and are not read.
func ReadWGConfs(dir string) ([]WGConf, error) {
	files, err := filepath.Glob(filepath.Join(dir, "wg*.conf"))
	if err != nil {
		return nil, err
	}
	var out []WGConf
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".conf")
		if !wgNameRe.MatchString(name) {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		c, err := ParseWGConf(name, string(b))
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Plan is everything a new link's transport will be.
type Plan struct {
	Interface string
	MAC       string
	ISP       string // for the comments in the rendered files
	Transport string // wg3
	Mark      uint32 // 0x2003
	Table     int    // 2003, also the rule priority; its guard is Table+100 (D-069)
	Address   netip.Addr
	Metric    int
	Reference WGConf // an existing per-link transport the peer settings are copied from
}

// MarkHex is the mark as wg-quick and ip write it.
func (p Plan) MarkHex() string { return fmt.Sprintf("0x%x", p.Mark) }

// PlanTransport chooses a new transport for an interface, following the
// conventions every transport so far has used: wgN, with fwmark 0x200N routed
// by table 200N, the next free address in the transports' subnet, and the next
// metric for the route to home's tunnel address. It refuses rather than guess
// when there is no existing per-link transport to copy home's peer settings
// from.
func PlanTransport(iface, mac string, existing []WGConf) (Plan, error) {
	var ref *WGConf
	names, tables, addrs := map[int]bool{}, map[int]bool{}, map[netip.Addr]bool{}
	metric := 0
	for i, c := range existing {
		if m := wgNameRe.FindStringSubmatch(c.Name); m != nil {
			n, _ := strconv.Atoi(m[1])
			names[n] = true
		}
		if c.FwMark != 0 {
			if ref == nil {
				ref = &existing[i]
			}
			if t, err := strconv.Atoi(fmt.Sprintf("%x", c.FwMark)); err == nil {
				tables[t] = true
			}
			if c.Metric > metric {
				metric = c.Metric
			}
		}
		if c.Address.IsValid() {
			addrs[c.Address.Addr()] = true
		}
	}
	if ref == nil {
		return Plan{}, errors.New("no existing per-link WireGuard transport to copy home's peer settings from")
	}
	if ref.PeerKey == "" || ref.Endpoint == "" || ref.AllowedIP == "" {
		return Plan{}, fmt.Errorf("%s has no complete [Peer] section to copy", ref.Name)
	}

	p := Plan{Interface: iface, MAC: mac, Reference: *ref, Metric: metric + 1}
	n := 1
	for names[n] {
		n++
	}
	p.Transport = fmt.Sprintf("wg%d", n)

	// Tables are written in decimal and marks in hex with the same digits, so
	// only tables whose digits are all decimal work: 2001-2009, then 2010.
	for t := 2001; t < 3000; t++ {
		if tables[t] {
			continue
		}
		mark, err := strconv.ParseUint(strconv.Itoa(t), 16, 32)
		if err != nil {
			continue
		}
		p.Table, p.Mark = t, uint32(mark)
		break
	}
	if p.Table == 0 {
		return Plan{}, errors.New("no free routing table left for a transport")
	}

	subnet := netip.PrefixFrom(ref.Address.Addr(), 24).Masked()
	home, err := netip.ParsePrefix(strings.TrimSpace(strings.Split(ref.AllowedIP, ",")[0]))
	if err == nil {
		addrs[home.Addr()] = true
	}
	for a := subnet.Addr().Next().Next(); subnet.Contains(a); a = a.Next() {
		if !addrs[a] && a != broadcastOf(subnet) {
			p.Address = a
			break
		}
	}
	if !p.Address.IsValid() {
		return Plan{}, fmt.Errorf("no free address left in %s", subnet)
	}
	return p, nil
}

func broadcastOf(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Where a plan's files go.
func (p Plan) NetplanPath() string { return "/etc/netplan/62-omp-wan-" + p.Interface + ".yaml" }
func (p Plan) DropinPath() string {
	return "/etc/systemd/network/10-netplan-" + p.Interface + ".network.d/omp-wan.conf"
}
func (p Plan) WGConfPath() string { return "/etc/wireguard/" + p.Transport + ".conf" }
func (p Plan) WGKeyPath() string  { return "/etc/wireguard/" + p.Transport + "_private.key" }
func (p Plan) HomeAddr() string {
	return strings.TrimSuffix(strings.TrimSpace(strings.Split(p.Reference.AllowedIP, ",")[0]), "/32")
}
func (p Plan) label() string {
	if p.ISP != "" {
		return fmt.Sprintf("%s (%s)", p.Interface, p.ISP)
	}
	return p.Interface
}

// NetplanFilePrefix marks the netplan files this package writes, so the LAN
// tab and the scanner can tell a WAN link added here from anything else.
const NetplanFilePrefix = "62-omp-wan-"

// RenderNetplan is the link's own netplan: DHCP, and its policy rule.
//
// Its DHCP routes go into the link's table, not main (the drop-in below), so
// its table's default always follows whatever gateway the lease names. The
// hand-written links pin one gateway in netplan instead, and a lease with a
// different gateway - Starlink's boot-time one, say - leaves that link down
// until the usual gateway returns (D-069). The carrier's DNS is not used: the
// vehicle resolves through the tunnel (D-004). No IPv6 and no router
// advertisements, for D-026's reason.
func RenderNetplan(p Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# D-070: WAN link %s, added from the web interface.\n", p.label())
	fmt.Fprintf(&b, "# Its transport is %s (fwmark %s, table %d).\n", p.Transport, p.MarkHex(), p.Table)
	b.WriteString("network:\n  version: 2\n  ethernets:\n")
	fmt.Fprintf(&b, "    %s:\n", p.Interface)
	fmt.Fprintf(&b, "      match:\n        macaddress: %q\n", p.MAC)
	fmt.Fprintf(&b, "      set-name: %q\n", p.Interface)
	b.WriteString("      dhcp4: true\n")
	b.WriteString("      dhcp4-overrides:\n        use-dns: false\n        use-hostname: false\n        use-domains: false\n")
	b.WriteString("      optional: true\n      accept-ra: false\n      link-local: []\n")
	b.WriteString("      routing-policy:\n")
	b.WriteString("        - from: 0.0.0.0/0\n")
	fmt.Fprintf(&b, "          mark: %d   # %s - %s traffic, must egress %s\n", p.Mark, p.MarkHex(), p.Transport, p.Interface)
	fmt.Fprintf(&b, "          table: %d\n", p.Table)
	fmt.Fprintf(&b, "          priority: %d\n", p.Table)
	return b.String()
}

// RenderDropin puts the link's DHCP routes in its own table. netplan has no
// key for that, so it is a networkd drop-in beside netplan's generated file.
func RenderDropin(p Plan) string {
	return fmt.Sprintf("# D-070: %s's DHCP routes, default included, live in table %d, so\n"+
		"# %s's traffic follows the lease's gateway and nothing else does.\n"+
		"[DHCPv4]\nRouteTable=%d\n", p.label(), p.Table, p.Transport, p.Table)
}

// RenderWGConf is the transport's wg-quick configuration, in the form every
// transport so far has.
func RenderWGConf(p Plan, privateKey string) string {
	ref := p.Reference
	mtu := ref.MTU
	if mtu == 0 {
		mtu = 1420
	}
	keepalive := ref.Keepalive
	if keepalive == 0 {
		keepalive = 25
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# D-070: the WireGuard transport for WAN link %s, added from the\n", p.label())
	b.WriteString("# web interface. See wg1.conf for why each setting is what it is.\n")
	fmt.Fprintf(&b, "#\n# FwMark %s is routed by table %d, whose default route is %s's\n", p.MarkHex(), p.Table, p.Interface)
	fmt.Fprintf(&b, "# lease, and guarded at priority %d so a dead link cannot fall into the\n# tunnel (D-069).\n", p.Table+100)
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", privateKey)
	fmt.Fprintf(&b, "Address = %s/32\n", p.Address)
	fmt.Fprintf(&b, "FwMark = %s\n", p.MarkHex())
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	b.WriteString("Table = off\n")
	fmt.Fprintf(&b, "PostUp = ip route replace %s/32 dev %%i metric %d\n", p.HomeAddr(), p.Metric)
	fmt.Fprintf(&b, "PostDown = ip route del %s/32 dev %%i metric %d 2>/dev/null || true\n", p.HomeAddr(), p.Metric)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", ref.PeerKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", ref.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", ref.AllowedIP)
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keepalive)
	return b.String()
}
