package lan

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The vehicle as it is set up: two LANs, DHCP on both.
func twoLANs() File {
	return File{
		Segments: []Segment{
			{Interface: "eth0", Name: "LAN 1", MAC: "02:ED:23:21:63:AB", Address: "10.0.0.1/24",
				DHCP: DHCP{Enabled: true}},
			{Interface: "ens19", Name: "LAN 2", MAC: "bc:24:11:d1:6d:cb", Address: "10.0.1.1/24",
				DHCP: DHCP{Enabled: true, DNSMode: DNSCustom, DNSServers: []string{"1.1.1.1"},
					Reservations: []Reservation{{MAC: "AA:BB:CC:DD:EE:FF", IP: "10.0.1.50", Hostname: "printer"}}}},
		},
	}.WithDefaults()
}

func TestDefaultsAreValid(t *testing.T) {
	f := twoLANs()
	if errs := f.Validate(); len(errs) > 0 {
		t.Fatalf("defaults do not validate: %v", errs)
	}
	s := f.Segments[0]
	if s.DHCP.RangeStart != "10.0.0.100" || s.DHCP.RangeEnd != "10.0.0.199" {
		t.Errorf("range = %s-%s, want the consumer default .100-.199", s.DHCP.RangeStart, s.DHCP.RangeEnd)
	}
	if s.DHCP.LeaseMinutes != DefaultLeaseMinutes || s.DHCP.DNSMode != DNSRouter || f.Domain != "lan" {
		t.Errorf("defaults not filled: %+v domain %q", s.DHCP, f.Domain)
	}
	if s.MAC != "02:ed:23:21:63:ab" {
		t.Errorf("MAC not normalised: %s", s.MAC)
	}
}

func TestDefaultRange(t *testing.T) {
	for _, c := range []struct{ addr, start, end string }{
		{"10.0.1.1/24", "10.0.1.100", "10.0.1.199"},
		{"192.168.1.150/24", "192.168.1.151", "192.168.1.199"}, // router inside the pool
		{"172.16.0.1/16", "172.16.64.0", "172.16.192.0"},
		{"10.9.9.1/30", "", ""},
		{"nonsense", "", ""},
	} {
		s, e := DefaultRange(c.addr)
		if s != c.start || e != c.end {
			t.Errorf("DefaultRange(%s) = %s-%s, want %s-%s", c.addr, s, e, c.start, c.end)
		}
	}
}

// Every mistake the tab can submit, each caught with a message naming it.
func TestValidateRefuses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*File)
		want   string
	}{
		{"overlapping LANs", func(f *File) { f.Segments[1].Address = "10.0.0.129/25" }, "overlaps 10.0.0.0/24"},
		{"tunnel subnet", func(f *File) { f.Segments[1].Address = "10.30.0.5/24" }, "tunnel itself"},
		{"transport subnet", func(f *File) { f.Segments[1].Address = "10.20.1.9/24" }, "tunnel itself"},
		{"public range", func(f *File) { f.Segments[1].Address = "8.8.8.1/24" }, "not a private range"},
		{"network address", func(f *File) { f.Segments[1].Address = "10.0.1.0/24" }, "network or broadcast"},
		{"too wide", func(f *File) { f.Segments[1].Address = "10.0.1.1/8" }, "not a usable LAN size"},
		{"no prefix", func(f *File) { f.Segments[1].Address = "10.0.1.1" }, "prefix length"},
		{"duplicate interface", func(f *File) { f.Segments[1].Interface = "eth0" }, "more than once"},
		{"range outside", func(f *File) { f.Segments[0].DHCP.RangeEnd = "10.0.1.20" }, "must be inside"},
		{"range backwards", func(f *File) { f.Segments[0].DHCP.RangeStart = "10.0.0.200" }, "ends before it starts"},
		{"range has router", func(f *File) { f.Segments[0].DHCP.RangeStart = "10.0.0.1" }, "router's own address"},
		{"lease too short", func(f *File) { f.Segments[0].DHCP.LeaseMinutes = 1 }, "lease time"},
		{"custom DNS empty", func(f *File) { f.Segments[1].DHCP.DNSServers = nil }, "at least one server"},
		{"bad DNS", func(f *File) { f.Segments[1].DHCP.DNSServers = []string{"dns.google"} }, "not an IPv4"},
		{"reservation outside", func(f *File) { f.Segments[1].DHCP.Reservations[0].IP = "10.0.0.50" }, "must be inside"},
		{"reservation router", func(f *File) { f.Segments[1].DHCP.Reservations[0].IP = "10.0.1.1" }, "router's own"},
		{"reservation MAC", func(f *File) { f.Segments[1].DHCP.Reservations[0].MAC = "zz" }, "MAC"},
		{"hostname", func(f *File) { f.Segments[1].DHCP.Reservations[0].Hostname = "my printer" }, "letters, digits"},
		{"duplicate reservation", func(f *File) {
			f.Segments[1].DHCP.Reservations = append(f.Segments[1].DHCP.Reservations,
				Reservation{MAC: "aa:bb:cc:dd:ee:00", IP: "10.0.1.50"})
		}, "more than one device"},
		{"domain", func(f *File) { f.Domain = "my.lan" }, "single lowercase"},
		{"no LANs", func(f *File) { f.Segments = nil }, "At least one"},
	}
	for _, c := range cases {
		f := twoLANs()
		c.mutate(&f)
		errs := f.Validate()
		if !strings.Contains(strings.Join(errs, "\n"), c.want) {
			t.Errorf("%s: errors %q do not mention %q", c.name, errs, c.want)
		}
	}
}

// DHCP switched off still checks the rest, but not a range nobody uses.
func TestValidateIgnoresRangeWhenDHCPOff(t *testing.T) {
	f := twoLANs()
	f.Segments[0].DHCP.Enabled = false
	f.Segments[0].DHCP.RangeStart, f.Segments[0].DHCP.RangeEnd = "", ""
	if errs := f.Validate(); len(errs) > 0 {
		t.Errorf("DHCP off refused: %v", errs)
	}
}

func TestAddressingEqual(t *testing.T) {
	a, b := twoLANs(), twoLANs()
	b.Segments[0].DHCP.LeaseMinutes = 60
	b.Segments[1].DHCP.Enabled = false
	if !AddressingEqual(a, b) {
		t.Error("a DHCP-only change counted as an address change")
	}
	b.Segments[0], b.Segments[1] = b.Segments[1], b.Segments[0]
	if !AddressingEqual(a, b) {
		t.Error("reordering counted as an address change")
	}
	b.Segments[0].Address = "10.0.1.2/24"
	if AddressingEqual(a, b) {
		t.Error("a new router address did not count")
	}
	c := twoLANs()
	c.Segments = c.Segments[:1]
	if AddressingEqual(a, c) {
		t.Error("removing a LAN did not count")
	}
}

func TestLoadSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lan.json")
	if _, err := Load(path); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("missing file: %v, want ErrNotConfigured", err)
	}
	if err := Save(path, twoLANs()); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Segments) != 2 || f.Segments[1].DHCP.Reservations[0].Hostname != "printer" {
		t.Errorf("round trip lost data: %+v", f)
	}
	os.WriteFile(path, []byte("{"), 0o644)
	if _, err := Load(path); err == nil || errors.Is(err, ErrNotConfigured) {
		t.Errorf("a corrupt file loaded: %v", err)
	}
}

func TestRenderNetplan(t *testing.T) {
	got := RenderNetplan(twoLANs())
	for _, want := range []string{
		"    eth0:\n      match:\n        macaddress: \"02:ed:23:21:63:ab\"\n      set-name: \"eth0\"\n",
		"      addresses:\n      - \"10.0.1.1/24\"\n",
		"      dhcp4: false\n      accept-ra: false\n",
		"        - 1.1.1.1\n        - 1.0.0.1\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("netplan lacks %q:\n%s", want, got)
		}
	}
}

func TestRenderDnsmasq(t *testing.T) {
	f := twoLANs()
	f.Segments[0].DHCP.Enabled = false
	got := RenderDnsmasq(f)
	for _, want := range []string{
		"bind-dynamic\n", "interface=eth0\n", "interface=ens19\n",
		"no-resolv\n", "server=1.1.1.1\n", "domain=lan\n", "local=/lan/\n",
		"interface-name=router.lan,ens19\n",
		"no-dhcp-interface=eth0\n",
		"dhcp-range=set:lan_ens19,10.0.1.100,10.0.1.199,255.255.255.0,720m\n",
		"dhcp-option=tag:lan_ens19,option:router,10.0.1.1\n",
		"dhcp-option=tag:lan_ens19,option:dns-server,1.1.1.1\n",
		"dhcp-host=aa:bb:cc:dd:ee:ff,10.0.1.50,printer\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("dnsmasq lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "dhcp-range=set:lan_eth0") {
		t.Error("DHCP switched off on eth0 but a range was still rendered")
	}
	if strings.Contains(got, "dhcp-authoritative") {
		t.Error("authoritative: would refuse the clients of any other DHCP server on the segment")
	}

	f.Segments[1].DHCP.DNSMode = DNSRouter
	if got := RenderDnsmasq(f); !strings.Contains(got, "option:dns-server,10.0.1.1\n") {
		t.Error("router DNS mode does not hand out the router's address")
	}
}

func TestLANEnv(t *testing.T) {
	if got := LANEnv(twoLANs()); !strings.Contains(got, `OMP_LAN="10.0.0.0/24 10.0.1.0/24"`) {
		t.Errorf("env = %s", got)
	}
}

func TestClients(t *testing.T) {
	f := twoLANs()
	leases := ParseLeases(strings.Join([]string{
		"2000000000 11:22:33:44:55:66 10.0.1.120 laptop 01:11:22:33:44:55:66",
		"2000000000 AA:BB:CC:DD:EE:FF 10.0.1.50 * *",      // the reservation's lease
		"1000 22:22:22:22:22:22 10.0.1.121 expired *",     // long expired
		"0 33:33:33:33:33:33 10.0.0.150 forever *",        // infinite lease
		"2000000000 44:44:44:44:44:44 192.168.9.9 away *", // not on any LAN
		"duid 00:01:00:01:2a:2b:2c:2d:2e:2f",              // IPv6 header line
		"2000000000 55:55:55:55:55:55 fd00::5 v6host *",   // IPv6
		"garbage",
	}, "\n"))
	neigh := ParseNeighbors([]byte(`[
		{"dst":"10.0.1.120","dev":"ens19","lladdr":"11:22:33:44:55:66","state":["REACHABLE"]},
		{"dst":"10.0.0.133","dev":"eth0","lladdr":"f4:26:79:05:02:6c","state":["STALE"]},
		{"dst":"10.0.0.183","dev":"eth0","state":["FAILED"]},
		{"dst":"10.0.1.99","dev":"eth0","lladdr":"66:66:66:66:66:66","state":["REACHABLE"]}
	]`))

	got := Clients(f, leases, neigh, 1_900_000_000)
	byIP := map[string]Client{}
	for _, c := range got {
		byIP[c.IP] = c
	}
	if len(got) != 4 {
		t.Fatalf("got %d clients, want 4: %+v", len(got), got)
	}
	if c := byIP["10.0.1.120"]; c.Kind != "dhcp" || c.Hostname != "laptop" || !c.Online || c.Segment != "LAN 2" {
		t.Errorf("laptop = %+v", c)
	}
	if c := byIP["10.0.1.50"]; c.Kind != "reserved" || !c.Reserved || c.Hostname != "printer" || c.Online {
		t.Errorf("printer = %+v", c)
	}
	if c := byIP["10.0.0.150"]; c.Kind != "dhcp" || c.LeaseExpiresUnix != 0 {
		t.Errorf("infinite lease = %+v", c)
	}
	if c := byIP["10.0.0.133"]; c.Kind != "static" || c.Online || c.Interface != "eth0" {
		t.Errorf("static device = %+v", c)
	}
	if got[0].Interface != "eth0" {
		t.Errorf("not ordered by LAN: first is %+v", got[0])
	}
}

// Home's guard is the one thing between a subnet off the network and home's
// routing table.
func TestScreen(t *testing.T) {
	local := []netip.Prefix{netip.MustParsePrefix("10.10.10.16/24"), netip.MustParsePrefix("10.20.1.1/24")}
	want := map[string]string{
		"10.0.0.0/24":     "",
		"10.0.1.0/24":     "",
		"10.10.10.0/25":   "attached to home",
		"10.30.0.0/24":    "tunnel's own",
		"0.0.0.0/0":       "wider than any LAN",
		"10.0.0.0/8":      "wider than any LAN",
		"100.64.0.0/24":   "not a private range",
		"192.168.50.0/24": "",
	}
	var in []netip.Prefix
	for p := range want {
		in = append(in, netip.MustParsePrefix(p))
	}
	for _, d := range Screen(in, local) {
		w := want[d.Prefix.String()]
		if w == "" && !d.Installed {
			t.Errorf("%s refused: %s", d.Prefix, d.Reason)
		}
		if w != "" && (d.Installed || !strings.Contains(d.Reason, w)) {
			t.Errorf("%s: installed %v reason %q, want refused for %q", d.Prefix, d.Installed, d.Reason, w)
		}
	}
}
