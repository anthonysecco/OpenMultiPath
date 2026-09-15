package wan

import (
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

func TestNameOrg(t *testing.T) {
	for _, c := range []struct {
		org  string
		asn  int
		name string
	}{
		{"AS14593 Space Exploration Technologies Corporation", 14593, "Starlink"},
		{"AS20057 AT&T Mobility LLC", 20057, "AT&T"},
		{"AS7018 AT&T Enterprises, LLC", 7018, "AT&T"},
		{"AS21928 T-Mobile USA, Inc.", 21928, "T-Mobile"},
		{"AS64500 Campground Wireless Co.", 64500, "Campground Wireless"},
		{"AS64501 Tiny ISP, Inc., LLC", 64501, "Tiny ISP"},
		{"Some Org Without AS", 0, "Some Org Without AS"},
		{"", 0, ""},
	} {
		asn, name := NameOrg(c.org)
		if asn != c.asn || name != c.name {
			t.Errorf("NameOrg(%q) = %d %q, want %d %q", c.org, asn, name, c.asn, c.name)
		}
	}
}

func TestParseIPInfo(t *testing.T) {
	isp, err := ParseIPInfo([]byte(`{"ip":"98.97.61.2","city":"Los Angeles","region":"California","country":"US","org":"AS14593 Space Exploration Technologies Corporation"}`), 42)
	if err != nil || isp.Name != "Starlink" || isp.PublicIP != "98.97.61.2" || isp.ASN != 14593 || isp.CheckedUnix != 42 {
		t.Errorf("got %+v %v", isp, err)
	}
	if _, err := ParseIPInfo([]byte(`{"error":{"title":"Rate limit exceeded"}}`), 0); err == nil {
		t.Error("a rate-limit answer parsed as an ISP")
	}
	if _, err := ParseIPInfo([]byte(`<html>captive portal</html>`), 0); err == nil {
		t.Error("a captive portal page parsed as an ISP")
	}
}

func TestUnclaimed(t *testing.T) {
	lans := map[string]bool{"eth0": true}
	configured := map[string]string{"enp1s0": "/etc/netplan/60-wan-i226.yaml"}
	for _, c := range []struct {
		link Link
		ok   bool
		why  string
	}{
		{Link{Name: "enx001122334455", MAC: "00:11:22:33:44:55", Hardware: true}, true, ""},
		{Link{Name: "eth0", MAC: "02:ed:23:21:63:ab", Hardware: true}, false, "a LAN"},
		{Link{Name: "enp1s0", MAC: "34:1a:4c:03:d5:c5", Hardware: true}, false, "configured in"},
		{Link{Name: "wg3", MAC: ""}, false, "virtual"},
		{Link{Name: "omp0"}, false, "virtual"},
		{Link{Name: "simup", MAC: "0a:1b:2c:3d:4e:5f"}, false, "not a hardware interface"},
		{Link{Name: "ens20", Hardware: true}, false, "no hardware address"},
		{Link{Name: "enx0a", MAC: "0a:0a:0a:0a:0a:0a", Hardware: true, HasIPv4: true}, false, "already has an address"},
	} {
		ok, why := Unclaimed(c.link, lans, configured)
		if ok != c.ok || !strings.Contains(why, c.why) {
			t.Errorf("%s: %v %q, want %v %q", c.link.Name, ok, why, c.ok, c.why)
		}
	}
}

// The probing policy the owner set: DHCP first; no lease, leave it until it
// is replugged; a lease but no internet, try again later; nothing attached,
// leave it; never probe what the owner is already deciding about.
func TestDecide(t *testing.T) {
	up := Link{Name: "ens20", MAC: "aa", Carrier: true, CarrierChanges: 4}
	down := Link{Name: "ens20", MAC: "aa", Carrier: false, CarrierChanges: 5}
	replugged := Link{Name: "ens20", MAC: "aa", Carrier: true, CarrierChanges: 6}
	const now = 10_000
	cand := func(state string, retry int64) *Candidate {
		return &Candidate{State: state, CarrierChanges: 4, RetryUnix: retry}
	}
	for _, c := range []struct {
		name string
		c    *Candidate
		l    Link
		want Action
	}{
		{"new link with carrier", nil, up, Probe},
		{"new port with nothing attached", nil, down, RecordNoLink},
		{"empty port stays empty", cand(NoLink, 0), down, Nothing},
		{"something plugged into an empty port", cand(NoLink, 0), up, Probe},
		{"no DHCP, same cable", cand(NoDHCP, 0), up, Nothing},
		{"no DHCP, replugged", cand(NoDHCP, 0), replugged, Probe},
		{"no internet, too soon", cand(NoInternet, now+1), up, Nothing},
		{"no internet, retry due", cand(NoInternet, now), up, Probe},
		{"no internet, replugged", cand(NoInternet, now+500), replugged, Probe},
		{"probe error, retry due", cand(ProbeError, now-1), up, Probe},
		{"already probing", cand(Probing, 0), replugged, Nothing},
		{"waiting for the owner", cand(Ready, 0), replugged, Nothing},
		{"ignored, same cable", cand(Ignored, 0), up, Nothing},
		{"ignored, replugged", cand(Ignored, 0), replugged, Probe},
		{"added", cand(Added, 0), replugged, Nothing},
		{"add failed, same cable", cand(AddFailed, 0), up, Nothing},
		{"no internet but carrier lost", cand(NoInternet, 0), down, Nothing},
	} {
		if got := Decide(c.c, c.l, now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseProbeAndApply(t *testing.T) {
	out := "ip=192.168.77.145\ncidr=24\ngateway=192.168.77.1\ndns=1.1.1.1\nhttp_code=204\n" +
		`ipinfo={  "ip": "172.56.1.2",  "org": "AS21928 T-Mobile USA, Inc."}` + "\nresult=internet\n"
	r := ParseProbe(out)
	var c Candidate
	c.Apply(r, 7, 100)
	if c.State != Ready || c.IP != "192.168.77.145" || c.ISP == nil || c.ISP.Name != "T-Mobile" || c.CarrierChanges != 7 {
		t.Errorf("internet: %+v isp %+v", c, c.ISP)
	}

	c.Apply(ParseProbe("ip=10.1.1.5\nhttp_code=302\ndetail=the connectivity check answered 302, not 204\nresult=no-internet\n"), 7, 100)
	if c.State != NoInternet || c.RetryUnix != 100+RetrySeconds || c.ISP != nil {
		t.Errorf("no internet: %+v", c)
	}
	c.Apply(ParseProbe("detail=no DHCP lease in 300s\nresult=no-dhcp\n"), 7, 100)
	if c.State != NoDHCP || c.RetryUnix != 0 {
		t.Errorf("no dhcp: %+v", c)
	}
	c.Apply(ParseProbe("ip=10.1.1.5\n"), 7, 100) // killed before it finished
	if c.State != ProbeError || c.Detail == "" {
		t.Errorf("unfinished probe: %+v", c)
	}
}

// The vehicle's real transports, as they are on disk.
const wg1Conf = `# D-020: one WireGuard interface per WAN link.
[Interface]
PrivateKey = cHJpdmF0ZQ==
Address = 10.20.1.2/32
FwMark = 0x2001
MTU = 1420
Table = off
PostUp = ip route replace 10.20.1.1/32 dev %i metric 1
PostDown = ip route del 10.20.1.1/32 dev %i metric 1 2>/dev/null || true

[Peer]
PublicKey = 74OXfOrqtYEtaaqXUryPEr3GCCRQglVegVL/5JhMXEM=
Endpoint = 162.231.243.253:48219
AllowedIPs = 10.20.1.1/32
PersistentKeepalive = 25
`

func realTransports(t *testing.T) []WGConf {
	wg1, err := ParseWGConf("wg1", wg1Conf)
	if err != nil {
		t.Fatal(err)
	}
	wg2, _ := ParseWGConf("wg2", strings.NewReplacer("10.20.1.2", "10.20.1.3", "0x2001", "0x2002", "metric 1", "metric 2").Replace(wg1Conf))
	wg0, _ := ParseWGConf("wg0", "[Interface]\nAddress = 10.20.0.2/24\n[Peer]\nPublicKey = x\n")
	return []WGConf{wg0, wg1, wg2}
}

func TestPlanTransportFollowsTheConventions(t *testing.T) {
	p, err := PlanTransport("ens20", "aa:bb:cc:dd:ee:ff", realTransports(t))
	if err != nil {
		t.Fatal(err)
	}
	if p.Transport != "wg3" || p.Mark != 0x2003 || p.Table != 2003 || p.Address.String() != "10.20.1.4" || p.Metric != 3 {
		t.Errorf("plan = %s mark %s table %d addr %s metric %d", p.Transport, p.MarkHex(), p.Table, p.Address, p.Metric)
	}
	if p.HomeAddr() != "10.20.1.1" {
		t.Errorf("home = %s", p.HomeAddr())
	}

	// With tables 2001-2009 taken the next is 2010, whose hex mark 0x2010
	// still spells it.
	var many []WGConf
	for i := 1; i <= 9; i++ {
		n := strconv.Itoa(i)
		c, err := ParseWGConf("wg"+n, strings.NewReplacer("0x2001", "0x200"+n, "10.20.1.2", "10.20.1."+strconv.Itoa(i+1)).Replace(wg1Conf))
		if err != nil {
			t.Fatal(err)
		}
		many = append(many, c)
	}
	p, err = PlanTransport("ens21", "aa:bb:cc:dd:ee:00", many)
	if err != nil || p.Table != 2010 || p.Mark != 0x2010 || p.Transport != "wg10" || p.Address.String() != "10.20.1.11" {
		t.Errorf("tenth transport: %+v %v", p, err)
	}

	if _, err := PlanTransport("ens20", "aa", []WGConf{{Name: "wg0"}}); err == nil {
		t.Error("planned a transport with no existing one to copy home's peer from")
	}
}

func TestRenderedFiles(t *testing.T) {
	p, _ := PlanTransport("ens20", "aa:bb:cc:dd:ee:ff", realTransports(t))
	p.ISP = "T-Mobile"
	np := RenderNetplan(p)
	for _, want := range []string{
		"    ens20:\n", `macaddress: "aa:bb:cc:dd:ee:ff"`, "dhcp4: true", "use-dns: false",
		"accept-ra: false", "link-local: []", "mark: 8195", "table: 2003", "priority: 2003",
	} {
		if !strings.Contains(np, want) {
			t.Errorf("netplan lacks %q:\n%s", want, np)
		}
	}
	if !strings.Contains(RenderDropin(p), "[DHCPv4]\nRouteTable=2003\n") {
		t.Errorf("drop-in:\n%s", RenderDropin(p))
	}
	wg := RenderWGConf(p, "PRIV")
	for _, want := range []string{
		"PrivateKey = PRIV", "Address = 10.20.1.4/32", "FwMark = 0x2003", "MTU = 1420", "Table = off",
		"PostUp = ip route replace 10.20.1.1/32 dev %i metric 3",
		"PublicKey = 74OXfOrqtYEtaaqXUryPEr3GCCRQglVegVL/5JhMXEM=", "Endpoint = 162.231.243.253:48219",
		"AllowedIPs = 10.20.1.1/32", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(wg, want) {
			t.Errorf("wg conf lacks %q:\n%s", want, wg)
		}
	}
	parsed, err := ParseWGConf("wg3", wg)
	if err != nil || parsed.FwMark != 0x2003 || parsed.Metric != 3 || parsed.PeerKey == "" {
		t.Errorf("rendered conf does not read back: %+v %v", parsed, err)
	}
}

func keyOf(b byte) (k [32]byte) {
	for i := range k {
		k[i] = b
	}
	return k
}

func b64(b byte) string {
	k := keyOf(b)
	return base64.StdEncoding.EncodeToString(k[:])
}

// Home only ever adds a peer, and only one that collides with nothing.
func TestScreenPeers(t *testing.T) {
	own := netip.MustParsePrefix("10.20.1.1/24")
	existing := ParseAllowedIPs(
		b64(1) + "\t10.20.1.2/32\n" + b64(2) + "\t10.20.1.3/32\n")
	tr := func(id uint8, k byte, addr string) protocol.Transport {
		return protocol.Transport{PathID: id, PublicKey: keyOf(k), Addr: netip.MustParseAddr(addr)}
	}
	got := ScreenPeers([]protocol.Transport{
		tr(0, 1, "10.20.1.2"),   // present
		tr(1, 2, "10.20.1.9"),   // present key, different address: never changed
		tr(2, 3, "10.20.1.4"),   // new: added
		tr(3, 4, "10.20.1.4"),   // same address as the one just added
		tr(4, 5, "10.20.1.3"),   // address of an existing peer
		tr(5, 6, "10.30.0.2"),   // outside the transport subnet
		tr(6, 7, "10.20.1.1"),   // home's own address
		tr(7, 0, "10.20.1.8"),   // no key
		tr(8, 8, "10.20.1.255"), // broadcast
	}, existing, own)
	want := []struct {
		present, added bool
		reason         string
	}{
		{true, false, ""},
		{false, false, "without 10.20.1.9"},
		{true, true, ""},
		{false, false, "already belongs"},
		{false, false, "already belongs"},
		{false, false, "outside"},
		{false, false, "not a usable"},
		{false, false, "no public key"},
		{false, false, "not a usable"},
	}
	for i, w := range want {
		d := got[i]
		if d.Present != w.present || d.Added != w.added || !strings.Contains(d.Reason, w.reason) {
			t.Errorf("entry %d: %+v, want present %v added %v reason %q", i, d, w.present, w.added, w.reason)
		}
	}
}
