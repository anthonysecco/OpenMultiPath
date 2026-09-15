package wan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/anthonysecco/OpenMultiPath/internal/lan"
)

// DefaultCandidatesPath is where what is known about new links is kept, so a
// restart of ompui neither forgets a link waiting for the owner nor probes
// every link again.
const DefaultCandidatesPath = "/var/lib/openmultipath/wan-candidates.json"

// RetrySeconds is how long a link with an address but no internet - or a
// probe that could not run - waits before it is probed again. Long enough
// that probing is not a load on a link that is genuinely not the internet
// (a captive portal, a printer's network); short enough that a link whose
// service comes up later is noticed without anyone asking.
const RetrySeconds = 10 * 60

// States a new link moves through.
const (
	// NoLink: nothing is attached. Left alone: what to do with an empty port
	// is a future enhancement (D-070).
	NoLink = "no-link"
	// Probing: omp-wan-probe is running on it, which can take the whole
	// five-minute window. The interface is inside the probe's namespace
	// meanwhile and so is not visible to the vehicle.
	Probing = "probing"
	// NoDHCP: no lease in the window. Nothing is done until the link is
	// replugged.
	NoDHCP = "no-dhcp"
	// NoInternet: a lease, but no answer from the connectivity check. Probed
	// again every RetrySeconds, and on a replug.
	NoInternet = "no-internet"
	// ProbeError: the probe itself failed. Retried like NoInternet.
	ProbeError = "error"
	// Ready: a lease and the internet. Waiting for the owner to add it.
	Ready = "ready"
	// Ignored: the owner declined it. Reconsidered on a replug.
	Ignored = "ignored"
	// Adding: being provisioned.
	Adding = "adding"
	// Added: a WAN link with its own transport and path.
	Added = "added"
	// AddFailed: provisioning failed and was undone. Detail says why; the
	// owner can try again.
	AddFailed = "add-failed"
)

// Candidate is what is known about one link that was not a LAN or a WAN when
// it was found.
type Candidate struct {
	Interface string `json:"interface"`
	MAC       string `json:"mac"`
	State     string `json:"state"`
	Detail    string `json:"detail,omitempty"`
	IP        string `json:"ip,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
	ISP       *ISP   `json:"isp,omitempty"`
	// ProbedUnix is when the last probe finished; RetryUnix when the next
	// is allowed.
	ProbedUnix int64 `json:"probed_unix,omitempty"`
	RetryUnix  int64 `json:"retry_unix,omitempty"`
	// CarrierChanges is the kernel's carrier_changes counter as of the last
	// probe. A different value means the link was unplugged or lost power
	// since, which is what makes a link worth probing again.
	CarrierChanges int64 `json:"carrier_changes"`
	// Transport is the WireGuard interface it was given, once added.
	Transport string `json:"transport,omitempty"`
}

// CandidatesFile is every candidate, keyed by interface name.
type CandidatesFile struct {
	Links map[string]Candidate `json:"links"`
}

// LoadCandidates reads the file. A missing file is an empty one.
func LoadCandidates(path string) (CandidatesFile, error) {
	f := CandidatesFile{Links: map[string]Candidate{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return CandidatesFile{Links: map[string]Candidate{}}, fmt.Errorf("wan: %s: %w", path, err)
	}
	if f.Links == nil {
		f.Links = map[string]Candidate{}
	}
	return f, nil
}

// SaveCandidates replaces the file atomically.
func SaveCandidates(path string, f CandidatesFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return lan.WriteAtomic(path, append(b, '\n'), 0o644)
}

// Link is one interface as the scanner sees it.
type Link struct {
	Name           string
	MAC            string
	Up             bool // administratively up; a down link has no carrier to read
	Carrier        bool
	CarrierChanges int64
	// HasIPv4 is the interface already holding an address somebody gave it
	// outside netplan.
	HasIPv4 bool
	// Hardware is the kernel naming a device behind the interface
	// (/sys/class/net/<if>/device): a NIC, a virtio NIC, a USB modem. veth,
	// macvlan, bridges, tunnels and dummies have none.
	Hardware bool
}

// virtualPrefixes name interfaces that are never a WAN link of their own,
// checked as well as Hardware: a belt for the few virtual drivers that do
// name a device.
var virtualPrefixes = []string{
	"lo", "wg", "omp", "tun", "tap", "docker", "br", "veth", "virbr",
	"tailscale", "ppp", "dummy", "gre", "sit", "ip6tnl", "bond", "vlan",
}

// Unclaimed says whether an interface is nobody's yet, and if not, why. lans
// are the LAN tab's interfaces; configured maps interfaces that some other
// netplan file configures to that file - an existing WAN link, set up by
// hand, is one of those. A link this package added is claimed by its record,
// not by this function.
func Unclaimed(l Link, lans map[string]bool, configured map[string]string) (bool, string) {
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(l.Name, p) {
			return false, "virtual interface"
		}
	}
	if !l.Hardware {
		return false, "not a hardware interface"
	}
	if l.MAC == "" {
		return false, "no hardware address"
	}
	if lans[l.Name] {
		return false, "a LAN"
	}
	if file, ok := configured[l.Name]; ok {
		return false, "configured in " + file
	}
	if l.HasIPv4 {
		// Configured by hand, or by something other than netplan. Probing it
		// would move it into a namespace, and that strips its addresses.
		return false, "already has an address"
	}
	return true, ""
}

// Action is what the scanner should do with a link now.
type Action int

const (
	Nothing Action = iota
	Probe
	RecordNoLink
)

// Decide chooses what to do with an unclaimed link, given what is already
// known about it. It never probes a link with no carrier, never probes one
// twice at once, and never probes one the owner has already been asked about
// unless it has been replugged since.
func Decide(c *Candidate, l Link, nowUnix int64) Action {
	if c == nil {
		if !l.Carrier {
			return RecordNoLink
		}
		return Probe
	}
	switch c.State {
	case Probing, Adding, Added, Ready:
		return Nothing
	}
	if !l.Carrier {
		// A link that loses carrier keeps what was learned about it: a dish
		// rebooting is not a link that has gone away.
		return Nothing
	}
	replugged := l.CarrierChanges != c.CarrierChanges
	switch c.State {
	case NoLink:
		return Probe
	case NoDHCP, Ignored, AddFailed:
		// Nothing more is learned by asking again; a replug is new evidence.
		// A failed add can also be retried from the page.
		if replugged {
			return Probe
		}
	case NoInternet, ProbeError:
		if replugged || nowUnix >= c.RetryUnix {
			return Probe
		}
	}
	return Nothing
}

// ProbeResult is omp-wan-probe's output.
type ProbeResult struct {
	Result   string
	IP       string
	CIDR     string
	Gateway  string
	DNS      string
	HTTPCode string
	Detail   string
	IPInfo   string
}

// ParseProbe reads omp-wan-probe's key=value lines. A missing result is an
// error result: a probe that did not finish did not find anything.
func ParseProbe(out string) ProbeResult {
	var r ProbeResult
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if !ok {
			continue
		}
		switch k {
		case "result":
			r.Result = v
		case "ip":
			r.IP = v
		case "cidr":
			r.CIDR = v
		case "gateway":
			r.Gateway = v
		case "dns":
			r.DNS = v
		case "http_code":
			r.HTTPCode = v
		case "detail":
			r.Detail = v
		case "ipinfo":
			r.IPInfo = v
		}
	}
	switch r.Result {
	case "internet", "no-internet", "no-dhcp", "error":
	default:
		if r.Detail == "" {
			r.Detail = "the probe did not report a result"
		}
		r.Result = "error"
	}
	return r
}

// Apply records a probe's result on a candidate.
func (c *Candidate) Apply(r ProbeResult, carrierChanges, nowUnix int64) {
	c.ProbedUnix = nowUnix
	c.CarrierChanges = carrierChanges
	c.IP, c.Gateway, c.Detail, c.ISP = r.IP, r.Gateway, r.Detail, nil
	c.RetryUnix = 0
	switch r.Result {
	case "internet":
		c.State = Ready
		if isp, err := ParseIPInfo([]byte(r.IPInfo), nowUnix); err == nil {
			c.ISP = &isp
		}
	case "no-internet":
		c.State = NoInternet
		c.RetryUnix = nowUnix + RetrySeconds
	case "no-dhcp":
		c.State = NoDHCP
	default:
		c.State = ProbeError
		c.RetryUnix = nowUnix + RetrySeconds
	}
}
