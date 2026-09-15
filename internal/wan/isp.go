// Package wan is the vehicle's WAN side as it changes (D-070, D-071): which
// links are new, what a probe found on them, who their ISP is, and how a new
// link is turned into a WireGuard transport and a path.
//
// Like internal/lan it does no networking of its own. Probing is
// deploy/omp-wan-probe's job, carrier and addresses are the kernel's, and a
// provisioned link is netplan's, networkd's and wg-quick's. What lives here is
// the reasoning, as pure functions that can be tested on a bench.
package wan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/anthonysecco/OpenMultiPath/internal/lan"
)

// DefaultISPPath is where each link's ISP is kept, keyed by the name ompd
// knows the path by: its WireGuard transport, e.g. wg1.
const DefaultISPPath = "/var/lib/openmultipath/isp.json"

// ISP is who a link belongs to, as ipinfo.io saw it from the link's own
// egress.
type ISP struct {
	// Name is what to call the link: a short, human ISP name.
	Name     string `json:"name"`
	Org      string `json:"org"` // ipinfo's own field, e.g. "AS14593 Space Exploration Technologies Corporation"
	ASN      int    `json:"asn"`
	PublicIP string `json:"public_ip"`
	City     string `json:"city,omitempty"`
	Region   string `json:"region,omitempty"`
	Country  string `json:"country,omitempty"`
	// CheckedUnix is when this was looked up.
	CheckedUnix int64 `json:"checked_unix"`
}

// brands names the carriers a vehicle is most likely to meet by the name
// people use, where the registry name is a holding company. Anything else
// gets its registry name, tidied.
var brands = map[int]string{
	14593: "Starlink",
	7018:  "AT&T",
	20057: "AT&T",
	21928: "T-Mobile",
	6167:  "Verizon",
	22394: "Verizon",
	701:   "Verizon",
	7922:  "Comcast",
	20115: "Spectrum",
	11427: "Spectrum",
	10796: "Spectrum",
	33363: "Spectrum",
	20001: "Spectrum",
	22773: "Cox",
	209:   "CenturyLink",
	6939:  "Hurricane Electric",
	13335: "Cloudflare",
	36352: "ColoCrossing",
	852:   "Telus",
	812:   "Rogers",
	577:   "Bell Canada",
}

var (
	asPrefix = regexp.MustCompile(`^AS(\d+)\s+`)
	suffixes = regexp.MustCompile(`(?i)[,\s]+(llc|l\.l\.c\.|inc\.?|incorporated|corporation|corp\.?|co\.?|company|ltd\.?|limited|gmbh|s\.a\.|plc|lp|l\.p\.)$`)
)

// ParseIPInfo reads ipinfo.io's JSON.
func ParseIPInfo(data []byte, nowUnix int64) (ISP, error) {
	var raw struct {
		IP      string `json:"ip"`
		Org     string `json:"org"`
		City    string `json:"city"`
		Region  string `json:"region"`
		Country string `json:"country"`
		Bogon   bool   `json:"bogon"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return ISP{}, fmt.Errorf("wan: ipinfo: %w", err)
	}
	if raw.IP == "" {
		return ISP{}, errors.New("wan: ipinfo answered without an address")
	}
	isp := ISP{Org: raw.Org, PublicIP: raw.IP, City: raw.City, Region: raw.Region, Country: raw.Country, CheckedUnix: nowUnix}
	isp.ASN, isp.Name = NameOrg(raw.Org)
	return isp, nil
}

// NameOrg turns ipinfo's org field into an AS number and a short name.
func NameOrg(org string) (asn int, name string) {
	org = strings.TrimSpace(org)
	if m := asPrefix.FindStringSubmatch(org); m != nil {
		asn, _ = strconv.Atoi(m[1])
		org = strings.TrimSpace(org[len(m[0]):])
	}
	if b, ok := brands[asn]; ok {
		return asn, b
	}
	for {
		trimmed := strings.TrimSpace(suffixes.ReplaceAllString(org, ""))
		if trimmed == org || trimmed == "" {
			break
		}
		org = trimmed
	}
	return asn, org
}

// ISPFile is every link's ISP, keyed by transport name.
type ISPFile struct {
	Links map[string]ISP `json:"links"`
}

// LoadISPs reads the file. A missing file is an empty one.
func LoadISPs(path string) (ISPFile, error) {
	f := ISPFile{Links: map[string]ISP{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return ISPFile{Links: map[string]ISP{}}, fmt.Errorf("wan: %s: %w", path, err)
	}
	if f.Links == nil {
		f.Links = map[string]ISP{}
	}
	return f, nil
}

// SaveISPs replaces the file atomically.
func SaveISPs(path string, f ISPFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return lan.WriteAtomic(path, append(b, '\n'), 0o644)
}
