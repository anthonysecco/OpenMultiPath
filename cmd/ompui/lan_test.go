package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/lan"
)

// testLAN is a manager whose files live in a temp directory and whose
// commands are recorded instead of run.
type testLAN struct {
	*lanManager
	cmdMu sync.Mutex
	cmds  []string
	fail  map[string]bool // a command prefix that fails
}

func newTestLAN(t *testing.T) *testLAN {
	dir := t.TempDir()
	m := newLANManager(filepath.Join(dir, "etc", "lan.json"), filepath.Join(dir, "state"))
	m.netplanDir = filepath.Join(dir, "netplan")
	m.netplanPath = filepath.Join(m.netplanDir, "40-omp-lan.yaml")
	m.dnsmasqPath = filepath.Join(dir, "dnsmasq.d", "omp-lan.conf")
	m.envPath = filepath.Join(dir, "default", "openmultipath")
	m.leasePath = filepath.Join(dir, "leases")
	os.MkdirAll(m.netplanDir, 0o755)
	os.MkdirAll(m.stateDir, 0o755)
	tl := &testLAN{lanManager: m, fail: map[string]bool{}}
	m.run = func(env []string, name string, args ...string) ([]byte, error) {
		line := strings.TrimSpace(strings.Join(env, " ") + " " + name + " " + strings.Join(args, " "))
		tl.cmdMu.Lock()
		tl.cmds = append(tl.cmds, line)
		tl.cmdMu.Unlock()
		for prefix := range tl.fail {
			if strings.HasPrefix(name+" "+strings.Join(args, " "), prefix) {
				return []byte("simulated failure"), errors.New("exit 1")
			}
		}
		return nil, nil
	}
	return tl
}

func (tl *testLAN) ran(sub string) bool {
	tl.cmdMu.Lock()
	defer tl.cmdMu.Unlock()
	for _, c := range tl.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func lanFile(lan2 string) lan.File {
	return lan.File{Segments: []lan.Segment{
		{Interface: "eth0", Name: "LAN 1", Address: "10.0.0.1/24"},
		{Interface: "ens19", Name: "LAN 2", Address: lan2, DHCP: lan.DHCP{Enabled: true}},
	}}
}

func TestFirstApplyWritesEverythingWithoutProbation(t *testing.T) {
	tl := newTestLAN(t)
	probation, err := tl.apply(lanFile("10.0.1.1/24"))
	if err != nil || probation {
		t.Fatalf("first apply: probation %v, err %v", probation, err)
	}
	np, _ := os.ReadFile(tl.netplanPath)
	dm, _ := os.ReadFile(tl.dnsmasqPath)
	env, _ := os.ReadFile(tl.envPath)
	if !strings.Contains(string(np), `- "10.0.1.1/24"`) || !strings.Contains(string(dm), "dhcp-range=set:lan_ens19") ||
		!strings.Contains(string(env), `OMP_LAN="10.0.0.0/24 10.0.1.0/24"`) {
		t.Errorf("rendered files wrong:\n%s\n%s\n%s", np, dm, env)
	}
	if !tl.ran("netplan generate") || !tl.ran("networkctl reload") {
		t.Errorf("netplan/networkd not applied: %v", tl.cmds)
	}
}

// An address change stays only if confirmed. Unconfirmed, it is undone by
// itself, files and all.
func TestAddressChangeRevertsUnlessConfirmed(t *testing.T) {
	tl := newTestLAN(t)
	if _, err := tl.apply(lanFile("10.0.1.1/24")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(tl.netplanPath)

	probation, err := tl.apply(lanFile("192.168.50.1/24"))
	if err != nil || !probation {
		t.Fatalf("address change: probation %v, err %v", probation, err)
	}
	if _, err := os.Stat(tl.markerPath()); err != nil {
		t.Error("no probation marker on disk; a restart would forget to revert")
	}
	// Both the old and the new LAN can reach the page while it is pending.
	if !tl.allowedLocal(netip.MustParseAddr("10.0.1.1")) || !tl.allowedLocal(netip.MustParseAddr("192.168.50.1")) {
		t.Error("the page is not reachable from both sides of a pending change")
	}

	// Pretend the deadline has passed and let the timer fire.
	tl.mu.Lock()
	tl.startTimerLocked(time.Now().Add(-time.Second))
	tl.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for {
		tl.mu.Lock()
		done := tl.deadline.IsZero()
		tl.mu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	after, _ := os.ReadFile(tl.netplanPath)
	if string(after) != string(before) {
		t.Errorf("netplan not restored:\n%s", after)
	}
	cur, _ := tl.current()
	if cur == nil || cur.Segments[1].Address != "10.0.1.1/24" {
		t.Errorf("settings not restored: %+v", cur)
	}
	if _, err := os.Stat(tl.markerPath()); err == nil {
		t.Error("marker left behind after the revert")
	}
	if tl.allowedLocal(netip.MustParseAddr("192.168.50.1")) {
		t.Error("the abandoned address is still allowed")
	}
}

func TestConfirmKeepsTheChange(t *testing.T) {
	tl := newTestLAN(t)
	tl.apply(lanFile("10.0.1.1/24"))
	tl.apply(lanFile("10.0.2.1/24"))
	if !tl.confirm() {
		t.Fatal("nothing to confirm")
	}
	cur, _ := tl.current()
	if cur.Segments[1].Address != "10.0.2.1/24" {
		t.Errorf("confirmed change lost: %+v", cur.Segments[1])
	}
	if _, err := os.Stat(tl.backupPath()); err == nil {
		t.Error("backup kept after confirmation")
	}
	if tl.revertNow() == nil {
		t.Error("revert allowed with nothing pending")
	}
}

// A second edit while the first is pending reverts to the original, not to
// the intermediate network nobody confirmed.
func TestRevertDuringProbationGoesBackToTheConfirmedLAN(t *testing.T) {
	tl := newTestLAN(t)
	tl.apply(lanFile("10.0.1.1/24"))
	tl.apply(lanFile("10.0.2.1/24"))
	if p, err := tl.apply(lanFile("10.0.3.1/24")); err != nil || !p {
		t.Fatalf("second change: %v %v", p, err)
	}
	if err := tl.revertNow(); err != nil {
		t.Fatal(err)
	}
	cur, _ := tl.current()
	if cur.Segments[1].Address != "10.0.1.1/24" {
		t.Errorf("reverted to %s, want the confirmed 10.0.1.1/24", cur.Segments[1].Address)
	}
}

// A probation left running by an ompui that died is picked up at start, and
// one already past its deadline is reverted at once.
func TestResumeRevertsAnExpiredProbation(t *testing.T) {
	tl := newTestLAN(t)
	tl.apply(lanFile("10.0.1.1/24"))
	tl.apply(lanFile("10.0.9.1/24"))
	tl.mu.Lock()
	tl.timer.Stop()
	tl.mu.Unlock()
	os.WriteFile(tl.markerPath(), []byte(`{"deadline_unix": 1}`), 0o644)

	fresh := newLANManager(tl.path, tl.stateDir)
	fresh.netplanDir, fresh.netplanPath, fresh.dnsmasqPath, fresh.envPath = tl.netplanDir, tl.netplanPath, tl.dnsmasqPath, tl.envPath
	fresh.run = tl.run
	fresh.resume()
	cur, _ := fresh.current()
	if cur.Segments[1].Address != "10.0.1.1/24" {
		t.Errorf("after resume: %s, want the reverted 10.0.1.1/24", cur.Segments[1].Address)
	}
}

func TestDHCPOnlyChangeNeedsNoProbation(t *testing.T) {
	tl := newTestLAN(t)
	tl.apply(lanFile("10.0.1.1/24"))
	f := lanFile("10.0.1.1/24")
	f.Segments[1].DHCP.LeaseMinutes = 60
	f.Segments[0].DHCP.Enabled = true
	if p, err := tl.apply(f); err != nil || p {
		t.Errorf("DHCP change: probation %v err %v", p, err)
	}
}

func TestInvalidOrConflictingSettingsChangeNothing(t *testing.T) {
	tl := newTestLAN(t)
	tl.apply(lanFile("10.0.1.1/24"))
	before, _ := os.ReadFile(tl.path)

	var verr validationError
	if _, err := tl.apply(lanFile("10.0.0.2/24")); !errors.As(err, &verr) {
		t.Errorf("overlapping LANs accepted: %v", err)
	}
	os.WriteFile(filepath.Join(tl.netplanDir, "50-cloud-init.yaml"),
		[]byte("network:\n  ethernets:\n    eth0:\n      addresses: [10.0.0.1/24]\n"), 0o600)
	if _, err := tl.apply(lanFile("10.0.1.1/24")); !errors.As(err, &verr) || !strings.Contains(err.Error(), "50-cloud-init.yaml") {
		t.Errorf("a second netplan file for eth0 was not refused: %v", err)
	}
	os.Remove(filepath.Join(tl.netplanDir, "50-cloud-init.yaml"))

	tl.fail["netplan generate"] = true
	if _, err := tl.apply(lanFile("10.0.5.1/24")); err == nil {
		t.Error("netplan failure not reported")
	}
	after, _ := os.ReadFile(tl.path)
	if string(after) != string(before) {
		t.Errorf("a failed apply left its settings behind:\n%s", after)
	}
}

// The PEP's interception follows the subnets, but only if it is on.
func TestPEPRulesFollowTheSubnets(t *testing.T) {
	tl := newTestLAN(t)
	tl.apply(lanFile("10.0.1.1/24"))
	tl.cmds = nil
	tl.apply(lanFile("10.0.7.1/24"))
	if !tl.ran("OMP_LAN=10.0.0.0/24 10.0.1.0/24 omp-pep-rules off") || !tl.ran("OMP_LAN=10.0.0.0/24 10.0.7.0/24 omp-pep-rules on") {
		t.Errorf("PEP rules not moved: %v", tl.cmds)
	}

	tl2 := newTestLAN(t)
	tl2.fail["systemctl is-active --quiet omp-pep-rules"] = true
	tl2.apply(lanFile("10.0.1.1/24"))
	if tl2.ran("omp-pep-rules on") {
		t.Error("interception turned on although it was off")
	}
}

func TestGuardWithoutSettingsAllowsEverything(t *testing.T) {
	tl := newTestLAN(t)
	if !tl.allowedLocal(netip.MustParseAddr("192.168.225.3")) {
		t.Error("an unconfigured LAN locked the page out")
	}
	tl.apply(lanFile("10.0.1.1/24"))
	if tl.allowedLocal(netip.MustParseAddr("192.168.225.3")) {
		t.Error("a WAN address is allowed once the LAN is configured")
	}
	if !tl.allowedLocal(netip.MustParseAddr("127.0.0.1")) || !tl.allowedLocal(netip.MustParseAddr("10.0.0.1")) {
		t.Error("loopback or LAN refused")
	}
}

// A LAN set up by hand or by cloud-init is proposed as a segment; a WAN link,
// and anything without an address, is not.
func TestProposalTakesAddressedNonWANInterfaces(t *testing.T) {
	f := proposal([]liveIface{
		{Name: "enp1s0", Role: "unmanaged", Reason: "configured in 60-wan-i226.yaml"},
		{Name: "enp2s0", Role: "wan", Addresses: []string{"192.168.225.3/22"}},
		{Name: "ens19", Role: "unmanaged", MAC: "bc:24:11:d1:6d:cb", Addresses: []string{"10.0.1.1/24"}},
		{Name: "eth0", Role: "unmanaged", MAC: "02:ed:23:21:63:ab", Addresses: []string{"10.0.0.1/24"}},
		{Name: "ens20", Role: "unassigned"},
	})
	if len(f.Segments) != 2 || f.Segments[0].Interface != "ens19" || f.Segments[1].Address != "10.0.0.1/24" {
		t.Fatalf("proposal = %+v", f.Segments)
	}
	if f.Segments[0].DHCP.Enabled {
		t.Error("a proposal switched DHCP on; it must never start a DHCP server nobody asked for")
	}
	if errs := f.Validate(); len(errs) > 0 {
		t.Errorf("the proposal does not validate: %v", errs)
	}
}

func TestChangedInterfaces(t *testing.T) {
	a, b := lanFile("10.0.1.1/24"), lanFile("10.0.1.1/24")
	b.Segments[1].DHCP.LeaseMinutes = 5
	if got := changedInterfaces(&a, &b); len(got) != 0 {
		t.Errorf("a DHCP-only change reconfigures %v", got)
	}
	b.Segments[1].Address = "10.0.2.1/24"
	b.Segments = append(b.Segments, lan.Segment{Interface: "ens20", Address: "10.0.3.1/24"})
	if got := strings.Join(changedInterfaces(&a, &b), ","); got != "ens19,ens20" {
		t.Errorf("changed = %s, want ens19,ens20", got)
	}
	if got := strings.Join(changedInterfaces(nil, &a), ","); got != "ens19,eth0" {
		t.Errorf("from nothing = %s", got)
	}
	if got := strings.Join(changedInterfaces(&a, nil), ","); got != "ens19,eth0" {
		t.Errorf("to nothing = %s", got)
	}
}
