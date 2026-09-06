// Package deploy holds no Go code. These tests exercise the shell that
// has to keep working when the Go code is the broken thing: the
// watchdog, the fallback, and the rollback.
//
// scope-v1.md asks for exactly this - "test the rollback before needing
// it" - and it is not a thing that can be tested by waiting for it to
// happen. A canyon, a wedged daemon and a bad upgrade are all conditions
// nobody can produce on a bench, so every external command the scripts
// touch is replaced with a fake that records what it was asked to do and
// can be told to fail.
package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// box is a fake vehicle: a temporary root, a PATH of fake commands, and
// switches for the conditions the scripts are supposed to react to.
type box struct {
	t    *testing.T
	root string
	bin  string // fake commands, first on PATH
	run  string // /run/openmultipath
	sbin string // where the scripts are installed
	log  string // every fake command's invocation, in order

	// noFallback models the responder, which has nowhere to route around
	// to and must never touch the routing.
	noFallback bool

	// wgConfDir stands in for /etc/wireguard. Pointing it at an empty
	// directory models the D-020 shape, where the tunnel is a TUN the
	// daemon owns and wg-quick has no config for.
	wgConfDir string
}

func newBox(t *testing.T) *box {
	t.Helper()
	root := t.TempDir()
	b := &box{
		t:    t,
		root: root,
		bin:  filepath.Join(root, "fakebin"),
		run:  filepath.Join(root, "run"),
		sbin: filepath.Join(root, "sbin"),
		log:  filepath.Join(root, "calls.log"),
	}
	for _, d := range []string{b.bin, b.run, b.sbin, filepath.Join(root, "usrbin"), filepath.Join(root, "lib")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// The scripts under test, copied so a test can never edit the repo.
	for _, s := range []string{"omp-watchdog", "omp-fallback", "omp-deploy"} {
		src, err := os.ReadFile(s)
		if err != nil {
			t.Fatalf("reading %s: %v", s, err)
		}
		if err := os.WriteFile(filepath.Join(b.sbin, s), src, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// By default wg-quick owns the tunnel, which is the production shape.
	// Tests modelling D-020 point wgConfDir at an empty directory instead.
	b.wgConfDir = filepath.Join(root, "wireguard")
	if err := os.MkdirAll(b.wgConfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.wgConfDir, "wg0.conf"), []byte("[Interface]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	b.fake("ping", `[ -e "$FAKE/ping_ok" ] && exit 0 || exit 1`)
	b.fake("wg-quick", `exit 0`)
	b.fake("nft", `exit 0`)
	b.fake("systemctl", `exit 0`)
	b.fake("logger", `exit 0`)
	b.fake("ip", `
case "$*" in
  *"link show"*)
     dev=${!#}
     if [ -e "$FAKE/down_$dev" ]; then exit 1; fi
     if [ -e "$FAKE/exists_$dev" ]; then echo "9: $dev: <BROADCAST> mtu 1500 state UP"; exit 0; fi
     exit 1 ;;
  *"route show default dev "*)
     dev=${!#}
     if [ -e "$FAKE/gw_$dev" ]; then echo "default via $(cat "$FAKE/gw_$dev") dev $dev proto dhcp"; fi
     exit 0 ;;
  *"route show default"*)
     cat "$FAKE/defaults" 2>/dev/null
     exit 0 ;;
  *) exit 0 ;;
esac`)
	return b
}

// fake installs a command that records its invocation and then runs body.
func (b *box) fake(name, body string) {
	b.t.Helper()
	script := fmt.Sprintf("#!/bin/bash\necho \"%s $*\" >> \"$CALLS\"\n%s\n", name, body)
	if err := os.WriteFile(filepath.Join(b.bin, name), []byte(script), 0o755); err != nil {
		b.t.Fatal(err)
	}
}

// link declares an interface that is up, with a default route via gw.
func (b *box) link(dev, gw string) {
	b.t.Helper()
	b.touch("exists_" + dev)
	b.write("gw_"+dev, gw)
	f, err := os.OpenFile(filepath.Join(b.root, "defaults"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		b.t.Fatal(err)
	}
	defer f.Close()
	fmt.Fprintf(f, "default via %s dev %s proto dhcp\n", gw, dev)
}

func (b *box) touch(name string) {
	b.t.Helper()
	if err := os.WriteFile(filepath.Join(b.root, name), nil, 0o644); err != nil {
		b.t.Fatal(err)
	}
}

func (b *box) write(name, content string) {
	b.t.Helper()
	if err := os.WriteFile(filepath.Join(b.root, name), []byte(content), 0o644); err != nil {
		b.t.Fatal(err)
	}
}

func (b *box) remove(name string) {
	b.t.Helper()
	os.Remove(filepath.Join(b.root, name))
}

// stateFile writes a scheduler snapshot with the given ranking, aged by
// the given amount so staleness can be tested.
func (b *box) stateFile(age time.Duration, ranking string, paths ...string) {
	b.t.Helper()
	var ps []string
	for i, name := range paths {
		ps = append(ps, fmt.Sprintf(`{"id":%d,"name":%q}`, i, name))
	}
	doc := fmt.Sprintf(`{"paths":[%s],"scheduler":{"ranking":[%s]}}`,
		strings.Join(ps, ","), ranking)
	p := filepath.Join(b.root, "state.json")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		b.t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		b.t.Fatal(err)
	}
}

// healthy sets the box to a working tunnel, or a broken one.
func (b *box) healthy(ok bool) {
	b.t.Helper()
	b.stateFile(0, "0", "enp2s0")
	if ok {
		b.touch("ping_ok")
		b.touch("exists_wg0")
	} else {
		b.remove("ping_ok")
	}
}

func (b *box) env() []string {
	return append(os.Environ(),
		"PATH="+b.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE="+b.root,
		"CALLS="+b.log,
		"OMP_RUN="+b.run,
		"OMP_STATE="+filepath.Join(b.root, "state.json"),
		"OMP_BIN="+filepath.Join(b.root, "usrbin"),
		"OMP_FALLBACK_CMD="+filepath.Join(b.sbin, "omp-fallback"),
		"OMP_FALLBACK_ORDER="+filepath.Join(b.root, "fallback.order"),
		"OMP_FAIL_CHECKS=4",
		"OMP_OK_CHECKS=12",
		"OMP_FALLBACK_ENABLED="+map[bool]string{true: "0", false: "1"}[b.noFallback],
		"OMP_WG_CONF_DIR="+b.wgConfDir,
	)
}

// run executes one of the scripts and returns its combined output.
func (b *box) run_(script string, args ...string) string {
	b.t.Helper()
	cmd := exec.Command(filepath.Join(b.sbin, script), args...)
	cmd.Env = b.env()
	cmd.Dir = b.root
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// tick runs the watchdog n times, as the timer would.
func (b *box) tick(n int) string {
	b.t.Helper()
	var out string
	for i := 0; i < n; i++ {
		out += b.run_("omp-watchdog")
	}
	return out
}

func (b *box) inFallback() bool {
	_, err := os.Stat(filepath.Join(b.run, "fallback"))
	return err == nil
}

func (b *box) calls() string {
	out, _ := os.ReadFile(b.log)
	return string(out)
}

// A working tunnel is left alone. This is the case that runs for months
// at a time, and the watchdog doing anything at all here would be a bug
// with a very long tail.
func TestHealthyTunnelIsLeftAlone(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")
	b.healthy(true)

	b.tick(20)

	if b.inFallback() {
		t.Error("watchdog fell back with a healthy tunnel")
	}
	if strings.Contains(b.calls(), "wg-quick down") {
		t.Error("watchdog took the tunnel down with nothing wrong")
	}
}

// A canyon is not a fault. scope-v1.md is explicit that intermittent
// connectivity is the normal case, so a failure has to be sustained
// before the tunnel is torn down for it.
func TestTransientFailureDoesNotFallBack(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")
	b.healthy(true)
	b.tick(2)

	b.healthy(false)
	b.tick(3) // one short of OMP_FAIL_CHECKS

	if b.inFallback() {
		t.Fatal("fell back after 3 failing checks, want 4")
	}

	b.healthy(true)
	b.tick(1)
	b.healthy(false)
	b.tick(3)

	if b.inFallback() {
		t.Error("a moment of health did not reset the failure count")
	}
}

// Sustained failure is what fallback is for.
func TestSustainedFailureFallsBack(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")
	b.healthy(false)

	b.tick(4)

	if !b.inFallback() {
		t.Fatal("did not fall back after 4 sustained failures")
	}
	calls := b.calls()
	if !strings.Contains(calls, "route replace default via 192.168.225.1 dev enp2s0") {
		t.Errorf("fallback did not install a direct default route; calls were:\n%s", calls)
	}
	if !strings.Contains(calls, "rule add from all lookup 2500 priority 2000") {
		t.Errorf("fallback did not take over the tunnel's catch-all rule; calls were:\n%s", calls)
	}
}

// The trap this design exists to avoid. Fallback must leave the tunnel
// interface up, because the watchdog decides the tunnel has recovered by
// probing it - and a fallback that removes the interface removes the only
// evidence that could ever end the fallback. The vehicle would egress
// directly and stay that way until somebody drove out to it.
func TestFallbackLeavesTheTunnelUpSoItCanRecover(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")
	b.healthy(false)
	b.tick(4)

	if !b.inFallback() {
		t.Fatal("setup: expected to be in fallback")
	}
	if strings.Contains(b.calls(), "wg-quick down") {
		t.Fatal("entering fallback took the tunnel down; recovery could never be detected")
	}

	// And recovery is in fact detectable and acted on.
	b.healthy(true)
	b.tick(12)
	if b.inFallback() {
		t.Error("could not leave fallback after the tunnel came back")
	}
}

// Coming back out takes longer than going in. Every transition breaks
// NAT state and kills in-flight sessions, so flapping between tunnel and
// fallback is worse than sitting in either (D-011).
func TestLeavingFallbackTakesLongerThanEntering(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")
	b.healthy(false)
	b.tick(4)
	if !b.inFallback() {
		t.Fatal("setup: expected to be in fallback")
	}

	b.healthy(true)
	b.tick(11) // one short of OMP_OK_CHECKS
	if !b.inFallback() {
		t.Fatal("left fallback after 11 good checks, want 12")
	}

	b.tick(1)
	if b.inFallback() {
		t.Error("never left fallback after the tunnel came back and stayed")
	}
	if !strings.Contains(b.calls(), "wg-quick up wg0") {
		t.Error("leaving fallback did not bring the tunnel back up")
	}
}

// The scheduler is the thing that died, so it cannot be asked which link
// is best - it writes its ranking down continuously for exactly this
// moment (architecture.md).
func TestFallbackFollowsTheSchedulersRanking(t *testing.T) {
	b := newBox(t)
	b.link("enp1s0", "100.64.0.1")
	b.link("enp2s0", "192.168.225.1")

	// Scheduler ranked path 1 (enp2s0) first.
	b.stateFile(0, "1,0", "enp1s0", "enp2s0")

	if got := strings.TrimSpace(b.run_("omp-fallback", "links")); got != "enp2s0 192.168.225.1" {
		t.Errorf("fallback picked %q, want the scheduler's first choice enp2s0", got)
	}

	// And the other way round, to be sure it is reading the ranking and
	// not just finding the same answer twice.
	b.stateFile(0, "0,1", "enp1s0", "enp2s0")
	if got := strings.TrimSpace(b.run_("omp-fallback", "links")); got != "enp1s0 100.64.0.1" {
		t.Errorf("fallback picked %q, want enp1s0", got)
	}
}

// A stale ranking is not evidence. The daemon may have been dead for
// hours, and the link it liked then may be the one that died.
func TestStaleRankingFallsBackToTheStaticOrder(t *testing.T) {
	b := newBox(t)
	b.link("enp1s0", "100.64.0.1")
	b.link("enp2s0", "192.168.225.1")
	b.write("fallback.order", "# operator's order\nenp1s0\nenp2s0\n")

	// Ranking says enp2s0, but it is hours old.
	b.stateFile(6*time.Hour, "1,0", "enp1s0", "enp2s0")

	if got := strings.TrimSpace(b.run_("omp-fallback", "links")); got != "enp1s0 100.64.0.1" {
		t.Errorf("picked %q from a six hour old ranking, want the static order's enp1s0", got)
	}
}

// Never leave the choice undefined. With no ranking and no configured
// order, whatever has a default route is still better than nothing.
func TestNoRankingAndNoOrderStillPicksALink(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")

	if got := strings.TrimSpace(b.run_("omp-fallback", "links")); got != "enp2s0 192.168.225.1" {
		t.Errorf("picked %q with nothing to go on, want enp2s0 from the routing table", got)
	}
}

// A ranking entry for a modem that has since dropped off is a reason to
// take the next one, not to give up.
func TestFallbackSkipsARankedLinkThatIsDown(t *testing.T) {
	b := newBox(t)
	b.link("enp1s0", "100.64.0.1")
	b.link("enp2s0", "192.168.225.1")
	b.stateFile(0, "0,1", "enp1s0", "enp2s0")
	b.touch("down_enp1s0")

	if got := strings.TrimSpace(b.run_("omp-fallback", "links")); got != "enp2s0 192.168.225.1" {
		t.Errorf("picked %q with the top-ranked link down, want enp2s0", got)
	}
}

// The rollback, which scope-v1.md calls the highest-value reliability
// investment in the project. A version that never brings the tunnel back
// is undone by the vehicle itself.
func TestBadUpgradeIsRolledBack(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")
	usr := filepath.Join(b.root, "usrbin")
	os.WriteFile(filepath.Join(usr, "ompd"), []byte("BAD"), 0o755)
	os.WriteFile(filepath.Join(usr, "ompd.prev"), []byte("GOOD"), 0o755)
	// Deployed a moment ago, with a window that has not expired.
	b.deployedAt(time.Now().Add(5 * time.Minute))

	b.healthy(false)
	b.tick(4)

	got, _ := os.ReadFile(filepath.Join(usr, "ompd"))
	if string(got) != "GOOD" {
		t.Fatalf("running binary is %q after a failed probation, want the previous one restored", got)
	}
	calls := b.calls()
	if !strings.Contains(calls, "systemctl restart ompd") {
		t.Error("rolled back without restarting the daemon")
	}
	// A bad build crash-loops, which latches the unit into
	// start-limit-hit, and systemd then refuses `restart` outright.
	// Without clearing that first, the rollback restores the right
	// binary and the daemon still never comes up - which is to say it
	// fails in exactly the case it exists for.
	if !strings.Contains(calls, "systemctl reset-failed ompd") {
		t.Error("rolled back without clearing systemd's start limit; restart would be refused")
	}
	if strings.Index(calls, "reset-failed ompd") > strings.Index(calls, "restart ompd") {
		t.Error("cleared the start limit after restarting rather than before")
	}
	// The rollback is the cheaper fix and comes first: it restores the
	// tunnel rather than a workaround.
	if b.inFallback() {
		t.Error("fell back instead of rolling back a version that was still on probation")
	}
	// The failed binary is kept: whatever it did wrong is worth reading,
	// and out here this is the only copy of it.
	if _, err := os.Stat(filepath.Join(usr, "ompd.failed")); err != nil {
		t.Error("the failed binary was discarded rather than kept for diagnosis")
	}
}

// A version that holds a working tunnel for the whole window is
// accepted, and a later outage is then treated as a fault rather than as
// a bad upgrade.
func TestGoodUpgradeIsPromoted(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")
	usr := filepath.Join(b.root, "usrbin")
	os.WriteFile(filepath.Join(usr, "ompd"), []byte("NEW"), 0o755)
	os.WriteFile(filepath.Join(usr, "ompd.prev"), []byte("OLD"), 0o755)
	b.deployedAt(time.Now().Add(-time.Second)) // window already elapsed

	b.healthy(true)
	b.tick(1)

	if _, err := os.Stat(filepath.Join(b.run, "probation")); err == nil {
		t.Fatal("still on probation after a healthy check past the deadline")
	}

	// And now a real outage must fall back rather than roll back.
	b.healthy(false)
	b.tick(4)
	if !b.inFallback() {
		t.Error("a later outage did not fall back")
	}
	if got, _ := os.ReadFile(filepath.Join(usr, "ompd")); string(got) != "NEW" {
		t.Error("a later outage rolled back a version that had already been confirmed")
	}
}

// Health during the window is not confirmation. A binary that works for
// one lucky minute and then wedges must still be undoable.
func TestProbationIsNotConfirmedEarly(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")
	usr := filepath.Join(b.root, "usrbin")
	os.WriteFile(filepath.Join(usr, "ompd"), []byte("NEW"), 0o755)
	os.WriteFile(filepath.Join(usr, "ompd.prev"), []byte("OLD"), 0o755)
	b.deployedAt(time.Now().Add(10 * time.Minute))

	b.healthy(true)
	b.tick(30)

	if _, err := os.Stat(filepath.Join(b.run, "probation")); err != nil {
		t.Fatal("probation was confirmed before its deadline")
	}

	b.healthy(false)
	b.tick(4)
	if got, _ := os.ReadFile(filepath.Join(usr, "ompd")); string(got) != "OLD" {
		t.Error("a version that wedged during probation was not rolled back")
	}
}

// Principle 5 applied to the watchdog itself. With no previous version
// kept there is nothing to roll back to, and the right answer is to fall
// back and keep the vehicle connected rather than to keep trying.
func TestRollbackWithNoPreviousVersionStillFallsBack(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")
	usr := filepath.Join(b.root, "usrbin")
	os.WriteFile(filepath.Join(usr, "ompd"), []byte("BAD"), 0o755)
	b.deployedAt(time.Now().Add(5 * time.Minute))

	b.healthy(false)
	b.tick(4)

	if _, err := os.Stat(filepath.Join(b.run, "probation")); err == nil {
		t.Error("probation survived a rollback that could not happen; it would retry forever")
	}

	b.tick(4)
	if !b.inFallback() {
		t.Error("never fell back after finding there was nothing to roll back to")
	}
}

// A daemon can be running and have stopped doing anything, which is the
// one failure systemd cannot see. A state file that has stopped
// advancing says so.
func TestWedgedDaemonCountsAsFailure(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")

	// Tunnel pings fine, but the daemon stopped writing an hour ago.
	b.touch("ping_ok")
	b.touch("exists_wg0")
	b.stateFile(time.Hour, "0", "enp2s0")

	b.tick(4)

	if !b.inFallback() {
		t.Error("a daemon that had stopped writing state was treated as healthy")
	}
}

// deployedAt writes the probation deadline the way omp-deploy does.
func (b *box) deployedAt(deadline time.Time) {
	b.t.Helper()
	p := filepath.Join(b.run, "probation")
	if err := os.WriteFile(p, []byte(fmt.Sprintf("%d\n", deadline.Unix())), 0o644); err != nil {
		b.t.Fatal(err)
	}
}

// The responder has one connection and nothing to route around, so its
// watchdog must never tear up the routing - but it still has to roll back
// a bad upgrade, because home is the end nobody can power-cycle by hand.
func TestResponderRollsBackButNeverFallsBack(t *testing.T) {
	b := newBox(t)
	b.link("eth0", "10.10.10.1")
	b.noFallback = true

	b.healthy(false)
	b.tick(10)

	if b.inFallback() {
		t.Error("responder fell back despite having nowhere to fall back to")
	}
	if strings.Contains(b.calls(), "rule add") {
		t.Error("responder altered routing rules")
	}

	// Rollback still works there.
	usr := filepath.Join(b.root, "usrbin")
	os.WriteFile(filepath.Join(usr, "ompd"), []byte("BAD"), 0o755)
	os.WriteFile(filepath.Join(usr, "ompd.prev"), []byte("GOOD"), 0o755)
	b.deployedAt(time.Now().Add(5 * time.Minute))

	b.tick(4)
	if got, _ := os.ReadFile(filepath.Join(usr, "ompd")); string(got) != "GOOD" {
		t.Errorf("responder did not roll back a failed upgrade; binary is %q", got)
	}
}

// The catch-all cannot be the only rule fallback installs.
//
// wg-quick puts a `lookup main suppress_prefixlength 0` rule at 1999 when
// the tunnel owns the default route, and that is what keeps the LAN, the
// connected subnets and the transport tunnels' own endpoints reachable.
// In the D-020 shape wg0 is down and that rule does not exist, so a bare
// catch-all swallows everything: the vehicle's LAN replies, and the path
// sockets' packets to home's tunnel address.
//
// The second of those is a deadlock, not an inconvenience. The watchdog
// leaves fallback only when the tunnel answers, and the tunnel cannot
// answer while its own transport is being routed into the clear.
func TestFallbackHonoursSpecificRoutesBeforeItsCatchAll(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")
	b.healthy(false)
	b.tick(4)

	calls := b.calls()
	suppress := strings.Index(calls, "suppress_prefixlength 0 priority 1998")
	catchAll := strings.Index(calls, "lookup 2500 priority 2000")

	if suppress < 0 {
		t.Fatalf("fallback installed no suppress_prefixlength rule; a bare catch-all "+
			"strands the box when wg-quick's own rule is absent. calls:\n%s", calls)
	}
	if catchAll < 0 {
		t.Fatalf("fallback installed no catch-all; calls:\n%s", calls)
	}
	if suppress > catchAll {
		t.Error("installed the catch-all before the suppress rule")
	}

	// And both come back out on the way home, or the next shape inherits
	// a rule nobody put there.
	b.healthy(true)
	b.tick(12)
	after := b.calls()[len(calls):]
	if !strings.Contains(after, "rule del priority 1998") {
		t.Error("leaving fallback left the suppress rule behind")
	}
	if !strings.Contains(after, "rule del priority 2000") {
		t.Error("leaving fallback left the catch-all behind")
	}
}

// Above WireGuard the tunnel is a TUN the daemon created, and wg-quick
// has never heard of it: there is no config to bring back up, and the
// rules fallback displaced were entirely its own. Cycling an interface
// wg-quick does not own is at best a no-op and at worst deletes the
// daemon's device out from under it.
func TestLeavingFallbackDoesNotCycleATunnelWgQuickDoesNotOwn(t *testing.T) {
	b := newBox(t)
	b.link("enp2s0", "192.168.225.1")
	// No wg0.conf here: the tunnel is a TUN the daemon owns.
	b.wgConfDir = filepath.Join(b.root, "wireguard-empty")
	os.MkdirAll(b.wgConfDir, 0o755)

	b.healthy(false)
	b.tick(4)
	mark := len(b.calls())

	b.healthy(true)
	b.tick(12)

	after := b.calls()[mark:]
	if strings.Contains(after, "wg-quick") {
		t.Errorf("cycled a tunnel wg-quick does not own; calls:\n%s", after)
	}
	if !strings.Contains(after, "rule del priority 2000") {
		t.Error("did not remove its own catch-all rule")
	}
}
