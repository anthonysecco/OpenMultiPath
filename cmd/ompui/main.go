// Command ompui serves the local management interface.
//
// It is a separate process from the daemon on purpose. The moment this
// interface matters most is the moment the daemon has stopped working, so
// it must not share the daemon's fate: it reads the state file the daemon
// leaves behind rather than asking the daemon anything, and it leads with
// how old that file is. Stale-but-visible is what diagnosis needs.
//
// For the same reason it binds a fixed LAN address and serves plain static
// assets with no build step, so it comes up with no routing, no tunnel and
// no toolchain.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/diag"
	"github.com/anthonysecco/OpenMultiPath/internal/linkspeed"
	"github.com/anthonysecco/OpenMultiPath/internal/state"
)

//go:embed static
var static embed.FS

type server struct {
	statePath  string
	configPath string
	unit       string

	// flowtestServer is the home end's omp-flowtest address (host:port) for
	// the on-demand raw-link uplink diagnostic (D-053). diagMu makes the
	// test single-flight: the server handles one run at a time, and two
	// saturating floods at once would measure neither path honestly.
	flowtestServer string

	// linkSpeedPath is where a successful flow test's result is saved as the
	// link's measured speed (D-055). ompui is its only writer; ompd on the
	// vehicle watches it, shapes to it, and passes it to home.
	linkSpeedPath string

	diagMu sync.Mutex
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8080",
		"address to serve on; set this to the LAN address so the interface is not exposed on the WAN side")
	statePath := flag.String("state", "/var/lib/openmultipath/state.json", "state file written by the daemon")
	configPath := flag.String("config", "/etc/openmultipath/config.json", "settings file shared with the daemon")
	unit := flag.String("unit", "ompd", "systemd unit for the daemon, for log access and restarts")
	flowtestServer := flag.String("flowtest-server", "10.20.1.1:5202", "initiator only: home's omp-flowtest address for the on-demand per-path uplink test (D-053)")
	linkSpeedPath := flag.String("linkspeed", linkspeed.DefaultPath, "initiator only: where a flow test's result is saved as the link's measured speed, which ompd shapes to (D-055)")
	flag.Parse()

	s := &server{
		statePath:      *statePath,
		configPath:     *configPath,
		unit:           *unit,
		flowtestServer: *flowtestServer,
		linkSpeedPath:  *linkSpeedPath,
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(mustSubFS())))
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/restart", s.handleRestart)
	mux.HandleFunc("/api/diag/bandwidth", s.handleDiagBandwidth)
	mux.HandleFunc("/api/diag/speedtest", s.handleDiagSpeedtest)
	mux.HandleFunc("/api/linkspeed/clear", s.handleLinkSpeedClear)
	mux.HandleFunc("/metrics", s.handleMetrics)

	log.Printf("ompui: serving on http://%s (state %s)", *listen, *statePath)
	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// mustSubFS serves the embedded page at the root rather than under the
// directory it happens to live in.
func mustSubFS() fs.FS {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		log.Fatalf("ompui: embedded assets: %v", err)
	}
	return sub
}

func (s *server) handleState(w http.ResponseWriter, r *http.Request) {
	snap, err := state.Read(s.statePath)
	if err != nil {
		// A missing or unreadable state file is itself the diagnosis: the
		// daemon has not written one. Say so rather than serving nothing.
		writeJSON(w, http.StatusOK, map[string]any{
			"available": false,
			"error":     err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"available":   true,
		"age_seconds": snap.Age().Seconds(),
		"state":       snap,
	})
}

func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		c, err := config.Load(s.configPath)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"config": c, "warning": err.Error(), "bounds": config.Bounds})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"config": c, "bounds": config.Bounds})

	case http.MethodPost:
		// Decode onto what is already saved, so a submission that names
		// only some settings changes only those. A zero is a real value
		// now rather than "unset", so decoding onto an empty Config would
		// quietly reset every setting the form did not happen to include -
		// which is precisely what happens the first time someone adds a
		// field to the page and forgets one.
		c, err := config.Load(s.configPath)
		if err != nil {
			c = config.Defaults()
		}
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "could not read the submitted settings: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Values are clamped rather than refused, so a bad number is
		// corrected into something workable instead of leaving the daemon
		// with nothing usable.
		if err := config.Save(s.configPath, c); err != nil {
			http.Error(w, "could not save: "+err.Error(), http.StatusInternalServerError)
			return
		}
		saved, _ := config.Load(s.configPath)
		writeJSON(w, http.StatusOK, map[string]any{"config": saved, "bounds": config.Bounds})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLogs serves the daemon's recent log. Reading the last few minutes
// of a path's behaviour without reaching for SSH is the difference between
// diagnosing and guessing.
func (s *server) handleLogs(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("journalctl", "-u", s.unit, "-n", "300", "--no-pager", "-o", "short-iso").CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"lines": []string{"could not read the log: " + err.Error()}})
		return
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines})
}

func (s *server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if out, err := exec.Command("systemctl", "restart", s.unit).CombinedOutput(); err != nil {
		http.Error(w, "restart failed: "+string(out), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"restarted": s.unit})
}

// handleDiagBandwidth runs an on-demand ompd-native UDP flow test (D-053)
// pinned to one path, and saves the result as that link's measured speed
// (D-055): ompd shapes each direction to 95% of it. It costs real, possibly
// metered, data in both directions, so it happens only when a person asks
// for it.
func (s *server) handleDiagBandwidth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PathID  *uint8 `json:"path_id"`
		Seconds int    `json:"seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PathID == nil {
		http.Error(w, "expected a JSON body with a path_id", http.StatusBadRequest)
		return
	}
	// A short test is enough to load the link; a long one just spends more
	// data. Clamp both ends so a bad value cannot flood the uplink for
	// minutes - each direction runs for this long, one after the other.
	if req.Seconds < 1 || req.Seconds > 30 {
		req.Seconds = 5
	}

	snap, err := state.Read(s.statePath)
	if err != nil {
		http.Error(w, "cannot read state to resolve the path: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !snap.ManagesPaths {
		http.Error(w, "this end does not own its paths; run the test from the vehicle", http.StatusBadRequest)
		return
	}
	var path *state.Path
	for i := range snap.Paths {
		if snap.Paths[i].ID == *req.PathID {
			path = &snap.Paths[i]
			break
		}
	}
	if path == nil {
		http.Error(w, "no such path", http.StatusNotFound)
		return
	}
	if path.Name == "" {
		http.Error(w, "that path has no interface to bind to", http.StatusBadRequest)
		return
	}
	if !path.Bound {
		http.Error(w, "that link is down; nothing to test over", http.StatusConflict)
		return
	}

	host, portStr, err := net.SplitHostPort(s.flowtestServer)
	if err != nil {
		http.Error(w, "flowtest server address is misconfigured: "+err.Error(), http.StatusInternalServerError)
		return
	}
	port, _ := strconv.Atoi(portStr)

	// Single-flight: the server handles one run at a time, and two floods at
	// once would measure neither honestly.
	if !s.diagMu.TryLock() {
		http.Error(w, "a bandwidth test is already running", http.StatusConflict)
		return
	}
	defer s.diagMu.Unlock()

	// Both directions run sequentially, each with its own retry budget for
	// the control round trips (see internal/diag/flowtest.go), so the whole
	// run takes noticeably longer than either direction alone.
	timeout := time.Duration(req.Seconds*2+20) * time.Second
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	res, runErr := diag.RunFlowTest(ctx, diag.FlowOptions{
		Iface:   path.Name,
		Server:  host,
		Port:    port,
		Seconds: req.Seconds,
	})

	out := map[string]any{
		"path_id": *req.PathID,
		"iface":   path.Name,
	}
	if runErr != nil {
		// A failed run saves nothing. The last good measurement stands: a test
		// that could not finish, in a dead zone say, is not evidence the link
		// got slower.
		out["error"] = runErr.Error()
		writeJSON(w, http.StatusOK, out)
		return
	}
	out["result"] = res

	saved, err := s.saveMeasurement(path.Name, res)
	if err != nil {
		out["save_error"] = err.Error()
	} else {
		out["saved"] = map[string]any{
			"up_kbps":          saved.UpKbps,
			"down_kbps":        saved.DownKbps,
			"measured_unix":    saved.MeasuredUnix,
			"shaped_up_kbps":   linkspeed.ShapedKbps(saved.UpKbps),
			"shaped_down_kbps": linkspeed.ShapedKbps(saved.DownKbps),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// saveMeasurement records a flow test's result as a link's measured speed.
//
// A direction that measured nothing keeps its previous figure rather than
// being set to zero - zero means "never measured", which is unlimited, and a
// direction that delivered nothing during one test has not been shown to be
// unlimited. Only called under diagMu, which is what keeps this file to one
// writer at a time.
func (s *server) saveMeasurement(iface string, res diag.FlowResult) (linkspeed.Measurement, error) {
	f, err := linkspeed.Load(s.linkSpeedPath)
	if err != nil {
		// A corrupt file is replaced rather than left to block every future
		// measurement; what it held could not be read by ompd either.
		log.Printf("ompui: %v; replacing it", err)
	}
	m := f.Links[iface]
	if up := res.UploadMbps * 1000; up > 0 {
		m.UpKbps = up
	}
	if down := res.DownloadMbps * 1000; down > 0 {
		m.DownKbps = down
	}
	m.MeasuredUnix = time.Now().Unix()
	f.Links[iface] = m
	return m, linkspeed.Save(s.linkSpeedPath, f)
}

// handleLinkSpeedClear forgets a link's measured speed, which leaves it
// unshaped at both ends - the way back from a measurement taken at a bad
// moment, short of measuring again.
func (s *server) handleLinkSpeedClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PathID *uint8 `json:"path_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PathID == nil {
		http.Error(w, "expected a JSON body with a path_id", http.StatusBadRequest)
		return
	}
	snap, err := state.Read(s.statePath)
	if err != nil {
		http.Error(w, "cannot read state to resolve the path: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !snap.ManagesPaths {
		http.Error(w, "link speeds are measured and kept on the vehicle; clear it there", http.StatusBadRequest)
		return
	}
	var name string
	for _, p := range snap.Paths {
		if p.ID == *req.PathID {
			name = p.Name
		}
	}
	if name == "" {
		http.Error(w, "no such path", http.StatusNotFound)
		return
	}
	// Shares the flow test's lock, so a clear cannot interleave with a save.
	s.diagMu.Lock()
	defer s.diagMu.Unlock()
	f, err := linkspeed.Load(s.linkSpeedPath)
	if err != nil {
		log.Printf("ompui: %v; replacing it", err)
	}
	delete(f.Links, name)
	if err := linkspeed.Save(s.linkSpeedPath, f); err != nil {
		http.Error(w, "saving link speeds failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cleared": name})
}

// handleDiagSpeedtest runs a public-internet speed test pinned to one path's
// physical WAN link, via the omp-speedtest helper. Unlike the flow test,
// which measures the tunnel to home, this measures the carrier's own
// capacity - a different and heavier thing: a full run spends tens of
// megabytes of real, possibly metered, data in each direction, which is why
// it is a button a person presses and the bytes it moved are reported back.
func (s *server) handleDiagSpeedtest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PathID  *uint8 `json:"path_id"`
		Seconds int    `json:"seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PathID == nil {
		http.Error(w, "expected a JSON body with a path_id", http.StatusBadRequest)
		return
	}
	if req.Seconds < 3 || req.Seconds > 20 {
		req.Seconds = 5
	}

	snap, err := state.Read(s.statePath)
	if err != nil {
		http.Error(w, "cannot read state to resolve the path: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !snap.ManagesPaths {
		http.Error(w, "this end does not own its paths; run the test from the vehicle", http.StatusBadRequest)
		return
	}
	var path *state.Path
	for i := range snap.Paths {
		if snap.Paths[i].ID == *req.PathID {
			path = &snap.Paths[i]
			break
		}
	}
	if path == nil {
		http.Error(w, "no such path", http.StatusNotFound)
		return
	}
	if path.Name == "" {
		http.Error(w, "that path has no interface to resolve", http.StatusBadRequest)
		return
	}
	if !path.Bound {
		http.Error(w, "that link is down; nothing to test over", http.StatusConflict)
		return
	}

	// One link test at a time, shared with the flow test: both saturate a
	// physical link, and two at once would measure neither.
	if !s.diagMu.TryLock() {
		http.Error(w, "a link test is already running", http.StatusConflict)
		return
	}
	defer s.diagMu.Unlock()

	// Generous margin over the duration: a speed test also spends time
	// selecting a server and running both directions.
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(req.Seconds*2+45)*time.Second)
	defer cancel()

	res, runErr := diag.RunSpeedtest(ctx, "", path.Name, req.Seconds)

	out := map[string]any{"path_id": *req.PathID, "iface": path.Name}
	if runErr != nil {
		out["error"] = runErr.Error()
		writeJSON(w, http.StatusOK, out)
		return
	}
	out["result"] = res
	writeJSON(w, http.StatusOK, out)
}

// handleMetrics exposes the same figures for Prometheus, which is nearly
// free on top of the JSON and is what gives historical graphing from the
// home end when connectivity allows.
func (s *server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snap, err := state.Read(s.statePath)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	if err != nil {
		fmt.Fprintf(w, "# state file unreadable: %v\n", err)
		fmt.Fprintf(w, "omp_state_available 0\n")
		return
	}
	fmt.Fprintf(w, "omp_state_available 1\n")

	fmt.Fprintf(w, "# HELP omp_state_age_seconds How long ago the daemon last wrote its state.\n")
	fmt.Fprintf(w, "# TYPE omp_state_age_seconds gauge\n")
	fmt.Fprintf(w, "omp_state_age_seconds %.3f\n", snap.Age().Seconds())

	// What the classifier decided, cumulative. The transactional split is
	// the only place the field data can say whether its thresholds are
	// right, so it is worth graphing before anything is tuned on it.
	fmt.Fprintf(w, "# HELP omp_duplicates_dropped_total Redundant copies discarded on arrival.\n")
	fmt.Fprintf(w, "# TYPE omp_duplicates_dropped_total counter\n")
	fmt.Fprintf(w, "omp_duplicates_dropped_total{node=%q} %d\n",
		escape(snap.Node), snap.Scheduler.DuplicatesDropped)

	fmt.Fprintf(w, "# HELP omp_bulk_cascade_active Whether bulk is being placed per packet by the cascade (1) or per flow (0).\n")
	fmt.Fprintf(w, "# TYPE omp_bulk_cascade_active gauge\n")
	fmt.Fprintf(w, "omp_bulk_cascade_active{node=%q} %g\n", escape(snap.Node), b2f(snap.Scheduler.BulkScheduler == "cascade"))
	fmt.Fprintf(w, "# HELP omp_bulk_overflowed_total Bulk sent with every cascade path's shaper backed up, onto the first path in the fill order.\n")
	fmt.Fprintf(w, "# TYPE omp_bulk_overflowed_total counter\n")
	fmt.Fprintf(w, "omp_bulk_overflowed_total{node=%q} %d\n", escape(snap.Node), snap.Scheduler.BulkOverflowed)
	fmt.Fprintf(w, "# HELP omp_wire_version Wire version spoken to the peer.\n# TYPE omp_wire_version gauge\n")
	fmt.Fprintf(w, "omp_wire_version{node=%q} %d\n", escape(snap.Node), snap.Scheduler.WireVersion)
	rs := snap.Scheduler.Resequencer
	fmt.Fprintf(w, "# HELP omp_resequencer_hold_ms How long a missing bulk packet is currently waited for.\n# TYPE omp_resequencer_hold_ms gauge\n")
	fmt.Fprintf(w, "omp_resequencer_hold_ms{node=%q} %g\n", escape(snap.Node), rs.HoldMs)
	fmt.Fprintf(w, "# HELP omp_resequencer_buffered Bulk packets waiting behind gaps.\n# TYPE omp_resequencer_buffered gauge\n")
	fmt.Fprintf(w, "omp_resequencer_buffered{node=%q} %d\n", escape(snap.Node), rs.Buffered)
	fmt.Fprintf(w, "# HELP omp_resequencer_packets_total Resequencer outcomes: delivered, reordered (held behind a gap), late (arrived after its gap was given up on).\n# TYPE omp_resequencer_packets_total counter\n")
	for _, c := range []struct {
		name string
		n    uint64
	}{{"delivered", rs.Delivered}, {"reordered", rs.Reordered}, {"late", rs.Late}} {
		fmt.Fprintf(w, "omp_resequencer_packets_total{node=%q,outcome=%q} %d\n", escape(snap.Node), c.name, c.n)
	}
	fmt.Fprintf(w, "# HELP omp_resequencer_gaps_total Gaps given up on, by reason.\n# TYPE omp_resequencer_gaps_total counter\n")
	for _, c := range []struct {
		name string
		n    uint64
	}{{"lost", rs.GapsLost}, {"timed_out", rs.GapsTimedOut}, {"forced", rs.GapsForced}} {
		fmt.Fprintf(w, "omp_resequencer_gaps_total{node=%q,reason=%q} %d\n", escape(snap.Node), c.name, c.n)
	}

	fmt.Fprintf(w, "# HELP omp_class_packets_total Packets carried, by traffic class.\n")
	fmt.Fprintf(w, "# TYPE omp_class_packets_total counter\n")
	for _, c := range []struct {
		name string
		n    uint64
	}{
		{"realtime", snap.Scheduler.ClassRealtime},
		{"transactional", snap.Scheduler.ClassTransactional},
		{"bulk", snap.Scheduler.ClassBulk},
		{"unclassified", snap.Scheduler.ClassUnknown},
	} {
		fmt.Fprintf(w, "omp_class_packets_total{node=%q,class=%q} %d\n",
			escape(snap.Node), c.name, c.n)
	}

	node := escape(snap.Node)
	for _, m := range []struct {
		name, help, typ string
		value           func(state.Path) float64
	}{
		{"omp_path_rtt_ms", "Most recent round trip on a path.", "gauge", func(p state.Path) float64 { return p.RTTMs }},
		{"omp_path_p95_spread_ms", "95th percentile transit above the path's own floor.", "gauge", func(p state.Path) float64 { return p.P95SpreadMs }},
		{"omp_path_jitter_ms", "RFC 3550 interarrival jitter.", "gauge", func(p state.Path) float64 { return p.JitterMs }},
		{"omp_path_queue_delay_ms", "Transit above the path's rolling minimum.", "gauge", func(p state.Path) float64 { return p.QueueDelayMs }},
		{"omp_path_received_total", "Packets received on a path.", "counter", func(p state.Path) float64 { return float64(p.Received) }},
		{"omp_path_lost_total", "Packets detected lost on a path.", "counter", func(p state.Path) float64 { return float64(p.Lost) }},
		{"omp_path_loss_percent", "Loss as a percentage of what should have arrived.", "gauge", func(p state.Path) float64 { return p.LossPercent }},
		{"omp_path_mtu_bytes", "Largest packet confirmed to cross the path.", "gauge", func(p state.Path) float64 { return float64(p.PathMTU) }},
		{"omp_path_alive", "Whether the path has delivered anything recently.", "gauge", func(p state.Path) float64 { return b2f(p.Alive) }},
		{"omp_path_samples", "Delay samples held for this path.", "gauge", func(p state.Path) float64 { return float64(p.Samples) }},
		{"omp_path_score", "E-model R factor after the scheduler's penalties; higher is better.", "gauge", func(p state.Path) float64 { return p.Score }},
		{"omp_path_r_factor", "E-model R factor before penalties.", "gauge", func(p state.Path) float64 { return p.RFactor }},
		{"omp_path_mos", "Score restated on the 1-to-5 scale.", "gauge", func(p state.Path) float64 { return p.MOS }},
		{"omp_path_stable", "Whether the path is meeting all of its thresholds.", "gauge", func(p state.Path) float64 { return b2f(p.State == "stable") }},
		{"omp_path_down", "Whether the path is considered down.", "gauge", func(p state.Path) float64 { return b2f(p.State == "down") }},
		{"omp_path_flapping", "Whether the path has changed state too often to be trusted.", "gauge", func(p state.Path) float64 { return b2f(p.Flapping) }},
		{"omp_path_transitions", "State changes within the flap window.", "gauge", func(p state.Path) float64 { return float64(p.Transitions) }},
		{"omp_path_sending", "Whether traffic is currently going out of this path.", "gauge", func(p state.Path) float64 { return b2f(p.Sending) }},
		{"omp_path_primary", "Whether this is the chosen path.", "gauge", func(p state.Path) float64 { return b2f(p.Primary) }},

		// The bulk cascade, v0.2.
		{"omp_path_cascade_position", "Place in the bulk fill order, 0 filled first; -1 when not in the cascade.", "gauge", func(p state.Path) float64 { return float64(p.CascadePosition) }},
		{"omp_path_bulk_kbps", "Bulk carried over the last evaluation.", "gauge", func(p state.Path) float64 { return p.BulkKbps }},

		// Measured link speed and shaping, D-055.
		{"omp_path_send_kbps", "What this end is sending on the path, in wire bytes.", "gauge", func(p state.Path) float64 { return p.SendKbps }},
		{"omp_path_link_up_kbps", "Measured link speed, vehicle to home; 0 is never measured.", "gauge", func(p state.Path) float64 { return p.LinkUpKbps }},
		{"omp_path_link_down_kbps", "Measured link speed, home to vehicle; 0 is never measured.", "gauge", func(p state.Path) float64 { return p.LinkDownKbps }},
		{"omp_path_shaped_kbps", "The most this end sends on the path; 0 is unshaped.", "gauge", func(p state.Path) float64 { return p.ShapedKbps }},
		{"omp_path_shaper_backlog_bytes", "Bytes queued behind the path's shaper.", "gauge", func(p state.Path) float64 { return float64(p.ShaperBacklogBytes) }},
		{"omp_path_shaper_dropped_total", "Packets dropped at the shaper's queue limit.", "counter", func(p state.Path) float64 { return float64(p.ShaperDropped) }},
		{"omp_path_tx_standing_queue_ms", "Standing queue in the send direction, as the peer reports it.", "gauge", func(p state.Path) float64 { return p.TxStandingQueueMs }},
		{"omp_path_tx_short_loss_percent", "Send-direction loss over the last second, as the peer reports it.", "gauge", func(p state.Path) float64 { return p.TxShortLossPercent }},

		// Cost tracking, step 10. Bytes rather than a band name, because
		// the useful alert is on the number approaching the cap rather
		// than on the band having already changed - by then the
		// duplication is off and the bulk has moved.
		{"omp_path_used_bytes", "Bytes carried on this link so far in its billing cycle, both directions.", "gauge", func(p state.Path) float64 { return float64(p.UsedBytes) }},
		{"omp_path_cap_bytes", "Configured billing-cycle allowance; zero means unmetered.", "gauge", func(p state.Path) float64 { return float64(p.CapBytes) }},
		{"omp_path_projected_bytes", "Whole-cycle total the current burn rate implies.", "gauge", func(p state.Path) float64 { return float64(p.ProjectedBytes) }},
		{"omp_path_budget_yellow", "Whether this link is projected to run short of its allowance.", "gauge", func(p state.Path) float64 { return b2f(p.Budget == "yellow") }},
		{"omp_path_budget_red", "Whether this link has spent its allowance.", "gauge", func(p state.Path) float64 { return b2f(p.Budget == "red") }},
	} {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", m.name, m.help, m.name, m.typ)
		for _, p := range snap.Paths {
			fmt.Fprintf(w, "%s{node=%q,path=\"%d\",name=%q} %g\n",
				m.name, node, p.ID, escape(p.Name), m.value(p))
		}
	}

	fmt.Fprintf(w, "# HELP omp_loss_percent Loss across every path.\n# TYPE omp_loss_percent gauge\n")
	fmt.Fprintf(w, "omp_loss_percent{node=%q} %g\n", node, snap.Aggregate.LossPercent)
	fmt.Fprintf(w, "# HELP omp_paths_alive Paths that have delivered something recently.\n# TYPE omp_paths_alive gauge\n")
	fmt.Fprintf(w, "omp_paths_alive{node=%q} %d\n", node, snap.Aggregate.PathsAlive)
	fmt.Fprintf(w, "# HELP omp_paths_total Paths known.\n# TYPE omp_paths_total gauge\n")
	fmt.Fprintf(w, "omp_paths_total{node=%q} %d\n", node, snap.Aggregate.PathsTotal)
	fmt.Fprintf(w, "# HELP omp_tunnel_mtu_bytes MTU the tunnel interface is set to.\n# TYPE omp_tunnel_mtu_bytes gauge\n")
	fmt.Fprintf(w, "omp_tunnel_mtu_bytes{node=%q} %d\n", node, snap.TunnelMTU)
	fmt.Fprintf(w, "# HELP omp_recommended_tunnel_mtu_bytes MTU the measured paths support.\n# TYPE omp_recommended_tunnel_mtu_bytes gauge\n")
	fmt.Fprintf(w, "omp_recommended_tunnel_mtu_bytes{node=%q} %d\n", node, snap.RecommendedTunnelMTU)

	// Blind is the one alarm worth wiring up: it means no path is in a
	// usable state and traffic is being sprayed at every link in the hope
	// something lands.
	fmt.Fprintf(w, "# HELP omp_scheduler_blind No path is usable; traffic is going everywhere.\n# TYPE omp_scheduler_blind gauge\n")
	fmt.Fprintf(w, "omp_scheduler_blind{node=%q} %g\n", node, b2f(snap.Scheduler.Blind))
	fmt.Fprintf(w, "# HELP omp_scheduler_switching A make-before-break handover is in progress.\n# TYPE omp_scheduler_switching gauge\n")
	fmt.Fprintf(w, "omp_scheduler_switching{node=%q} %g\n", node, b2f(snap.Scheduler.Switching))
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// escape makes a value safe to use inside a Prometheus label.
func escape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("ompui: writing response failed: %v", err)
	}
}
