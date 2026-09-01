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
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/state"
)

//go:embed static
var static embed.FS

type server struct {
	statePath  string
	configPath string
	unit       string
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8080",
		"address to serve on; set this to the LAN address so the interface is not exposed on the WAN side")
	statePath := flag.String("state", "/var/lib/openmultipath/state.json", "state file written by the daemon")
	configPath := flag.String("config", "/etc/openmultipath/config.json", "settings file shared with the daemon")
	unit := flag.String("unit", "ompd", "systemd unit for the daemon, for log access and restarts")
	flag.Parse()

	s := &server{statePath: *statePath, configPath: *configPath, unit: *unit}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(mustSubFS())))
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/restart", s.handleRestart)
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
