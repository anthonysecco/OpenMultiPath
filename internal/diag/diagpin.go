package diag

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// PinPath is where an operator-triggered diagnostic pin request lives.
// Under /run, not /etc: the request is a one-off action tied to a single
// test run, not a durable setting, and tmpfs means a reboot cannot leave a
// stale one behind (D-048).
const PinPath = "/run/openmultipath/diag-pin.json"

// PinRequest asks the daemon to force one flow onto one path, bypassing
// D-044's load-balancing hash and every gate above it (D-045, D-046). It
// exists so an operator-triggered saturation test can answer "what does
// this specific link do under load" even for a link the live gates
// currently exclude - which is often exactly the link worth asking about.
//
// The flow is named by its 5-tuple rather than some new identifier so the
// daemon can compute the same hash the data path already computes per
// packet and match against it directly - see flowHashTuple in
// internal/relay - with no second way of identifying a flow to keep in
// sync with the first.
type PinRequest struct {
	PathID      uint8  `json:"path_id"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	Protocol    uint8  `json:"protocol"` // 17 for UDP, 6 for TCP
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	ExpiresUnix int64  `json:"expires_unix"`
}

// WritePin records a pin request for the daemon to pick up. Written to a
// temp file and renamed into place, so the daemon's poll - which trusts
// mtime and size to mean "this file changed" - never observes a
// half-written one.
func WritePin(req PinRequest) error {
	if err := os.MkdirAll(filepath.Dir(PinPath), 0o755); err != nil {
		return fmt.Errorf("diag pin: %w", err)
	}
	b, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("diag pin: %w", err)
	}
	tmp := PinPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("diag pin: %w", err)
	}
	if err := os.Rename(tmp, PinPath); err != nil {
		return fmt.Errorf("diag pin: %w", err)
	}
	return nil
}

// ClearPin removes a pin request, called once a pinned test finishes so the
// forced routing does not outlive it. Not the only protection: the request
// also carries its own expiry, for when this is never reached - ompui
// killed mid-test, the request dropped.
func ClearPin() error {
	if err := os.Remove(PinPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("diag pin: %w", err)
	}
	return nil
}

// ReadPin loads a pin request from path.
func ReadPin(path string) (PinRequest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return PinRequest{}, err
	}
	var req PinRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return PinRequest{}, fmt.Errorf("diag pin: bad json: %w", err)
	}
	return req, nil
}
