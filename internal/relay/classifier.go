package relay

import (
	"github.com/anthonysecco/OpenMultiPath/internal/classify"
	"github.com/anthonysecco/OpenMultiPath/internal/config"
	"github.com/anthonysecco/OpenMultiPath/internal/protocol"
)

// flowClassifier is step 7 attached to the data path, and the gate that
// keeps it from running where it would be meaningless.
//
// Classification needs to see inner packets. Below WireGuard the payload
// is ciphertext, and the failure there would not be loud: a 5-tuple parser
// pointed at an encrypted blob does not error, it finds plausible-looking
// addresses and ports in random bytes and hands back a verdict built on
// them. So the classifier exists only when the local endpoint says its
// payloads are plaintext, and every packet is ClassUnknown otherwise -
// which is exactly how the daemon behaved before step 7, and the right
// behaviour for the loopback relay that D-020 keeps as the way back.
type flowClassifier struct {
	c *classify.Classifier
}

func newFlowClassifier(local localEndpoint, settings *config.Holder) flowClassifier {
	if !local.plaintext() {
		return flowClassifier{}
	}
	return flowClassifier{c: classify.New(settings)}
}

// classify returns the class for one payload, or ClassUnknown when there
// is nothing that can honestly be said about it.
func (f flowClassifier) classify(payload []byte) uint8 {
	if f.c == nil {
		return protocol.ClassUnknown
	}
	return f.c.Classify(payload)
}

// enabled reports whether classification is actually running, for the
// startup log line - "no real-time traffic seen" and "not looking" are
// very different things to read at 2am.
func (f flowClassifier) enabled() bool { return f.c != nil }

// flows is how many conversations are being tracked, for the interface.
func (f flowClassifier) flows() int {
	if f.c == nil {
		return 0
	}
	return f.c.Flows()
}
