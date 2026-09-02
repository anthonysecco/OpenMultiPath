// Package tun opens the TUN device the daemon reads inner packets from.
//
// D-020 moves the daemon above WireGuard so it can see plaintext. This is
// the seam where that happens: what comes out of Read is an inner IP
// packet exactly as the LAN sent it, which is what classification needs a
// 5-tuple from and what the scheduler is choosing a path for. Below this
// package there is nothing interesting; above it is the whole point of the
// project.
//
// It is deliberately small and stdlib-only. The device is created,
// addressed, sized and brought up through the same ioctls the kernel has
// exposed for decades, rather than through netlink or by shelling out to
// ip(8). Netlink would be several hundred lines of encoding for what four
// ioctls do; shelling out would make the daemon depend on a binary being
// present and on its output format. Neither trade is worth it here.
package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

// Linux ioctl numbers and interface flags. These are ABI: they are fixed
// for the lifetime of the kernel's userspace interface, which is why it is
// safe to write them down rather than pull in a package to name them.
const (
	tunsetiff      = 0x400454ca
	siocsifmtu     = 0x8922
	siocgifmtu     = 0x8921
	siocsifflags   = 0x8914
	siocgifflags   = 0x8913
	siocsifaddr    = 0x8916
	siocsifnetmask = 0x891c

	iffTun = 0x0001

	// iffNoPI drops the four-byte packet-information prefix the device
	// otherwise puts in front of every frame. Without it Read would hand
	// back two bytes of flags and two of protocol before the IP header,
	// and every consumer would have to know to skip them. With it, a read
	// is exactly one IP packet, which is what the rest of the daemon
	// wants and what internal/classify already parses.
	iffNoPI = 0x1000

	iffUp      = 0x1
	iffRunning = 0x40
)

// Config describes the device to open. Every field has a working default
// except Name, because a daemon that picked its own interface name would
// be a daemon nobody could write a firewall rule for.
type Config struct {
	Name string // interface name, e.g. "omp0"

	// MTU is the largest inner packet the device will hand back. Zero
	// leaves the kernel default, which is 1500 and is wrong for a tunnel;
	// the caller is expected to set it from what the paths can carry.
	MTU int

	// Address is the tunnel address assigned to the device. The zero
	// value leaves the device unaddressed, which is legitimate: routes
	// can point at an interface rather than a next hop.
	Address netip.Prefix
}

// Device is an open TUN interface.
type Device struct {
	f    *os.File
	name string
}

// Open creates the device, configures it, and brings it up.
//
// The device disappears when the last handle to it closes, so nothing is
// left behind if the daemon dies - which is the behaviour wanted on a box
// that power-cycles in a campground. It is not a persistent interface that
// could be left half-configured by a crash.
func Open(cfg Config) (*Device, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("tun: a device name is required")
	}
	if len(cfg.Name) >= syscall.IFNAMSIZ {
		return nil, fmt.Errorf("tun: name %q is longer than the kernel's %d-byte limit", cfg.Name, syscall.IFNAMSIZ-1)
	}

	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun (is the tun module loaded, and are we CAP_NET_ADMIN?): %w", err)
	}

	req := newIfreq(cfg.Name)
	*(*uint16)(unsafe.Pointer(&req.data[0])) = iffTun | iffNoPI
	if err := ioctl(uintptr(fd), tunsetiff, &req); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun: create %s: %w", cfg.Name, err)
	}

	// The kernel may hand back a different name than the one asked for
	// when the request was a pattern. Trust what it reports rather than
	// what was requested.
	name := nameOf(req.name)

	if err := configure(name, cfg); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Non-blocking, so the Go runtime drives reads through the netpoller
	// rather than parking an OS thread on each one. /dev/net/tun supports
	// poll, so this works; without it every blocked read would hold a
	// thread hostage.
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun: set %s non-blocking: %w", name, err)
	}

	return &Device{f: os.NewFile(uintptr(fd), "/dev/net/tun"), name: name}, nil
}

// configure applies MTU, address and the up flag, in that order. Address
// before up so the interface never spends a moment up and unaddressed.
func configure(name string, cfg Config) error {
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("tun: control socket: %w", err)
	}
	defer syscall.Close(sock)

	if cfg.MTU > 0 {
		req := newIfreq(name)
		*(*int32)(unsafe.Pointer(&req.data[0])) = int32(cfg.MTU)
		if err := ioctl(uintptr(sock), siocsifmtu, &req); err != nil {
			return fmt.Errorf("tun: set mtu %d on %s: %w", cfg.MTU, name, err)
		}
	}

	if cfg.Address.IsValid() {
		if !cfg.Address.Addr().Is4() {
			return fmt.Errorf("tun: address %s is not IPv4; D-026 keeps v6 off the WAN", cfg.Address)
		}
		req := newIfreq(name)
		putSockaddrInet4(&req.data, cfg.Address.Addr().As4())
		if err := ioctl(uintptr(sock), siocsifaddr, &req); err != nil {
			return fmt.Errorf("tun: set address %s on %s: %w", cfg.Address.Addr(), name, err)
		}

		mask := netip.PrefixFrom(cfg.Address.Addr(), cfg.Address.Bits()).Masked()
		req = newIfreq(name)
		putSockaddrInet4(&req.data, maskOf(mask.Bits()))
		if err := ioctl(uintptr(sock), siocsifnetmask, &req); err != nil {
			return fmt.Errorf("tun: set netmask /%d on %s: %w", cfg.Address.Bits(), name, err)
		}
	}

	// Before the interface comes up, not after. The moment a device is up
	// the kernel autoconfigures an IPv6 link-local address on it and starts
	// emitting multicast listener reports and router solicitations - which
	// the daemon would then read back out of its own tunnel as inner
	// packets to classify and schedule. D-026 keeps IPv6 off this box
	// entirely, so the device should never do it in the first place.
	if err := disableIPv6(name); err != nil {
		return err
	}

	req := newIfreq(name)
	if err := ioctl(uintptr(sock), siocgifflags, &req); err != nil {
		return fmt.Errorf("tun: read flags of %s: %w", name, err)
	}
	*(*uint16)(unsafe.Pointer(&req.data[0])) |= iffUp | iffRunning
	if err := ioctl(uintptr(sock), siocsifflags, &req); err != nil {
		return fmt.Errorf("tun: bring up %s: %w", name, err)
	}
	return nil
}

// Read returns exactly one inner IP packet.
//
// What arrives is not only traffic that was routed here. The kernel emits
// its own housekeeping on the device - an IGMP membership report turns up
// on a freshly created one - so a caller must be prepared for packets it
// did not expect and did not ask for. Classification handles this already:
// anything it cannot place in a conversation is ClassUnknown rather than a
// guess. A short buffer is an error the
// kernel reports rather than a silent truncation, so a caller that sizes
// its buffer to the MTU will never lose the tail of a packet.
func (d *Device) Read(p []byte) (int, error) { return d.f.Read(p) }

// Write sends one inner IP packet to the kernel, as though it had arrived
// on the wire.
func (d *Device) Write(p []byte) (int, error) { return d.f.Write(p) }

// Name is the interface name the kernel actually assigned.
func (d *Device) Name() string { return d.name }

// MTU reads the device's current MTU back from the kernel rather than
// reporting what was asked for, since the two can differ.
func (d *Device) MTU() (int, error) {
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(sock)

	req := newIfreq(d.name)
	if err := ioctl(uintptr(sock), siocgifmtu, &req); err != nil {
		return 0, fmt.Errorf("tun: read mtu of %s: %w", d.name, err)
	}
	return int(*(*int32)(unsafe.Pointer(&req.data[0]))), nil
}

// Close releases the device, which removes the interface.
func (d *Device) Close() error { return d.f.Close() }

// ifreq is the kernel's interface request structure: a name followed by a
// union the particular ioctl decides the meaning of.
type ifreq struct {
	name [syscall.IFNAMSIZ]byte
	data [24]byte
}

func newIfreq(name string) ifreq {
	var r ifreq
	copy(r.name[:], name)
	return r
}

func nameOf(b [syscall.IFNAMSIZ]byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b[:])
}

// putSockaddrInet4 writes a sockaddr_in into an ifreq's union: family,
// then a zero port, then the address.
func putSockaddrInet4(data *[24]byte, addr [4]byte) {
	*(*uint16)(unsafe.Pointer(&data[0])) = syscall.AF_INET
	data[2], data[3] = 0, 0
	copy(data[4:8], addr[:])
}

// maskOf turns a prefix length into a dotted netmask.
func maskOf(bits int) [4]byte {
	var m [4]byte
	for i := 0; i < bits; i++ {
		m[i/8] |= 1 << (7 - uint(i%8))
	}
	return m
}

func ioctl(fd, req uintptr, arg *ifreq) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(arg))); errno != 0 {
		return errno
	}
	return nil
}

// disableIPv6 turns IPv6 off for one interface.
//
// This is the one setting with no ioctl behind it - it lives only in
// sysfs. A missing file is not an error: a kernel built without IPv6 has
// nothing to disable, which is the state this is trying to reach anyway.
func disableIPv6(name string) error {
	path := "/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6"
	err := os.WriteFile(path, []byte("1\n"), 0o644)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("tun: disable ipv6 on %s: %w", name, err)
	}
	return nil
}
