package lan

import (
	"fmt"
	"net/netip"
	"strings"
)

// Where the rendered files go on the vehicle.
const (
	NetplanPath = "/etc/netplan/40-omp-lan.yaml"
	DnsmasqPath = "/etc/dnsmasq.d/omp-lan.conf"
	EnvPath     = "/etc/default/openmultipath"
	LeasePath   = "/var/lib/misc/dnsmasq.leases"
)

// RenderNetplan writes every segment's address as netplan.
//
// A LAN segment is static and deliberately inert: no DHCP client, and no
// IPv6 router advertisements, for the reason D-026 gives on the WAN side -
// a v6 default route learned from something plugged into the LAN would be
// a way out that bypasses the tunnel. The upstream resolvers go on each
// segment so the router's own lookups keep working the way cloud-init's
// eth0 stanza made them work before this file took it over.
//
// Written by hand rather than through a YAML library: the project takes no
// dependencies, and everything interpolated here has already been through
// Validate, which admits no character YAML would treat specially.
func RenderNetplan(f File) string {
	var b strings.Builder
	b.WriteString("# Written by ompui from " + DefaultPath + " (D-067).\n")
	b.WriteString("# Edit the LAN tab, not this file: it is replaced on every save.\n")
	b.WriteString("network:\n  version: 2\n  ethernets:\n")
	for _, s := range f.Segments {
		fmt.Fprintf(&b, "    %s:\n", s.Interface)
		if s.MAC != "" {
			fmt.Fprintf(&b, "      match:\n        macaddress: %q\n", s.MAC)
			fmt.Fprintf(&b, "      set-name: %q\n", s.Interface)
		}
		fmt.Fprintf(&b, "      addresses:\n      - %q\n", s.Address)
		b.WriteString("      dhcp4: false\n      accept-ra: false\n")
		if len(f.UpstreamDNS) > 0 {
			b.WriteString("      nameservers:\n        addresses:\n")
			for _, u := range f.UpstreamDNS {
				fmt.Fprintf(&b, "        - %s\n", u)
			}
		}
	}
	return b.String()
}

// RenderDnsmasq writes the DHCP and DNS service for every segment.
//
// dnsmasq answers DNS on every LAN, and DHCP only on the segments that have
// it switched on. It binds each LAN address itself (bind-dynamic) rather
// than the wildcard, so it neither collides with systemd-resolved on the
// loopback nor listens on a WAN link, and it follows an address that changes
// without a restart.
//
// Not authoritative. A second DHCP server left running on a segment would
// have its clients refused outright by an authoritative one; without it the
// two only compete for new clients, which is the recoverable failure.
func RenderDnsmasq(f File) string {
	var b strings.Builder
	b.WriteString("# Written by ompui from " + DefaultPath + " (D-067).\n")
	b.WriteString("# Edit the LAN tab, not this file: it is replaced on every save.\n\n")
	b.WriteString("bind-dynamic\nexcept-interface=lo\n")
	for _, s := range f.Segments {
		fmt.Fprintf(&b, "interface=%s\n", s.Interface)
	}

	b.WriteString("\n# Resolver: forward through the tunnel, answer local names from leases.\n")
	b.WriteString("no-resolv\ndomain-needed\nbogus-priv\ncache-size=1000\n")
	for _, u := range f.UpstreamDNS {
		fmt.Fprintf(&b, "server=%s\n", u)
	}
	fmt.Fprintf(&b, "domain=%s\nlocal=/%s/\nexpand-hosts\nlocalise-queries\n", f.Domain, f.Domain)
	for _, s := range f.Segments {
		// router.lan is whichever address of the router the asker can reach.
		fmt.Fprintf(&b, "interface-name=router.%s,%s\n", f.Domain, s.Interface)
	}
	fmt.Fprintf(&b, "dhcp-leasefile=%s\n", LeasePath)

	for _, s := range f.Segments {
		tag := "lan_" + strings.NewReplacer(".", "_", "-", "_").Replace(s.Interface)
		fmt.Fprintf(&b, "\n# %s\n", s.Label())
		if !s.DHCP.Enabled {
			fmt.Fprintf(&b, "no-dhcp-interface=%s\n", s.Interface)
			continue
		}
		pfx, err := netip.ParsePrefix(s.Address)
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "dhcp-range=set:%s,%s,%s,%s,%dm\n",
			tag, s.DHCP.RangeStart, s.DHCP.RangeEnd, netmask(pfx.Bits()), s.DHCP.LeaseMinutes)
		fmt.Fprintf(&b, "dhcp-option=tag:%s,option:router,%s\n", tag, pfx.Addr())
		if s.DHCP.DNSMode == DNSCustom {
			fmt.Fprintf(&b, "dhcp-option=tag:%s,option:dns-server,%s\n", tag, strings.Join(s.DHCP.DNSServers, ","))
		} else {
			fmt.Fprintf(&b, "dhcp-option=tag:%s,option:dns-server,%s\n", tag, pfx.Addr())
		}
		fmt.Fprintf(&b, "dhcp-option=tag:%s,option:domain-name,%s\n", tag, f.Domain)
		for _, r := range s.DHCP.Reservations {
			if r.Hostname != "" {
				fmt.Fprintf(&b, "dhcp-host=%s,%s,%s\n", r.MAC, r.IP, r.Hostname)
			} else {
				fmt.Fprintf(&b, "dhcp-host=%s,%s\n", r.MAC, r.IP)
			}
		}
	}
	return b.String()
}

func netmask(bits int) string {
	m := ^uint32(0) << (32 - bits)
	return fromV4(m).String()
}
