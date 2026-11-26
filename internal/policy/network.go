package policy

import (
	"fmt"
	"net"
	"strings"
)

// NetworkArtifacts renders kernel-level enforcement for the guest:
// an nftables ruleset that fails closed, and /etc/hosts pins so the guest
// needs no DNS server. Hostnames are resolved by the controller, not the guest.
func (p *Policy) NetworkArtifacts() (rules, hosts string, err error) {
	var b, h strings.Builder
	b.WriteString("flush ruleset\n")
	b.WriteString("table ip tracefuse {\n  chain output {\n")
	b.WriteString("    type filter hook output priority 0; policy drop;\n")
	b.WriteString("    oif \"lo\" accept\n")
	b.WriteString("    ct state established,related accept\n")
	b.WriteString("    ip daddr 169.254.0.0/16 drop\n")
	for _, d := range p.Network.Allow {
		host, port, err := net.SplitHostPort(d)
		if err != nil {
			return "", "", fmt.Errorf("bad destination %q: %w", d, err)
		}
		ips := []string{host}
		if net.ParseIP(host) == nil {
			if ips, err = net.LookupHost(host); err != nil {
				return "", "", fmt.Errorf("resolve %s: %w", host, err)
			}
		}
		for _, ip := range ips {
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.To4() == nil {
				continue // MVP: IPv4 only
			}
			if ip != host {
				fmt.Fprintf(&h, "%s %s\n", ip, host)
			}
			fmt.Fprintf(&b, "    ip daddr %s tcp dport %s accept\n", ip, port)
		}
	}
	b.WriteString("    drop\n  }\n}\n")
	return b.String(), h.String(), nil
}
