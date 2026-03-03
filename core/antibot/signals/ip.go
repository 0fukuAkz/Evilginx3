package signals

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/kgretzky/evilginx2/log"
)

// IPNet defines an IP with an optional mask
type IPNet struct {
	ipv4 net.IP
	mask *net.IPNet
}

// IPSignal manages blacklists, whitelists, and override IPs.
type IPSignal struct {
	blacklistIPs   map[string]*IPNet
	blacklistMasks []*IPNet
	whitelistIPs   map[string]*IPNet
	whitelistMasks []*IPNet

	blPath string
	wlPath string

	blMode    string
	wlEnabled bool

	overrideIPs []string
	verbose     bool
}

// NewIPSignal initializes the IP signal module.
func NewIPSignal(blPath, wlPath string) (*IPSignal, error) {
	ip := &IPSignal{
		blacklistIPs:   make(map[string]*IPNet),
		blacklistMasks: make([]*IPNet, 0),
		whitelistIPs:   make(map[string]*IPNet),
		whitelistMasks: make([]*IPNet, 0),
		blPath:         blPath,
		wlPath:         wlPath,
		blMode:         "off",
		wlEnabled:      false,
		verbose:        true,
	}

	ip.loadList(blPath, true)
	ip.loadList(wlPath, false)

	return ip, nil
}

func (ip *IPSignal) loadList(path string, isBlacklist bool) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		if n := strings.Index(l, ";"); n > -1 {
			l = l[:n]
		}
		l = strings.TrimSpace(l)

		if len(l) > 0 {
			if strings.Contains(l, "/") {
				ipv4, mask, err := net.ParseCIDR(l)
				if err == nil {
					if isBlacklist {
						ip.blacklistMasks = append(ip.blacklistMasks, &IPNet{ipv4: ipv4, mask: mask})
					} else {
						ip.whitelistMasks = append(ip.whitelistMasks, &IPNet{ipv4: ipv4, mask: mask})
					}
				} else {
					log.Error("ip_signal: invalid ip/mask address: %s", l)
				}
			} else {
				ipv4 := net.ParseIP(l)
				if ipv4 != nil {
					if isBlacklist {
						ip.blacklistIPs[ipv4.String()] = &IPNet{ipv4: ipv4, mask: nil}
					} else {
						ip.whitelistIPs[ipv4.String()] = &IPNet{ipv4: ipv4, mask: nil}
					}
				} else {
					log.Error("ip_signal: invalid ip address: %s", l)
				}
			}
		}
	}

	if isBlacklist {
		log.Debug("blacklist: loaded %d ip addresses and %d ip masks", len(ip.blacklistIPs), len(ip.blacklistMasks))
	} else {
		log.Debug("whitelist: loaded %d ip addresses and %d ip masks", len(ip.whitelistIPs), len(ip.whitelistMasks))
	}
}

// IPVerdict represents the outcome of the IP signal evaluation
type IPVerdict struct {
	IsWhitelisted bool
	IsBlacklisted bool
	Reasons       []string
}

// Evaluate checks if the IP is blacklisted or whitelisted
func (ip *IPSignal) Evaluate(clientIP string) IPVerdict {
	verdict := IPVerdict{
		IsWhitelisted: false,
		IsBlacklisted: false,
	}

	// 1. Check Override IPs (always whitelist)
	for _, override := range ip.overrideIPs {
		if clientIP == override {
			verdict.IsWhitelisted = true
			verdict.Reasons = append(verdict.Reasons, "ip_in_override_list")
			return verdict
		}
	}

	// 2. Check Whitelist
	if ip.IsWhitelisted(clientIP) {
		verdict.IsWhitelisted = true
		verdict.Reasons = append(verdict.Reasons, "ip_in_whitelist")
		return verdict
	}

	// 3. Check Blacklist
	if ip.blMode != "off" && ip.IsBlacklisted(clientIP) {
		verdict.IsBlacklisted = true
		verdict.Reasons = append(verdict.Reasons, "ip_in_blacklist")
	}

	return verdict
}

// SetOptions configures mode and overrides
func (ip *IPSignal) SetOptions(blMode string, wlEnabled bool, overrideIPs []string) {
	ip.blMode = blMode
	ip.wlEnabled = wlEnabled
	ip.overrideIPs = overrideIPs
}

// AddIP adds an IP to either blacklist or whitelist
func (ip *IPSignal) AddIP(ipStr string, isBlacklist bool) error {
	if isBlacklist && ip.IsBlacklisted(ipStr) {
		return nil
	}
	if !isBlacklist && ip.IsWhitelisted(ipStr) {
		return nil
	}

	var ipv4 net.IP
	var mask *net.IPNet
	var err error

	if strings.Contains(ipStr, "/") {
		ipv4, mask, err = net.ParseCIDR(ipStr)
		if err != nil {
			return fmt.Errorf("invalid ip/mask address: %s", ipStr)
		}
		if isBlacklist {
			ip.blacklistMasks = append(ip.blacklistMasks, &IPNet{ipv4: ipv4, mask: mask})
		} else {
			ip.whitelistMasks = append(ip.whitelistMasks, &IPNet{ipv4: ipv4, mask: mask})
		}
	} else {
		ipv4 = net.ParseIP(ipStr)
		if ipv4 != nil {
			if isBlacklist {
				ip.blacklistIPs[ipv4.String()] = &IPNet{ipv4: ipv4, mask: nil}
			} else {
				ip.whitelistIPs[ipv4.String()] = &IPNet{ipv4: ipv4, mask: nil}
			}
		} else {
			return fmt.Errorf("invalid ip address: %s", ipStr)
		}
	}

	// append to file
	path := ip.blPath
	if !isBlacklist {
		path = ip.wlPath
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(ipStr + "\n")
	return err
}

func (ip *IPSignal) IsBlacklisted(ipStr string) bool {
	ipv4 := net.ParseIP(ipStr)
	if ipv4 == nil {
		return false
	}

	if _, ok := ip.blacklistIPs[ipv4.String()]; ok {
		return true
	}
	for _, m := range ip.blacklistMasks {
		if m.mask != nil && m.mask.Contains(ipv4) {
			return true
		}
	}
	return false
}

func (ip *IPSignal) IsWhitelisted(ipStr string) bool {
	ipv4 := net.ParseIP(ipStr)
	if ipv4 == nil {
		return false
	}

	if ipStr == "127.0.0.1" || ipStr == "::1" {
		return true
	}

	if !ip.wlEnabled {
		return false // Or true if not explicitly required, but previous code only checked if enabled in proxy_middleware
	}

	if _, ok := ip.whitelistIPs[ipStr]; ok {
		return true
	}

	for _, m := range ip.whitelistMasks {
		if m.mask != nil && m.mask.Contains(ipv4) {
			return true
		}
	}
	return false
}

// (We can add RemoveIP, Clear, etc. if needed later, adapting whitelist implementation)
