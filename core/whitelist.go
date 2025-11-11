package core

import (
  "bufio"
  "fmt"
  "net"
  "os"
  "strings"

  "github.com/kgretzky/evilginx2/log"
)

type AllowIP struct {
  ipv4 net.IP
  mask *net.IPNet
}

type Whitelist struct {
  ips        map[string]*AllowIP
  masks      []*AllowIP
  configPath string
  enabled    bool
  verbose    bool
}

func NewWhitelist(path string) (*Whitelist, error) {
  f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
  if err != nil {
    return nil, err
  }
  defer f.Close()

  wl := &Whitelist{
    ips:        make(map[string]*AllowIP),
    configPath: path,
    enabled:    false,
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
          wl.masks = append(wl.masks, &AllowIP{ipv4: ipv4, mask: mask})
        } else {
          log.Error("whitelist: invalid ip/mask address: %s", l)
        }
      } else {
        ipv4 := net.ParseIP(l)
        if ipv4 != nil {
          wl.ips[ipv4.String()] = &AllowIP{ipv4: ipv4, mask: nil}
        } else {
          log.Error("whitelist: invalid ip address: %s", l)
        }
      }
    }
  }

  log.Info("whitelist: loaded %d ip addresses and %d ip masks", len(wl.ips), len(wl.masks))
  return wl, nil
}

func (wl *Whitelist) GetStats() (int, int) {
  return len(wl.ips), len(wl.masks)
}

func (wl *Whitelist) AddIP(ip string) error {
  if wl.IsWhitelisted(ip) {
    return nil
  }

  ipv4 := net.ParseIP(ip)
  if ipv4 != nil {
    wl.ips[ipv4.String()] = &AllowIP{ipv4: ipv4, mask: nil}
  } else {
    return fmt.Errorf("invalid ip address: %s", ip)
  }

  // write to file
  f, err := os.OpenFile(wl.configPath, os.O_APPEND|os.O_WRONLY, 0644)
  if err != nil {
    return err
  }
  defer f.Close()

  _, err = f.WriteString(ipv4.String() + "\n")
  if err != nil {
    return err
  }

  return nil
}

func (wl *Whitelist) RemoveIP(ip string) error {
  ipv4 := net.ParseIP(ip)
  if ipv4 == nil {
    return fmt.Errorf("invalid ip address: %s", ip)
  }

  // remove from memory
  delete(wl.ips, ipv4.String())

  // rewrite file without this IP
  f, err := os.OpenFile(wl.configPath, os.O_RDONLY, 0644)
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
  fw, err := os.OpenFile(wl.configPath, os.O_WRONLY|os.O_TRUNC, 0644)
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

func (wl *Whitelist) IsWhitelisted(ip string) bool {
  ipv4 := net.ParseIP(ip)
  if ipv4 == nil {
    return false
  }

  // Always allow localhost
  if ip == "127.0.0.1" || ip == "::1" {
    return true
  }

  if _, ok := wl.ips[ip]; ok {
    return true
  }

  for _, m := range wl.masks {
    if m.mask != nil && m.mask.Contains(ipv4) {
      return true
    }
  }

  return false
}

func (wl *Whitelist) Clear() error {
  wl.ips = make(map[string]*AllowIP)
  wl.masks = []*AllowIP{}

  // clear file
  f, err := os.OpenFile(wl.configPath, os.O_WRONLY|os.O_TRUNC, 0644)
  if err != nil {
    return err
  }
  defer f.Close()

  return nil
}

func (wl *Whitelist) SetEnabled(enabled bool) {
  wl.enabled = enabled
}

func (wl *Whitelist) IsEnabled() bool {
  return wl.enabled
}

func (wl *Whitelist) SetVerbose(verbose bool) {
  wl.verbose = verbose
}

func (wl *Whitelist) IsVerbose() bool {
  return wl.verbose
}

func (wl *Whitelist) GetAllIPs() []string {
  var ips []string

  for ip := range wl.ips {
    ips = append(ips, ip)
  }

  for _, m := range wl.masks {
    if m.mask != nil {
      ips = append(ips, m.mask.String())
    }
  }

  return ips
}

