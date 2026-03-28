package core

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/kgretzky/evilginx2/log"
)

type Nameserver struct {
	srv              *dns.Server
	cfg              *Config
	bind             string
	serial           uint32
	ctx              context.Context
	registeredZones  []string
}

func NewNameserver(cfg *Config) (*Nameserver, error) {
	o := &Nameserver{
		serial:          uint32(time.Now().Unix()),
		cfg:             cfg,
		bind:            fmt.Sprintf("%s:%d", cfg.GetServerBindIP(), cfg.GetDnsPort()),
		ctx:             context.Background(),
		registeredZones: make([]string, 0),
	}

	o.Reset()

	return o, nil
}

// Reset re-registers DNS handlers for all active domains from DomainManager.
func (o *Nameserver) Reset() {
	// Deregister old zones
	for _, zone := range o.registeredZones {
		dns.HandleRemove(zone)
	}
	o.registeredZones = nil

	dm := o.cfg.GetDomainManager()
	if dm == nil {
		return
	}

	domains := dm.GetActiveDomains()
	for _, d := range domains {
		zone := pdom(d)
		dns.HandleFunc(zone, o.handleRequest)
		o.registeredZones = append(o.registeredZones, zone)
	}
}

// Refresh is called by DomainManager when the active domains list changes.
func (o *Nameserver) Refresh(domains []string) {
	// Deregister old zones
	for _, zone := range o.registeredZones {
		dns.HandleRemove(zone)
	}
	o.registeredZones = nil

	for _, d := range domains {
		zone := pdom(d)
		dns.HandleFunc(zone, o.handleRequest)
		o.registeredZones = append(o.registeredZones, zone)
	}
	log.Debug("Nameserver refreshed: %d zones", len(domains))
}

func (o *Nameserver) Start() {
	go func() {
		o.srv = &dns.Server{Addr: o.bind, Net: "udp"}
		if err := o.srv.ListenAndServe(); err != nil {
			log.Fatal("Failed to start nameserver on: %s", o.bind)
		}
	}()
}

func (o *Nameserver) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	externalIP := o.cfg.GetServerExternalIP()
	if externalIP == "" {
		return
	}

	fqdn := strings.ToLower(r.Question[0].Name)

	// Determine which managed domain this query belongs to
	baseDomain := o.matchDomain(fqdn)
	if baseDomain == "" {
		w.WriteMsg(m)
		return
	}

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: pdom(baseDomain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + pdom(baseDomain),
		Mbox:    "hostmaster." + pdom(baseDomain),
		Serial:  o.serial,
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		Minttl:  60,
	}
	m.Ns = []dns.RR{soa}

	switch r.Question[0].Qtype {
	case dns.TypeSOA:
		log.Debug("DNS SOA: " + fqdn)
		m.Answer = append(m.Answer, soa)
	case dns.TypeA:
		log.Debug("DNS A: " + fqdn + " = " + externalIP)
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(externalIP),
		}
		m.Answer = append(m.Answer, rr)
	case dns.TypeNS:
		log.Debug("DNS NS: " + fqdn)
		if fqdn == pdom(baseDomain) {
			for _, i := range []int{1, 2} {
				rr := &dns.NS{
					Hdr: dns.RR_Header{Name: pdom(baseDomain), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns" + strconv.Itoa(i) + "." + pdom(baseDomain),
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	}
	w.WriteMsg(m)
}

// matchDomain finds which managed domain the FQDN belongs to.
func (o *Nameserver) matchDomain(fqdn string) string {
	// Strip trailing dot
	host := strings.TrimSuffix(fqdn, ".")
	dm := o.cfg.GetDomainManager()
	if dm == nil {
		return ""
	}
	domains := dm.GetActiveDomains()
	// Try longest match first
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return d
		}
	}
	return ""
}

func pdom(domain string) string {
	return domain + "."
}
