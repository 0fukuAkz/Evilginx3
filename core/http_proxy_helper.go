package core

import (
	"net"
	"net/http"
	"strings"
)

func (p *HttpProxy) getRealIP(req *http.Request) string {
	from_ip := strings.SplitN(req.RemoteAddr, ":", 2)[0]

	// Check if configured TrustedProxies match the source IP
	trustedProxies := p.cfg.GetTrustedProxies()
	isTrusted := false
	if len(trustedProxies) > 0 {
		for _, cidr := range trustedProxies {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err == nil {
				ip := net.ParseIP(from_ip)
				if ip != nil && ipnet.Contains(ip) {
					isTrusted = true
					break
				}
			} else {
				// Handle single IP
				if from_ip == cidr {
					isTrusted = true
					break
				}
			}
		}
	}

	if isTrusted {
		proxyHeaders := []string{"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "Connecting-IP", "True-Client-IP", "Client-IP"}
		for _, h := range proxyHeaders {
			origin_ip := req.Header.Get(h)
			if origin_ip != "" {
				// Check for multiple IPs in X-Forwarded-For
				ips := strings.Split(origin_ip, ",")
				if len(ips) > 0 {
					return strings.TrimSpace(ips[0])
				}
				return strings.SplitN(origin_ip, ":", 2)[0]
			}
		}
	}

	return from_ip
}
