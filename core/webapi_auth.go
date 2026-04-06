package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
	"golang.org/x/crypto/bcrypt"
)

const (
	authCookieName  = "evilginx_session"
	authTokenPrefix = "auth_session:"
	sessionTTLHours = 24

	maxLoginAttempts = 5
	loginWindowSecs  = 300 // 5 minutes
)

// loginAttempt tracks failed login attempts per IP for rate limiting.
type loginAttempt struct {
	count   int
	resetAt time.Time
}

var loginRateLimiter sync.Map // map[string]loginAttempt

// generateToken creates a cryptographically random hex token.
func generateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// initAuth creates the default admin user on first run if no users exist.
func (w *WebAPI) initAuth() {
	users, err := w.db.ListUsers()
	if err != nil || len(users) == 0 {
		pass, err := generateToken(16)
		if err != nil {
			log.Error("webapi: failed to generate admin password: %v", err)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			log.Error("webapi: failed to hash admin password: %v", err)
			return
		}
		_, err = w.db.CreateUser("admin", string(hash), "admin")
		if err != nil {
			log.Error("webapi: failed to create admin user: %v", err)
			return
		}
		w.adminPass = pass
		log.Important("==============================================")
		log.Important("  Web Admin default credentials:")
		log.Important("  Username: admin")
		log.Important("  Password: %s", pass)
		log.Important("==============================================")
	}
}

// storeAuthSession saves a session token in BuntDB mapped to a username.
func (w *WebAPI) storeAuthSession(token string, username string) error {
	return w.db.StoreAuthToken(token, username)
}

// getAuthSession retrieves the username for a given session token.
func (w *WebAPI) getAuthSession(token string) (string, error) {
	return w.db.GetAuthToken(token)
}

// deleteAuthSession removes a session token from BuntDB.
func (w *WebAPI) deleteAuthSession(token string) error {
	return w.db.DeleteAuthToken(token)
}

// getUserFromRequest extracts the authenticated user from the request cookie.
func (w *WebAPI) getUserFromRequest(req *http.Request) (*database.User, error) {
	cookie, err := req.Cookie(authCookieName)
	if err != nil {
		return nil, fmt.Errorf("no session cookie")
	}
	username, err := w.getAuthSession(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid session token")
	}
	user, err := w.db.GetUserByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// requireAuth wraps an http.HandlerFunc with authentication checking.
func (w *WebAPI) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		_, err := w.getUserFromRequest(req)
		if err != nil {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(rw).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		next(rw, req)
	}
}

// requireAdmin wraps an http.HandlerFunc with admin role checking.
func (w *WebAPI) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		user, err := w.getUserFromRequest(req)
		if err != nil {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(rw).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		if user.Role != "admin" {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusForbidden)
			json.NewEncoder(rw).Encode(map[string]string{"error": "admin access required"})
			return
		}
		next(rw, req)
	}
}

// requireOperator wraps an http.HandlerFunc requiring role admin or operator.
// Viewer-role users are denied write/mutation endpoints.
func (w *WebAPI) requireOperator(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		user, err := w.getUserFromRequest(req)
		if err != nil {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(rw).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		if user.Role != "admin" && user.Role != "operator" {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusForbidden)
			json.NewEncoder(rw).Encode(map[string]string{"error": "operator or admin access required"})
			return
		}
		next(rw, req)
	}
}

// getClientIP extracts the client IP from the request.
func getClientIP(req *http.Request) string {
	forwarded := req.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	// Strip port from RemoteAddr
	addr := req.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// handleLogin handles POST /api/auth/login
func (w *WebAPI) handleLogin(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit by IP: max 5 attempts per 5 minutes
	clientIP := getClientIP(req)
	now := time.Now()
	if v, ok := loginRateLimiter.Load(clientIP); ok {
		attempt := v.(loginAttempt)
		if now.Before(attempt.resetAt) && attempt.count >= maxLoginAttempts {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(rw).Encode(map[string]string{"error": "too many login attempts, try again later"})
			return
		}
		if now.After(attempt.resetAt) {
			loginRateLimiter.Store(clientIP, loginAttempt{count: 0, resetAt: now.Add(loginWindowSecs * time.Second)})
		}
	}

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	// recordFailedAttempt increments the rate-limit counter for this IP
	recordFailedAttempt := func() {
		v, _ := loginRateLimiter.LoadOrStore(clientIP, loginAttempt{count: 0, resetAt: now.Add(loginWindowSecs * time.Second)})
		attempt := v.(loginAttempt)
		attempt.count++
		loginRateLimiter.Store(clientIP, attempt)
	}

	user, err := w.db.GetUserByUsername(payload.Username)
	if err != nil {
		recordFailedAttempt()
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(map[string]string{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(payload.Password)); err != nil {
		recordFailedAttempt()
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(map[string]string{"error": "invalid credentials"})
		return
	}

	// Successful login — clear rate limit counter
	loginRateLimiter.Delete(clientIP)

	token, err := generateToken(32)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(rw).Encode(map[string]string{"error": "failed to create session"})
		return
	}

	if err := w.storeAuthSession(token, user.Username); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(rw).Encode(map[string]string{"error": "failed to store session"})
		return
	}

	// Update last login
	user.LastLogin = time.Now().UTC().Unix()
	w.db.UpdateUser(user.Id, user)

	http.SetCookie(rw, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   sessionTTLHours * 3600,
	})

	clientIP = getClientIP(req)
	w.db.CreateAuditEntry(user.Username, "login", "User logged in", clientIP)
	log.Info("webapi: user '%s' logged in from %s", user.Username, clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]interface{}{
		"message":  "login successful",
		"username": user.Username,
		"role":     user.Role,
	})
}

// handleLogoutAPI handles POST /api/auth/logout
func (w *WebAPI) handleLogoutAPI(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "logged out"})
}

// handleAuthCheck handles GET /api/auth/check
func (w *WebAPI) handleAuthCheck(rw http.ResponseWriter, req *http.Request) {
	user, err := w.getUserFromRequest(req)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(map[string]string{"error": "not authenticated"})
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      user.Username,
		"role":          user.Role,
	})
}

// handleChangePassword handles POST /api/auth/change-password
func (w *WebAPI) handleChangePassword(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := w.getUserFromRequest(req)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	var payload struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(payload.OldPassword)); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(rw).Encode(map[string]string{"error": "current password is incorrect"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(payload.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(rw).Encode(map[string]string{"error": "failed to hash password"})
		return
	}

	user.PasswordHash = string(hash)
	if err := w.db.UpdateUser(user.Id, user); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(rw).Encode(map[string]string{"error": "failed to update password"})
		return
	}

	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(user.Username, "change_password", "Password changed", clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "password changed successfully"})
}

// handleListUsers handles GET /api/users (admin only)
func (w *WebAPI) handleListUsers(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	users, err := w.db.ListUsers()
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(rw).Encode(map[string]string{"error": "failed to list users"})
		return
	}

	// Strip password hashes from response
	type safeUser struct {
		Id        int    `json:"id"`
		Username  string `json:"username"`
		Role      string `json:"role"`
		CreatedAt int64  `json:"created_at"`
		LastLogin int64  `json:"last_login"`
	}
	safe := make([]safeUser, 0, len(users))
	for _, u := range users {
		safe = append(safe, safeUser{
			Id:        u.Id,
			Username:  u.Username,
			Role:      u.Role,
			CreatedAt: u.CreatedAt,
			LastLogin: u.LastLogin,
		})
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(safe)
}

// handleCreateUser handles POST /api/users (admin only)
func (w *WebAPI) handleCreateUser(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if payload.Username == "" || payload.Password == "" {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "username and password are required"})
		return
	}

	if payload.Role == "" {
		payload.Role = "operator"
	}
	if payload.Role != "admin" && payload.Role != "operator" && payload.Role != "viewer" {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "role must be admin, operator, or viewer"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(rw).Encode(map[string]string{"error": "failed to hash password"})
		return
	}

	user, err := w.db.CreateUser(payload.Username, string(hash), payload.Role)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusConflict)
		json.NewEncoder(rw).Encode(map[string]string{"error": err.Error()})
		return
	}

	adminUser, _ := w.getUserFromRequest(req)
	adminName := "unknown"
	if adminUser != nil {
		adminName = adminUser.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(adminName, "create_user", fmt.Sprintf("Created user '%s' with role '%s'", user.Username, user.Role), clientIP)

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusCreated)
	json.NewEncoder(rw).Encode(map[string]interface{}{
		"message":  "user created",
		"id":       user.Id,
		"username": user.Username,
		"role":     user.Role,
	})
}

// handleDeleteUser handles DELETE /api/users (admin only)
func (w *WebAPI) handleDeleteUser(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodDelete {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Id int `json:"id"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	target, err := w.db.GetUserById(payload.Id)
	if err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusNotFound)
		json.NewEncoder(rw).Encode(map[string]string{"error": "user not found"})
		return
	}

	// Prevent deleting yourself
	currentUser, _ := w.getUserFromRequest(req)
	if currentUser != nil && currentUser.Id == target.Id {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(rw).Encode(map[string]string{"error": "cannot delete your own account"})
		return
	}

	if err := w.db.DeleteUser(payload.Id); err != nil {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(rw).Encode(map[string]string{"error": "failed to delete user"})
		return
	}

	adminName := "unknown"
	if currentUser != nil {
		adminName = currentUser.Username
	}
	clientIP := getClientIP(req)
	w.db.CreateAuditEntry(adminName, "delete_user", fmt.Sprintf("Deleted user '%s'", target.Username), clientIP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"message": "user deleted"})
}
