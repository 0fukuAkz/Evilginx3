package api

import (
	"net/http"

	"github.com/kgretzky/evilginx2/gophish/auth"
	ctx "github.com/kgretzky/evilginx2/gophish/context"
	"github.com/kgretzky/evilginx2/gophish/models"
)

// Reset (/api/reset) resets the currently authenticated user's API key
func (as *Server) Reset(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == "POST":
		u := ctx.Get(r, "user").(models.User)
		u.ApiKey = auth.GenerateSecureKey(auth.APIKeyLength)
		err := models.PutUser(&u)
		if err != nil {
			http.Error(w, "Error setting API Key", http.StatusInternalServerError)
		} else {
			JSONResponse(w, models.Response{Success: true, Message: "API Key successfully reset!", Data: u.ApiKey}, http.StatusOK)
		}
	}
}
