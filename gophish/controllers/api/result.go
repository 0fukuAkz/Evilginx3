package api

import (
	"encoding/json"
	"net/http"
	"net/url"

	log "github.com/kgretzky/evilginx2/gophish/logger"
	"github.com/kgretzky/evilginx2/gophish/models"
	"github.com/gorilla/mux"
)

const (
	RESULT_ACTION_OPEN   = 0
	RESULT_ACTION_CLICK  = iota
	RESULT_ACTION_SUBMIT = iota
)

type resultData struct {
	IP        string     `json:"address"`
	UserAgent string     `json:"user-agent"`
	Payload   url.Values `json:"payload"`
}

func (as *Server) ResultOpen(w http.ResponseWriter, r *http.Request) {
	as.handleResult(RESULT_ACTION_OPEN, w, r)
}

func (as *Server) ResultClick(w http.ResponseWriter, r *http.Request) {
	as.handleResult(RESULT_ACTION_CLICK, w, r)
}

func (as *Server) ResultSubmit(w http.ResponseWriter, r *http.Request) {
	as.handleResult(RESULT_ACTION_SUBMIT, w, r)
}

func (as *Server) handleResult(action int, w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == "POST":
		vars := mux.Vars(r)
		id := vars["id"]

		c := resultData{}
		// Put the request into a campaign
		err := json.NewDecoder(r.Body).Decode(&c)
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: "Invalid JSON structure"}, http.StatusBadRequest)
			return
		}

		d := models.EventDetails{
			Payload: url.Values{},
			Browser: make(map[string]string),
		}
		d.Browser["address"] = c.IP
		d.Browser["user-agent"] = c.UserAgent
		d.Payload = c.Payload

		rs, err := models.GetResult(id)
		if err != nil {
			log.Error(err)
			JSONResponse(w, models.Response{Success: false, Message: "Result not found"}, http.StatusNotFound)
			return
		}

		switch action {
		case RESULT_ACTION_OPEN:
			err = rs.HandleEmailOpened(d)
		case RESULT_ACTION_CLICK:
			err = rs.HandleClickedLink(d)
		case RESULT_ACTION_SUBMIT:
			err = rs.HandleFormSubmit(d)
		}
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: "Error updating result"}, http.StatusInternalServerError)
			return
		}
	}
}
