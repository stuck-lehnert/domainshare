package webapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/stuck-lehnert/domainshare/internal/accesscontrol"
	"github.com/stuck-lehnert/domainshare/internal/webauth"
)

func (api AdminAPI) startAction(w http.ResponseWriter, r *http.Request, action string, user webauth.Session) {
	if api.Action == nil {
		writeError(w, http.StatusServiceUnavailable, "Die Aktion ist nicht verfügbar")
		return
	}

	if err := api.Action(r.Context(), action); err != nil {
		var conflict accesscontrol.Conflict
		if errors.As(err, &conflict) {
			writeError(w, http.StatusConflict, conflict.Error())
		} else {
			log.Printf("[web] could not start %s", action)
			writeError(w, http.StatusInternalServerError, "Aktion konnte nicht gestartet werden")
		}
		return
	}

	log.Printf("[web] %q started %s", user.Username, action)
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "action": action})
}
