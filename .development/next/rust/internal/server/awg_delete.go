package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"nfqws2strategy/internal/services/awgroute"
)

// Keep an omitted replacement distinct from an invalid explicit choice: a bad
// transfer request must never fall back to deleting without transferring rules.
func serveAWG2Delete(w http.ResponseWriter, r *http.Request, remove func(string, string) error, status func() awgroute.AWG2Status) {
	id := strings.TrimSpace(r.PathValue("id"))
	replacement := ""
	if values, supplied := r.URL.Query()["replacement_id"]; supplied {
		if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
			httpErr(w, http.StatusBadRequest, fmt.Errorf("Выберите одно подключение для переноса правил"))
			return
		}
		replacement = strings.TrimSpace(values[0])
		if replacement == id {
			httpErr(w, http.StatusBadRequest, fmt.Errorf("Подключение для переноса должно отличаться от удаляемого"))
			return
		}
	}
	if id == "" {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("Не указано удаляемое подключение"))
		return
	}
	err := remove(id, replacement)
	var uncertain *awgroute.DeleteServerPersistenceUncertainError
	if errors.As(err, &uncertain) {
		httpErr(w, http.StatusConflict, err)
		return
	}
	var committed *awgroute.DeleteServerCommittedError
	if err != nil && !errors.As(err, &committed) {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	response := struct {
		awgroute.AWG2Status
		Warning string `json:"warning,omitempty"`
	}{AWG2Status: status()}
	if err != nil {
		response.Warning = err.Error()
	}
	writeJSON(w, http.StatusOK, response)
}
