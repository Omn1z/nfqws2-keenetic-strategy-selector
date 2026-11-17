package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"nfqws2strategy/internal/services/awgroute"
)

func (s *Server) awg2SetEndpointBackups(w http.ResponseWriter, r *http.Request) {
	serveAWG2EndpointBackups(w, r, s.app.AWG2SetEndpointBackups, s.app.AWG2StatusView)
}

func serveAWG2EndpointBackups(w http.ResponseWriter, r *http.Request, save func(string, []string) error, status func() awgroute.AWG2Status) {
	var in struct {
		Endpoints *[]string `json:"endpoint_backups"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" || in.Endpoints == nil {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("Укажите подключение и список endpoint_backups; для удаления резервных адресов передайте []"))
		return
	}
	err := save(id, *in.Endpoints)
	var uncertain *awgroute.EndpointBackupsPersistenceUncertainError
	if errors.As(err, &uncertain) {
		httpErr(w, http.StatusConflict, err)
		return
	}
	var committed *awgroute.EndpointBackupsCommittedError
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
