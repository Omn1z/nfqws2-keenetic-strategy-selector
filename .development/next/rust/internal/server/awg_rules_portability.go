package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/services/awgroute"
)

func readAWGRoutingTransferJSON(w http.ResponseWriter, r *http.Request, out any) error {
	reader := http.MaxBytesReader(w, r.Body, awgroute.AWGRoutingRequestLimit)
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	return awgroute.DecodeAWGRoutingJSON(raw, out, awgroute.AWGRoutingRequestLimit)
}

func awgRoutingTransferError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		status = http.StatusRequestEntityTooLarge
	}
	if errors.Is(err, awgroute.ErrAWGRoutingPolicyConflict) {
		status = http.StatusConflict
	}
	httpErr(w, status, err)
}

func (s *Server) awg2RulesExport(w http.ResponseWriter, r *http.Request) {
	var draft *awg.RoutingConfig
	if r.Method == http.MethodPost {
		var in struct {
			Routing *awg.RoutingConfig `json:"routing"`
		}
		if err := readAWGRoutingTransferJSON(w, r, &in); err != nil {
			awgRoutingTransferError(w, err)
			return
		}
		if in.Routing == nil {
			awgRoutingTransferError(w, fmt.Errorf("routing обязателен"))
			return
		}
		draft = in.Routing
	}
	document, err := s.app.AWG2ExportRoutingRules(draft)
	if err != nil {
		awgRoutingTransferError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, document)
}

func (s *Server) awg2RulesImportPreview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Document json.RawMessage `json:"document"`
	}
	if err := readAWGRoutingTransferJSON(w, r, &in); err != nil {
		awgRoutingTransferError(w, err)
		return
	}
	plan, err := s.app.AWG2PreviewRoutingRules(in.Document)
	if err != nil {
		awgRoutingTransferError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) awg2RulesImport(w http.ResponseWriter, r *http.Request) {
	var in awgroute.AWGRoutingImportRequest
	if err := readAWGRoutingTransferJSON(w, r, &in); err != nil {
		awgRoutingTransferError(w, err)
		return
	}
	result, err := s.app.AWG2ImportRoutingRules(in)
	if err != nil {
		awgRoutingTransferError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
