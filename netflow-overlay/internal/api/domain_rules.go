package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"mikrotik-home-netflow-plus/internal/engine"
	"mikrotik-home-netflow-plus/internal/store"
)

func (s *Server) domainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, engine.ErrInvalidDomainRule):
		fail(w, http.StatusBadRequest, "invalid domain rule")
	case errors.Is(err, engine.ErrDomainRuleConflict):
		fail(w, http.StatusConflict, "conflicting domain rule")
	case errors.Is(err, store.ErrDomainRuleNotFound):
		fail(w, http.StatusNotFound, "domain rule not found")
	case errors.Is(err, engine.ErrDomainUnavailable):
		fail(w, http.StatusServiceUnavailable, "domain intelligence unavailable")
	default:
		s.log.Error("domain rule request failed", "err", err)
		fail(w, http.StatusInternalServerError, "internal error")
	}
}
func (s *Server) handleDomainApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.eng.DomainApplications()
	if err != nil {
		s.domainError(w, err)
		return
	}
	writeJSON(w, apps)
}

func (s *Server) handleDomainUnknown(w http.ResponseWriter, r *http.Request) {
	to := time.Now().Truncate(time.Hour).Add(time.Hour).Unix()
	from := to - 7*24*3600
	rows, err := s.st.HistoricalDomains(from, to, 50)
	if err != nil {
		s.domainError(w, err)
		return
	}
	writeJSON(w, map[string]any{"from": from, "to": to, "items": rows})
}
func (s *Server) handleDomainRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.eng.DomainRules()
	if err != nil {
		s.domainError(w, err)
		return
	}
	writeJSON(w, rules)
}

func (s *Server) handleBuiltinDomainRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.eng.BuiltinDomainRules()
	if err != nil {
		s.domainError(w, err)
		return
	}
	writeJSON(w, rules)
}

func (s *Server) handleDomainRuleTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	match, label, err := s.eng.TestDomain(body.Domain)
	if err != nil {
		s.domainError(w, err)
		return
	}
	writeJSON(w, map[string]any{"match": match, "application": label})
}
func (s *Server) handleDomainRuleCreate(w http.ResponseWriter, r *http.Request) {
	var rule store.UserDomainRule
	if !readJSON(w, r, &rule) {
		return
	}
	rule.ID = 0
	saved, err := s.eng.SaveDomainRule(rule)
	if err != nil {
		s.domainError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, saved)
}
func domainRuleID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, store.ErrDomainRuleNotFound
	}
	return id, nil
}
func (s *Server) handleDomainRuleUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := domainRuleID(r)
	if err != nil {
		s.domainError(w, err)
		return
	}
	var rule store.UserDomainRule
	if !readJSON(w, r, &rule) {
		return
	}
	rule.ID = id
	saved, err := s.eng.SaveDomainRule(rule)
	if err != nil {
		s.domainError(w, err)
		return
	}
	writeJSON(w, saved)
}
func (s *Server) handleDomainRuleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := domainRuleID(r)
	if err != nil {
		s.domainError(w, err)
		return
	}
	if err = s.eng.DeleteDomainRule(id); err != nil {
		s.domainError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
