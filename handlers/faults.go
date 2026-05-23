package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// FaultConfig models the user-injectable fault knobs that bend
// fakeaws's normally-deterministic behavior toward what real AWS
// users actually experience: eventual-consistency latency, throttling,
// transient 5xx. Each knob defaults to its zero value (no fault), so
// pre-S49 fakeaws behavior is preserved by default.
//
// Per concepts.md § "Anti-patterns explicitly forbidden" — fakeaws
// stays synchronous and deterministic unless the test/scenario
// explicitly asks for non-determinism via POST /mock/faults. Resetting
// (POST /mock/reset) clears the fault config alongside table state so
// no test leaks knobs into the next test.
type FaultConfig struct {
	// IAMAttachLatencyMS adds a synthetic sleep to IAM AttachRolePolicy
	// (and DetachRolePolicy) responses, simulating real Cloud IAM's
	// 5-30s eventual-consistency window between an attach call and the
	// new permissions being visible to downstream services. The most
	// common AWS footgun this surfaces is "I attached the policy and
	// the next EC2 call still fails with AccessDenied" — exactly the
	// pattern a retry-and-backoff training scenario should exercise.
	IAMAttachLatencyMS int64 `json:"iam_attach_latency_ms,omitempty"`
}

// faultState is the package-level holder for the active FaultConfig.
// Mutex-protected because /mock/faults POST and per-request handlers
// race naturally. Cleared by app.repo.Reset() via clearFaults().
type faultState struct {
	mu  sync.RWMutex
	cfg FaultConfig
}

func (s *faultState) get() FaultConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *faultState) set(c FaultConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = c
}

// registerFaultRoutes attaches the /mock/faults endpoints. Mounted
// under the same /mock prefix as the existing admin routes (state,
// reset, snapshot, restore) so callers configure faults via the same
// admin surface they already know.
func (app *Application) registerFaultRoutes(r chi.Router) {
	r.Route("/mock/faults", func(mr chi.Router) {
		mr.Get("/", app.handleGetFaults)
		mr.Post("/", app.handleSetFaults)
	})
}

func (app *Application) handleGetFaults(w http.ResponseWriter, _ *http.Request) {
	writeJSONStatus(w, http.StatusOK, app.faults.get())
}

func (app *Application) handleSetFaults(w http.ResponseWriter, r *http.Request) {
	var cfg FaultConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{
			"status":  "error",
			"message": "invalid fault config JSON: " + err.Error(),
		})
		return
	}
	if cfg.IAMAttachLatencyMS < 0 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{
			"status":  "error",
			"message": "iam_attach_latency_ms must be non-negative",
		})
		return
	}
	app.faults.set(cfg)
	writeJSONStatus(w, http.StatusOK, app.faults.get())
}

// applyIAMAttachLatency sleeps the configured number of milliseconds
// when the IAMAttachLatencyMS knob is non-zero. Called from the IAM
// attach/detach handlers BEFORE writing the success response — the
// underlying repository mutation has already committed, so the delay
// only affects when the caller learns about the attachment, which is
// exactly how real AWS eventual consistency presents itself.
func (app *Application) applyIAMAttachLatency() {
	ms := app.faults.get().IAMAttachLatencyMS
	if ms <= 0 {
		return
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
}
