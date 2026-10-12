package handlers

// load.go — POST /mock/load: replaces every row with a recorded read
// (ADR-0041) in one transaction, through the registered loaders.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"

	"github.com/redscaresu/fakeaws/repository"
)

// loadEnvelope is ADR-0041's recorded read. Its account and region are
// the identity a load stores, and the ones every row it writes is under.
type loadEnvelope struct {
	Account    string         `json:"account"`
	Region     string         `json:"region"`
	Timestamp  string         `json:"timestamp"`
	DurationMS int64          `json:"duration_ms"`
	Calls      int            `json:"calls"`
	Exchanges  []loadExchange `json:"exchanges"`
}

// loadExchange is one recorded exchange: a read-set entry, the wire
// status and the raw response body.
type loadExchange struct {
	readSetEntry
	Status int    `json:"status"`
	Body   string `json:"body"`
}

func (ex *loadExchange) key() LoadKey { return LoadKey{ex.Service, ex.Action} }

// loadRef names a row by its type (vpc, subnet, role) and id.
type loadRef struct{ Type, ID string }

// loadReference is a row an item references. Unread flags one the
// reader never reads, so no exchange can hold it.
type loadReference struct {
	loadRef
	Unread bool
}

// loadItem is one item a loader wrote: its row, where its recorded
// subtree sits in the exchange's body (Tree.Subtree's path and index),
// and the rows it references.
type loadItem struct {
	loadRef
	Path  string
	Index int
	Refs  []loadReference
}

// loader loads the exchanges of one {service, action}. A loader file,
// handlers/load_<service>_*.go, registers its loaders from init.
type loader struct {
	key LoadKey
	// notFound are the error codes a non-2xx answers when the read
	// found nothing.
	notFound []string
	// requestToken is the request param a next page carries (NextToken,
	// Marker); responseToken is the response field a page answers it in
	// (nextToken, Marker).
	requestToken, responseToken string
	// load writes ex's items as rows through tx, under env's account
	// and, for a region-scoped row, env's region, and returns them.
	load func(tx *repository.LoadTx, env *loadEnvelope, ex *loadExchange) ([]loadItem, error)
	// render reads the rows of ids back through tx and marshals them
	// with the encoder the Describe or Get handler answers with, never
	// from what load decoded.
	render func(tx *repository.LoadTx, ids []string) ([]byte, error)
}

// loaders is the registry, in registration order, which is the order a
// load runs them in: a loader whose rows reference another's registers
// after it.
var loaders []loader

func registerLoader(l loader) {
	if slices.ContainsFunc(loaders, func(have loader) bool { return have.key == l.key }) {
		panic(fmt.Sprintf("loader %s %s registered twice", l.key.Service, l.key.Action))
	}
	loaders = append(loaders, l)
}

// loadAnswer is a load's 200, each part keyed by type: the items
// loaded, the reads that found nothing, and the ids of references no
// exchange held.
type loadAnswer struct {
	Loaded     map[string]int      `json:"loaded"`
	Absent     map[string]int      `json:"absent"`
	Unresolved map[string][]string `json:"unresolved"`
}

// errLoadRefused rolls back a load whose loaders refused an exchange.
var errLoadRefused = errors.New("load refused")

// handleMockLoad replaces every row with a recorded read of at most
// loadMaxBytes (413 over it): 200 with a loadAnswer, or 400 listing
// every refusal, after which nothing has changed.
func (app *Application) handleMockLoad(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, app.loadMaxBytes))
	if errors.As(err, new(*http.MaxBytesError)) {
		writeAdminError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body over -load-max-bytes (%d)", app.loadMaxBytes))
		return
	}
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var env loadEnvelope
	if err := decodeStrict(bytes.NewReader(body), &env); err != nil {
		writeLoadRefused(w, []string{"invalid body: " + err.Error()})
		return
	}
	if refusals := env.refusals(); len(refusals) > 0 {
		writeLoadRefused(w, refusals)
		return
	}
	answer, refusals, err := app.load(&env)
	switch {
	case len(refusals) > 0:
		writeLoadRefused(w, refusals)
	case err != nil:
		log.Printf("POST /mock/load: %v", err)
		writeAdminError(w, http.StatusInternalServerError, "the load could not be written")
	default:
		writeJSONStatus(w, http.StatusOK, answer)
	}
}

// refusals names every field of env that is invalid and every exchange
// no loader is registered for.
func (env *loadEnvelope) refusals() []string {
	var out []string
	if err := CheckAccountID(env.Account); err != nil {
		out = append(out, "account "+err.Error())
	}
	if err := CheckRegion(env.Region); err != nil {
		out = append(out, "region "+err.Error())
	}
	for i := range env.Exchanges {
		key := env.Exchanges[i].key()
		if !slices.ContainsFunc(loaders, func(l loader) bool { return l.key == key }) {
			out = append(out, fmt.Sprintf("exchange %d: no loader for %s %s", i, key.Service, key.Action))
		}
	}
	return out
}

// load replaces every row with env's in one transaction, running the
// loaders in registry order, each on its exchanges in recorded order.
// It holds identityMu exclusively, so no request reads between the
// delete and the commit.
func (app *Application) load(env *loadEnvelope) (*loadAnswer, []string, error) {
	app.identityMu.Lock()
	defer app.identityMu.Unlock()
	answer := &loadAnswer{Loaded: map[string]int{}, Absent: map[string]int{}, Unresolved: map[string][]string{}}
	var refusals []string
	err := app.repo.Load(repository.Identity{AccountID: env.Account, Region: env.Region}, func(tx *repository.LoadTx) error {
		for _, l := range loaders {
			for i := range env.Exchanges {
				ex := &env.Exchanges[i]
				if ex.key() != l.key {
					continue
				}
				items, err := l.load(tx, env, ex)
				if err != nil {
					refusals = append(refusals, fmt.Sprintf("exchange %d: %s %s: %v", i, ex.Service, ex.Action, err))
					continue
				}
				for _, item := range items {
					answer.Loaded[item.Type]++
				}
			}
		}
		if len(refusals) > 0 {
			return errLoadRefused
		}
		return nil
	})
	if len(refusals) > 0 {
		return nil, refusals, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return answer, nil, nil
}

func writeLoadRefused(w http.ResponseWriter, refusals []string) {
	writeJSONStatus(w, http.StatusBadRequest, map[string]any{"status": "error", "refusals": refusals})
}
