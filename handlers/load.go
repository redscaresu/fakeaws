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

// loadRefusal is how a loader refuses an exchange on purpose: the load
// collects it, runs on to name every refusal, then rolls back and
// answers 400. Any other error a loader returns, or any failed statement
// in its transaction whatever it returns (repository.LoadTx.Failed),
// aborts the load at once: SQLite may have rolled the transaction back
// itself (SQLITE_FULL, IOERR, BUSY, NOMEM), and a later write would then
// commit on its own.
type loadRefusal string

func (r loadRefusal) Error() string { return string(r) }

// loader loads the exchanges of one {service, action}. A loader file,
// handlers/load_<service>_*.go, registers its loaders from init.
type loader struct {
	key LoadKey
	// table is the most-parent table the loader writes. Loaders run
	// parents first, by repository.LoadRank, so a row's parent rows are
	// stored before it; loaders on one table run in registration order.
	table string
	rank  int // repository.LoadRank(table), set by registerLoader
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

// loaders is the registry, in the order a load runs them: by table
// rank, then registration order. Init order is file-name order, so it
// never decides which table loads first.
var loaders []loader

// registerLoader adds l in rank order. It panics on a table resetTables
// does not hold or a key already registered.
func registerLoader(l loader) {
	rank, ok := repository.LoadRank(l.table)
	if !ok {
		panic(fmt.Sprintf("loader %s %s writes %q, which is not a reset table", l.key.Service, l.key.Action, l.table))
	}
	if slices.ContainsFunc(loaders, func(have loader) bool { return have.key == l.key }) {
		panic(fmt.Sprintf("loader %s %s registered twice", l.key.Service, l.key.Action))
	}
	l.rank = rank
	i := slices.IndexFunc(loaders, func(have loader) bool { return have.rank > rank })
	if i < 0 {
		i = len(loaders)
	}
	loaders = slices.Insert(loaders, i, l)
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

// loadAbort is a load stopped by a loader's failure. It holds the
// exchange's index and its loader's key, and nothing of the failure: its
// text can quote a real account's body, so it is never logged or
// answered.
type loadAbort struct {
	index int
	key   LoadKey
}

func (a *loadAbort) Error() string {
	return fmt.Sprintf("exchange %d: %s %s failed; the load stopped there and wrote nothing", a.index, a.key.Service, a.key.Action)
}

// errLoadTransaction stands for any failure of the load's transaction
// itself (its delete, identity write or commit), whose text is not
// logged or answered either.
var errLoadTransaction = errors.New("the load's transaction failed and wrote nothing")

// handleMockLoad replaces every row with a recorded read of at most
// loadMaxBytes (413 over it): 200 with a loadAnswer; 400 listing every
// refusal, and where the load stopped when a loader failed after them;
// or 500 when a loader fails before any refusal, or the transaction
// does. After a 400 or a 500 nothing has changed. The log line of a
// failure is app.load's error, which names at most an exchange's index
// and its loader's key.
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
	if err != nil {
		log.Printf("POST /mock/load: %v", err)
	}
	switch {
	case len(refusals) > 0:
		writeLoadRefused(w, refusals)
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSONStatus(w, http.StatusOK, answer)
	}
}

// refusals names every field of env that is invalid and every exchange
// no loader is registered for. An absent or null exchanges is refused,
// so an envelope cut short never loads as empty; [] loads nothing.
func (env *loadEnvelope) refusals() []string {
	var out []string
	if env.Exchanges == nil {
		out = append(out, "exchanges is required: [] loads nothing")
	}
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

// load replaces every row with env's in one transaction, running each
// loader, parents first (the registry's order), on its exchanges in
// recorded order. It holds identityMu exclusively, so no request reads
// between the delete and the commit. A committed load clears the
// request log, as /mock/reset does: the traffic it holds was against
// the replaced rows.
//
// It returns the answer; or the refusals; or a *loadAbort, with the
// refusals so far and the abort's own line after them when there are
// any; or errLoadTransaction. Its error is only ever one of those two.
func (app *Application) load(env *loadEnvelope) (*loadAnswer, []string, error) {
	app.identityMu.Lock()
	defer app.identityMu.Unlock()
	run := loadRun{env: env, answer: &loadAnswer{Loaded: map[string]int{}, Absent: map[string]int{}, Unresolved: map[string][]string{}}}
	err := app.repo.Load(repository.Identity{AccountID: env.Account, Region: env.Region}, run.fill)
	var abort *loadAbort
	switch {
	case errors.Is(err, errLoadRefused):
		return nil, run.refusals, nil
	case errors.As(err, &abort) && len(run.refusals) > 0:
		return nil, append(run.refusals, abort.Error()), abort
	case errors.As(err, &abort):
		return nil, nil, abort
	case err != nil:
		return nil, nil, errLoadTransaction
	}
	app.requests.clear()
	return run.answer, nil, nil
}

// loadRun is one load's progress: its answer and its refusals so far.
type loadRun struct {
	env      *loadEnvelope
	answer   *loadAnswer
	refusals []string
}

// fill runs the loaders inside the load's transaction. A loadRefusal is
// collected and the run goes on; a failure stops it there.
func (run *loadRun) fill(tx *repository.LoadTx) error {
	byKey := map[LoadKey][]int{}
	for i := range run.env.Exchanges {
		key := run.env.Exchanges[i].key()
		byKey[key] = append(byKey[key], i)
	}
	for _, l := range loaders {
		for _, i := range byKey[l.key] {
			if err := run.exchange(tx, l, i); err != nil {
				return err
			}
		}
	}
	if len(run.refusals) > 0 {
		return errLoadRefused
	}
	return nil
}

// exchange runs l on exchange i. A failed statement in tx is a
// *loadAbort whatever l returned, so a loader cannot pass one off as a
// refusal; so is any error but a loadRefusal.
func (run *loadRun) exchange(tx *repository.LoadTx, l loader, i int) error {
	items, err := l.load(tx, run.env, &run.env.Exchanges[i])
	var refusal loadRefusal
	switch {
	case tx.Failed(), err != nil && !errors.As(err, &refusal):
		return &loadAbort{index: i, key: l.key}
	case err != nil:
		run.refusals = append(run.refusals, fmt.Sprintf("exchange %d: %s %s: %s", i, l.key.Service, l.key.Action, refusal))
		return nil
	}
	for _, item := range items {
		run.answer.Loaded[item.Type]++
	}
	return nil
}

func writeLoadRefused(w http.ResponseWriter, refusals []string) {
	writeJSONStatus(w, http.StatusBadRequest, map[string]any{"status": "error", "refusals": refusals})
}
