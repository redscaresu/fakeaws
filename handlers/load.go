package handlers

// load.go — POST /mock/load: replaces every row with a recorded read
// (ADR-0041) in one transaction, through the registered loaders.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"slices"
	"strings"

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
// reader never reads, so no exchange can hold it. A Path, with its
// Index (Tree.Subtree's), is where the item's body holds its own copy
// of the row, which must agree with the row's recorded item.
type loadReference struct {
	loadRef
	Unread bool
	Path   string
	Index  int
}

// loadItem is one item a loader decoded: its row, where its recorded
// subtree sits in the exchange's body (Tree.Subtree's path and index),
// the rows it references, and write, which stores its rows through tx.
// The load calls write once per row: an item another exchange already
// loaded is compared, never written again. An item with no write stores
// no row (a list naming rows another exchange loads): it is rendered and
// its references checked, but loaded never counts it.
type loadItem struct {
	loadRef
	Path  string
	Index int
	Refs  []loadReference
	write func(tx *repository.LoadTx) error
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
	// typ is the type of row a read of it finds: a NotFound counts
	// under it in the answer's absent.
	typ string
	// notFound are the error codes a non-2xx answers when the read
	// found nothing.
	notFound []string
	// requestToken is the request param a next page carries (NextToken,
	// Marker); responseToken is the response field a page answers it in
	// (nextToken, Marker); truncated, for a service that answers one,
	// is the field that answers true while more pages follow
	// (IsTruncated).
	requestToken, responseToken, truncated string
	// decode returns ex's items, each writing its rows under env's
	// account and, for a region-scoped row, env's region. It writes
	// nothing itself.
	decode func(env *loadEnvelope, ex *loadExchange) ([]loadItem, error)
	// render reads the rows of ids back through tx and marshals them
	// with the encoder the Describe or Get handler answers with, never
	// from what decode decoded.
	render func(tx *repository.LoadTx, ids []string) ([]byte, error)
}

// loaderFor is key's loader; refusals has refused any exchange without
// one.
func loaderFor(key LoadKey) *loader {
	return &loaders[slices.IndexFunc(loaders, func(l loader) bool { return l.key == key })]
}

// LoadAttributeReads are the attributes a load needs one recorded answer
// of per loaded row, by the EC2 action that reads one: a loaded VPC
// references each DescribeVpcAttribute, and an instance each
// DescribeInstanceAttribute, so a recording that lacks one is refused.
func LoadAttributeReads() map[string][]string {
	return map[string][]string{
		"DescribeVpcAttribute":      slices.Clone(ec2VpcDNSAttributes),
		"DescribeInstanceAttribute": slices.Clone(ec2InstanceReadAttributes),
	}
}

// loaders is the registry, in the order a load runs them: by table
// rank, then registration order. Init order is file-name order, so it
// never decides which table loads first.
var loaders []loader

// registerLoader adds l in rank order. It panics on a table resetTables
// does not hold, a key already registered, a missing decode or render,
// half a pair of page tokens, a truncated field with no response token,
// or NotFound codes with no typ to count them under.
func registerLoader(l loader) {
	name := l.key.Service + " " + l.key.Action
	rank, ok := repository.LoadRank(l.table)
	if !ok {
		panic(fmt.Sprintf("loader %s writes %q, which is not a reset table", name, l.table))
	}
	switch {
	case slices.ContainsFunc(loaders, func(have loader) bool { return have.key == l.key }):
		panic(fmt.Sprintf("loader %s registered twice", name))
	case l.decode == nil || l.render == nil:
		panic(fmt.Sprintf("loader %s needs both decode and render", name))
	case (l.requestToken == "") != (l.responseToken == ""):
		panic(fmt.Sprintf("loader %s pages with only one of requestToken and responseToken", name))
	case l.truncated != "" && l.responseToken == "":
		panic(fmt.Sprintf("loader %s answers truncated %q but no responseToken", name, l.truncated))
	case len(l.notFound) > 0 && l.typ == "":
		panic(fmt.Sprintf("loader %s has notFound codes but no typ to count them under", name))
	}
	l.rank = rank
	i := slices.IndexFunc(loaders, func(have loader) bool { return have.rank > rank })
	if i < 0 {
		i = len(loaders)
	}
	loaders = slices.Insert(loaders, i, l)
}

// loadAnswer is a load's 200, each part keyed by type: the rows
// loaded, the reads that found nothing (a NotFound, under its loader's
// typ), and the ids, sorted, of references the reader never reads that
// no exchange held.
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

// CRITICAL[mock-load-off-by-default]: without Options.LoadMaxBytes the
// route is not registered, so POST /mock/load answers as any unknown
// /mock path.
//
// CRITICAL[mock-load-needs-admin-token]: NewApplication refuses
// Options.LoadMaxBytes without an AdminToken (ErrLoadNeedsAdminToken):
// a load deletes every row.
//
// CRITICAL[mock-load-replaces-every-row-atomically]: a second load
// replaces the first whole: its rows, its identity and its tables'
// other rows.
//
// CRITICAL[mock-load-refusal-changes-nothing]: a load that is refused
// or fails changes nothing: rows, identity and snapshot as they were.
//
// CRITICAL[mock-load-keeps-snapshot]: a load never touches the
// snapshot, so /mock/restore after a load returns to the snapshot.
//
// CRITICAL[mock-load-refuses-unheld-field]: a field of a recorded body
// that the model cannot hold refuses the load, naming the row and the
// field's path, whatever the handler's own decoder would drop.
//
// CRITICAL[mock-load-never-mints]: a VPC's recorded default security
// group loads under its recorded id, and a VPC whose recording holds
// none gets none, after the load and after a snapshot and restore.
//
// CRITICAL[mock-load-refuses-dangling-reference]: a row that names or
// references a row no exchange loaded is refused, naming both.
//
// CRITICAL[mock-load-not-found-loads-nothing]: a non-2xx answering its
// loader's NotFound code (an XML Code, or a JSON __type with or without
// its namespace and suffix) loads no row and counts under absent.
//
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
// loader, parents first (the registry's order), on its 2xx exchanges in
// recorded order, then checking every row's references and rendering
// (loadRun.fill). It holds identityMu exclusively, so no request reads
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
	run := loadRun{
		env:    env,
		answer: &loadAnswer{Loaded: map[string]int{}, Absent: map[string]int{}, Unresolved: map[string][]string{}},
		trees:  map[int]*Tree{},
		chain:  make([]int, len(env.Exchanges)),
		rows:   map[loadRef]*loadRow{},
	}
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

// loadRun is one load's progress: its answer, its refusals so far, each
// exchange's parsed body and page chain, and the rows written.
type loadRun struct {
	env      *loadEnvelope
	answer   *loadAnswer
	refusals []string
	trees    map[int]*Tree // by 2xx exchange whose body parsed
	chain    []int         // by 2xx exchange: its chain's first page
	rows     map[loadRef]*loadRow
	order    []*loadRow // rows in the order they were written
}

// loadRow is a row the load wrote: the item, its exchange's index, and
// the exchange each page chain that held it first held it in.
type loadRow struct {
	loadItem
	exchange int
	seen     map[int]int
}

// fill runs the loaders inside the load's transaction, then checks
// every row's references and its rendering. A refusal is collected and
// the run goes on; a failure stops it there.
func (run *loadRun) fill(tx *repository.LoadTx) error {
	byKey := run.link()
	for _, l := range loaders {
		for _, i := range byKey[l.key] {
			if err := run.exchange(tx, &l, i); err != nil {
				return err
			}
		}
	}
	if err := run.resolve(); err != nil {
		return err
	}
	for _, row := range run.order {
		if err := run.diff(tx, row); err != nil {
			return err
		}
	}
	if len(run.refusals) > 0 {
		return errLoadRefused
	}
	return nil
}

// refuse collects a refusal of exchange i.
func (run *loadRun) refuse(i int, format string, args ...any) {
	key := run.env.Exchanges[i].key()
	run.refusals = append(run.refusals, fmt.Sprintf("exchange %d: %s %s: ", i, key.Service, key.Action)+fmt.Sprintf(format, args...))
}

// parseLoadBody parses body as protocol's services answer: JSON for
// json, else XML.
func parseLoadBody(protocol string, body []byte) (*Tree, error) {
	if protocol == protocolJSON {
		return ParseJSON(body)
	}
	return ParseXML(body)
}

// link answers each non-2xx exchange (absent, or refused naming its
// status), parses each 2xx one's body, refusing one that does not parse
// so no loader sees it, and links the rest into page chains, returning
// them by key. Pages are one entry when their key is one and their
// params are equal but for the request token.
func (run *loadRun) link() map[LoadKey][]int {
	type entry struct {
		key    LoadKey
		params string
	}
	byKey := map[LoadKey][]int{}
	entries := map[entry][]int{}
	var order []entry
	for i := range run.env.Exchanges {
		ex := &run.env.Exchanges[i]
		l := loaderFor(ex.key())
		if ex.Status < http.StatusOK || ex.Status >= http.StatusMultipleChoices {
			run.status(l, i)
			continue
		}
		t, err := parseLoadBody(ex.Protocol, []byte(ex.Body))
		if err != nil {
			run.refuse(i, "%v", err)
			continue
		}
		run.trees[i] = t
		byKey[l.key] = append(byKey[l.key], i)
		params := ex.Params
		if m, ok := params.(map[string]any); ok && l.requestToken != "" {
			m = maps.Clone(m)
			delete(m, l.requestToken)
			params = m
		}
		b, _ := json.Marshal(params) // decoded JSON, so it marshals
		e := entry{l.key, string(b)}
		if _, ok := entries[e]; !ok {
			order = append(order, e)
		}
		entries[e] = append(entries[e], i)
	}
	for _, e := range order {
		run.pages(loaderFor(e.key), entries[e])
	}
	return byKey
}

// status answers non-2xx exchange i: absent under l's typ when its
// error code is one of l's notFound, else refused naming its status.
func (run *loadRun) status(l *loader, i int) {
	ex := &run.env.Exchanges[i]
	if t, err := parseLoadBody(ex.Protocol, []byte(ex.Body)); err == nil && slices.Contains(l.notFound, loadErrorCode(t)) {
		run.answer.Absent[l.typ]++
		return
	}
	run.refuse(i, "answered %d, which is not a NotFound", ex.Status)
}

// loadErrorCode is the AWS error code an error body answers: a JSON
// body's __type between any namespace '#' and any ':' suffix, as the
// AWS SDK reads it, or an XML body's Code.
func loadErrorCode(t *Tree) string {
	if t.json {
		code := loadField(t, "__type")
		code, _, _ = strings.Cut(code[strings.LastIndexByte(code, '#')+1:], ":")
		return code
	}
	return loadField(t, "Code")
}

// loadField is the text of the first field named name in t outside any
// set member: a response's paging field or an error's code, never an
// item's field.
func loadField(t *Tree, name string) string {
	for _, k := range t.kids {
		if k.member {
			continue
		}
		if k.name == name && k.text != "" {
			return k.text
		}
		if s := loadField(k, name); s != "" {
			return s
		}
	}
	return ""
}

// pages links one entry's pages, in recorded order, into chains: a page
// carrying no request token starts one, and a page carrying the token
// an earlier page answered (the latest, when two did) continues that
// page's chain. A page carrying a token no earlier page answered is
// refused as an orphan, in a chain of its own; a page answering more
// pages, by a token or a truncated field, that no later page continues
// is refused as truncated.
func (run *loadRun) pages(l *loader, pages []int) {
	answered := map[string]int{} // token → the latest page that answered it
	continued := map[int]bool{}
	var more []int // pages that answered more pages
	for _, i := range pages {
		run.chain[i] = i
		if token := l.carried(&run.env.Exchanges[i]); token != "" {
			if p, ok := answered[token]; ok {
				run.chain[i], continued[p] = run.chain[p], true
			} else {
				run.refuse(i, "orphan page: no earlier page of its read answered the %s it carries", l.requestToken)
			}
		}
		if l.responseToken == "" {
			continue
		}
		next, flag := loadField(run.trees[i], l.responseToken), loadField(run.trees[i], l.truncated)
		if next != "" || (l.truncated != "" && flag != "" && flag != "false") {
			more = append(more, i)
		}
		if next != "" {
			answered[next] = i
		}
	}
	for _, i := range more {
		if !continued[i] {
			run.refuse(i, "truncated: it answers more pages, and no later page of its read carries its %s", l.responseToken)
		}
	}
}

// carried is the request token ex carries, "" for none: an absent, null
// or empty token. Any other value is a token, as fmt spells it.
func (l *loader) carried(ex *loadExchange) string {
	params, _ := ex.Params.(map[string]any)
	if token := params[l.requestToken]; token != nil && l.requestToken != "" {
		return fmt.Sprint(token)
	}
	return ""
}

// guard runs step, l's decode, an item's write or l's render for
// exchange i. A loadRefusal it returns is collected (refused). A failed
// statement in tx, whatever step returned, is a *loadAbort, so a loader
// cannot pass one off as a refusal; so is any error but a loadRefusal,
// and so is a panic, whose value (a decoder's, quoting the body) is
// dropped here rather than reaching middleware.Recoverer's stack print.
func (run *loadRun) guard(tx *repository.LoadTx, l *loader, i int, step func() error) (refused bool, abort error) {
	defer func() {
		if recover() != nil {
			refused, abort = false, &loadAbort{index: i, key: l.key}
		}
	}()
	err := step()
	var refusal loadRefusal
	switch {
	case tx.Failed(), err != nil && !errors.As(err, &refusal):
		return false, &loadAbort{index: i, key: l.key}
	case err != nil:
		run.refuse(i, "%s", refusal)
		return true, nil
	}
	return false, nil
}

// exchange decodes exchange i with l and writes each item whose row no
// earlier item wrote.
func (run *loadRun) exchange(tx *repository.LoadTx, l *loader, i int) error {
	var items []loadItem
	refused, err := run.guard(tx, l, i, func() (err error) {
		items, err = l.decode(run.env, &run.env.Exchanges[i])
		return err
	})
	if refused || err != nil {
		return err
	}
	for _, item := range items {
		if first, ok := run.rows[item.loadRef]; ok {
			if err := run.repeat(first, i, &item); err != nil {
				return err
			}
			continue
		}
		if item.write != nil {
			refused, err := run.guard(tx, l, i, func() error { return item.write(tx) })
			if err != nil {
				return err
			}
			if refused {
				continue
			}
			run.answer.Loaded[item.Type]++
		}
		row := &loadRow{loadItem: item, exchange: i, seen: map[int]int{run.chain[i]: i}}
		run.rows[item.loadRef], run.order = row, append(run.order, row)
	}
	return nil
}

// recorded is item's subtree in exchange i's body, or a *loadAbort when
// the loader named a path the body does not hold.
func (run *loadRun) recorded(i int, item *loadItem) (*Tree, error) {
	if sub := run.trees[i].Subtree(item.Path, item.Index); sub != nil {
		return sub, nil
	}
	return nil, &loadAbort{index: i, key: run.env.Exchanges[i].key()}
}

// repeat answers item of exchange i, whose row first already wrote.
// Within one page chain it is refused, naming it. Across chains it loads
// once when the two recorded items are equal by Diff, else it is refused
// naming it and both exchanges. The items compare below their paths,
// unnamed, so one item two actions answer (GetRole's Role, ListRoles'
// member) compares by its fields, under both keys' ignore and encoded
// entries.
func (run *loadRun) repeat(first *loadRow, i int, item *loadItem) error {
	if at, ok := first.seen[run.chain[i]]; ok {
		run.refuse(i, "%s %s repeats in its page chain, first at exchange %d", item.Type, item.ID, at)
		return nil
	}
	first.seen[run.chain[i]] = i
	was, err := run.recorded(first.exchange, &first.loadItem)
	if err != nil {
		return err
	}
	now, err := run.recorded(i, item)
	if err != nil {
		return err
	}
	key := run.env.Exchanges[first.exchange].key()
	rules := diffRules{ignore: map[string]bool{}, decode: map[string]bool{}}
	add := func(rule map[string]bool, entryKey LoadKey, path string) {
		for _, side := range []struct {
			key  LoadKey
			path string
		}{{key, first.Path}, {run.env.Exchanges[i].key(), item.Path}} {
			if rel, ok := strings.CutPrefix(path, side.path+"/"); ok && entryKey == side.key {
				rule[rel] = true
			}
		}
	}
	for _, e := range loadIgnores {
		add(rules.ignore, e.Key, e.Path)
	}
	for _, e := range loadEncoded {
		add(rules.decode, e.Key, e.Path)
	}
	if rec, ren := diffIgnoring(rules, itemNode(was, first.Path), itemNode(now, item.Path)); len(rec)+len(ren) > 0 {
		run.refuse(i, "%s %s differs from exchange %d's (%s %s)", item.Type, item.ID, first.exchange, key.Service, key.Action)
	}
	return nil
}

// itemNode is the node a Subtree chain at path ends at, unnamed, so two
// actions' items compare by their fields whatever each calls them.
func itemNode(chain *Tree, path string) *Tree {
	for range strings.Count(path, "/") + 1 {
		chain = chain.kids[0]
	}
	n := *chain
	n.name, n.member, n.index = "", false, 0
	return &n
}

// resolve checks every row's references: one naming no loaded row is
// refused naming both, unless it is flagged Unread, which the answer
// lists under unresolved; one with a Path is checked by agree.
func (run *loadRun) resolve() error {
	for _, row := range run.order {
		for _, ref := range row.Refs {
			switch target, loaded := run.rows[ref.loadRef]; {
			case loaded && ref.Path != "":
				if err := run.agree(row, ref, target); err != nil {
					return err
				}
			case loaded:
			case ref.Unread:
				run.answer.Unresolved[ref.Type] = append(run.answer.Unresolved[ref.Type], ref.ID)
			default:
				run.refuse(row.exchange, "%s %s references %s %s, which no exchange loaded", row.Type, row.ID, ref.Type, ref.ID)
			}
		}
	}
	for typ, ids := range run.answer.Unresolved {
		slices.Sort(ids)
		run.answer.Unresolved[typ] = slices.Compact(ids)
	}
	return nil
}

// agree refuses, naming row, target, the field and both exchanges, each
// field of row's copy of target at ref's path whose value target's
// recorded item gives otherwise. Only fields holding a value of their
// own compare: a set or structure the two shapes spell apart (an
// instance's attachment) is left to row's rendering diff.
func (run *loadRun) agree(row *loadRow, ref loadReference, target *loadRow) error {
	copied, err := run.recorded(row.exchange, &loadItem{Path: ref.Path, Index: ref.Index})
	if err != nil {
		return err
	}
	recorded, err := run.recorded(target.exchange, &target.loadItem)
	if err != nil {
		return err
	}
	mine, theirs := itemNode(copied, ref.Path), itemNode(recorded, target.Path)
	key := run.env.Exchanges[target.exchange].key()
	for _, k := range mine.kids {
		i := slices.IndexFunc(theirs.kids, func(t *Tree) bool { return t.name == k.name && len(t.kids) == 0 })
		if !k.member && len(k.kids) == 0 && i >= 0 && theirs.kids[i].text != k.text {
			run.refuse(row.exchange, "%s %s: its %s %s's %s differs from exchange %d's (%s %s)",
				row.Type, row.ID, ref.Type, ref.ID, diffLabel(k.name, k.json), target.exchange, key.Service, key.Action)
		}
	}
	return nil
}

// The ends of diff's refusals, each naming the path: TestLoadReadBack
// reports that path, and nothing else of a refusal.
const (
	loadRecordedOnly = "the model cannot hold recorded %s"
	loadRenderedOnly = "fakeaws would answer %s, which the recording does not hold"
)

// diff renders row through its loader and refuses each path where the
// rendering and the recorded subtree differ, naming row's type and id
// and the path: one only the recording holds is a field the model cannot hold,
// and one only the rendering holds a field fakeaws would mint.
func (run *loadRun) diff(tx *repository.LoadTx, row *loadRow) error {
	l := loaderFor(run.env.Exchanges[row.exchange].key())
	recorded, err := run.recorded(row.exchange, &row.loadItem)
	if err != nil {
		return err
	}
	var body []byte
	refused, err := run.guard(tx, l, row.exchange, func() (err error) {
		body, err = l.render(tx, []string{row.ID})
		return err
	})
	if refused || err != nil {
		return err
	}
	rendered, err := parseLoadBody(run.env.Exchanges[row.exchange].Protocol, body)
	if err != nil {
		return &loadAbort{index: row.exchange, key: l.key}
	}
	got := rendered.Subtree(row.Path, 0)
	if got != nil {
		alignSubtree(recorded, got, row.Path)
	}
	recordedOnly, renderedOnly := Diff(l.key, recorded, got)
	for _, p := range recordedOnly {
		run.refuse(row.exchange, "%s %s: "+loadRecordedOnly, row.Type, row.ID, p)
	}
	for _, p := range renderedOnly {
		run.refuse(row.exchange, "%s %s: "+loadRenderedOnly, row.Type, row.ID, p)
	}
	return nil
}

// alignSubtree gives each node of rendered's Subtree chain at path the
// index of recorded's, so a path names the item as the recording does,
// though its rendering held it alone.
func alignSubtree(recorded, rendered *Tree, path string) {
	for range strings.Count(path, "/") + 1 {
		recorded, rendered = recorded.kids[0], rendered.kids[0]
		rendered.index = recorded.index
	}
}

func writeLoadRefused(w http.ResponseWriter, refusals []string) {
	writeJSONStatus(w, http.StatusBadRequest, map[string]any{"status": "error", "refusals": refusals})
}
