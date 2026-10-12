package handlers

// load_diff.go — a generic diff of a recorded response body against
// fakeaws's rendering of the same rows, naming every path where they
// differ. It reports paths only, never a value: a body may hold a real
// account's data.

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// LoadKey names an exchange by service and action: loaders and ignore
// entries register under it.
type LoadKey struct{ Service, Action string }

// IgnoreEntry suppresses one path of its own key's diff, and everything
// under it, in both directions. Path is index-free
// (vpcSet/item/dhcpOptionsId) and never carries a value. Cite names the
// terraform-provider-aws v5.100.0 source file in which the field is never
// read, spelt as TestLoadDiffIgnoreList's ignoreCiteRE checks.
type IgnoreEntry struct {
	Key  LoadKey
	Path string
	Cite string
}

// loadIgnores holds every loader file's entries, each registered from
// that file's init through registerIgnores.
var loadIgnores []IgnoreEntry

func registerIgnores(entries ...IgnoreEntry) { loadIgnores = append(loadIgnores, entries...) }

// diffAlwaysIgnored names fields no diff compares, at any depth: request
// ids and paging, which differ between any two answers.
var diffAlwaysIgnored = map[string]bool{
	"requestId": true, "RequestId": true, "ResponseMetadata": true,
	"nextToken": true, "NextToken": true, "IsTruncated": true, "Marker": true,
}

// nodeKind says how a node's value compares: byte-exact text, and for a
// JSON scalar its type too.
type nodeKind byte

const (
	nodeText       nodeKind = iota // XML text; a JSON object or array, which has none
	nodeJSONString                 // a value even when empty
	nodeJSONNumber                 // text is diffNumber's spelling
	nodeJSONBool
)

// Tree is a parsed XML element or JSON value. A set member (an XML item
// or member, a JSON array element) is compared with its same-named
// siblings as a multiset. Diff treats a node with no value and no kids
// (an empty element, a JSON null, {} or []) as absent: see prune.
type Tree struct {
	name   string
	text   string
	kind   nodeKind
	json   bool // name is a JSON key
	member bool
	kids   []*Tree
	index  int // among its same-named siblings in the body it was parsed from, or in MergePages's tree; set by diffAppend
}

// diffAppend adds kid to parent, indexed among parent's kids in its
// group: the index a path names, which Subtree and prune keep.
//
// ponytail: O(n²) per parent; keep a per-group count if one set reaches
// ~100k members.
func diffAppend(parent, kid *Tree) {
	kid.index = 0
	for _, k := range parent.kids {
		if k.group() == kid.group() {
			kid.index++
		}
	}
	parent.kids = append(parent.kids, kid)
}

// valued says whether t holds a value of its own, which an XML element
// with text or any JSON scalar does.
func (t *Tree) valued() bool { return t.text != "" || t.kind != nodeText }

var (
	// diffJSONMemberName is how AWS's JSON protocols spell a structure member.
	diffJSONMemberName = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	diffXMLMemberName  = regexp.MustCompile(`^@?[A-Za-z][A-Za-z0-9]*$`)
)

// diffLabel is how a path shows a name, and an allowlist: a name in its
// protocol's member spelling shows as itself, any other as {key}. A
// map-shaped member's keys (DynamoDB attribute names, tag keys) are
// data; one spelt like a member (a tag key Owner) still shows, and no
// loader's JSON 1.1 response has a map member.
func diffLabel(name string, isJSON bool) string {
	switch {
	case name == "",
		isJSON && diffJSONMemberName.MatchString(name),
		!isJSON && diffXMLMemberName.MatchString(name):
		return name
	}
	return "{key}"
}

// diffXMLSpace is XML's whitespace: text made only of it is layout.
const diffXMLSpace = " \t\r\n"

// ParseXML parses body through encoding/xml tokens, so an element no
// struct names is kept. Comments, processing instructions, namespace
// declarations and whitespace-only text are dropped; any other text is
// kept byte-exact. An attribute becomes an @name leaf.
func ParseXML(body []byte) (*Tree, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var stack []*Tree
	var root *Tree
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, diffXMLError(err)
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			if root != nil {
				return nil, errors.New("body is not XML: more than one root element")
			}
			stack = append(stack, diffXMLElement(tok))
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text += string(tok)
			} else if len(bytes.Trim(tok, diffXMLSpace)) > 0 {
				return nil, errors.New("body is not XML: text outside the root element")
			}
		case xml.EndElement:
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if strings.Trim(n.text, diffXMLSpace) == "" {
				n.text = ""
			}
			if len(stack) == 0 {
				root = n
			} else {
				diffAppend(stack[len(stack)-1], n)
			}
		}
	}
	if root == nil {
		return nil, errors.New("body is not XML: no root element")
	}
	return root, nil
}

func diffXMLElement(tok xml.StartElement) *Tree {
	n := &Tree{name: tok.Name.Local, member: tok.Name.Local == "item" || tok.Name.Local == "member"}
	for _, a := range tok.Attr {
		if a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns") {
			continue
		}
		n.kids = append(n.kids, &Tree{name: "@" + a.Name.Local, text: a.Value})
	}
	return n
}

// diffXMLError keeps only the line of a syntax error: the decoder's
// message can quote the body.
func diffXMLError(err error) error {
	var se *xml.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("body is not XML: syntax error on line %d", se.Line)
	}
	return errors.New("body is not XML")
}

// ParseJSON parses a JSON 1.1 body through a generic walk with UseNumber,
// so a key no struct names is kept. An array's elements are set members
// named by its key.
func ParseJSON(body []byte) (*Tree, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return nil, fmt.Errorf("body is not JSON: syntax error at offset %d", se.Offset)
		}
		return nil, errors.New("body is not JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("body is not JSON: more than one value")
	}
	return diffJSONValue("", v), nil
}

// diffJSONField adds to parent the nodes a field holds: one set member
// per array element, or the value itself.
func diffJSONField(parent *Tree, name string, v any) {
	arr, ok := v.([]any)
	if !ok {
		diffAppend(parent, diffJSONValue(name, v))
		return
	}
	for _, e := range arr {
		n := diffJSONValue(name, e)
		n.member = true
		diffAppend(parent, n)
	}
}

// diffJSONValue returns v as a node named name. An array reaches it only
// nested in another, so its elements are unnamed.
func diffJSONValue(name string, v any) *Tree {
	n := &Tree{name: name, json: true}
	switch v := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			diffJSONField(n, k, v[k])
		}
	case []any:
		diffJSONField(n, "", v)
	case string:
		n.text, n.kind = v, nodeJSONString
	case json.Number:
		n.text, n.kind = diffNumber(v), nodeJSONNumber
	case bool:
		n.text, n.kind = strconv.FormatBool(v), nodeJSONBool
	}
	return n
}

// diffNumber spells a JSON number's exact value one way, digits and a
// power of ten, so 1.7E9 and 1700000000 both give 17e8. It does no
// arithmetic, so no exponent can make it slow.
func diffNumber(num json.Number) string {
	s, sign := string(num), ""
	if strings.HasPrefix(s, "-") {
		s, sign = s[1:], "-"
	}
	exp := 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return string(num)
		}
		s, exp = s[:i], e
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		exp -= len(s) - i - 1
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	digits := strings.TrimRight(s, "0")
	return sign + digits + "e" + strconv.Itoa(exp+len(s)-len(digits))
}

// Subtree returns the index-th node, in document order, at path
// (index-free and from the root: vpcSet/item, Parameter), under the
// chain of its ancestors and nothing else, each keeping its index, so
// its paths and ignore entries read as the whole body's. It returns nil
// when there is none.
func (t *Tree) Subtree(path string, index int) *Tree {
	segs := strings.Split(path, "/")
	seen := 0
	var walk func(n *Tree, depth int) *Tree
	walk = func(n *Tree, depth int) *Tree {
		if depth == len(segs) {
			seen++
			if seen-1 == index {
				return n
			}
			return nil
		}
		for _, k := range n.kids {
			if k.name != segs[depth] {
				continue
			}
			if got := walk(k, depth+1); got != nil {
				return &Tree{name: n.name, json: n.json, member: n.member, index: n.index, kids: []*Tree{got}}
			}
		}
		return nil
	}
	return walk(t, 0)
}

// MergePages returns the union of a paged list's pages: every set member
// of every page, and the first page's value of any other field (the
// paging fields differ by page, and Diff ignores them). The pages of one
// list share a root, so no page, a nil page or a page under another root
// is an error.
//
// ponytail: a list whose items are not set members (S3's and Route53's
// flattened lists) merges into one item; add a rule when a loader pages one.
func MergePages(pages ...*Tree) (*Tree, error) {
	if len(pages) == 0 {
		return nil, errors.New("no pages to merge")
	}
	if slices.Contains(pages, nil) {
		return nil, errors.New("a page to merge is nil")
	}
	out := diffClone(pages[0])
	for i, p := range pages[1:] {
		if p.name != out.name || p.json != out.json {
			return nil, fmt.Errorf("page %d's root %s is not page 0's %s", i+1, diffRootPath(p), diffRootPath(out))
		}
		diffMerge(out, p)
	}
	return out, nil
}

// diffMerge adds src's kids to dst, which MergePages owns, each indexed
// in the merged tree.
func diffMerge(dst, src *Tree) {
	for _, k := range src.kids {
		i := -1
		if !k.member {
			i = slices.IndexFunc(dst.kids, func(d *Tree) bool { return !d.member && d.name == k.name })
		}
		if i < 0 {
			diffAppend(dst, diffClone(k))
			continue
		}
		diffMerge(dst.kids[i], k)
	}
}

func diffClone(t *Tree) *Tree {
	c := *t
	c.kids = make([]*Tree, len(t.kids))
	for i, k := range t.kids {
		c.kids[i] = diffClone(k)
	}
	return &c
}

// diffRootPath is how a path names a root: its element name, or "." for
// JSON's unnamed root, so no path is empty.
func diffRootPath(t *Tree) string {
	if t.name == "" {
		return "."
	}
	return diffLabel(t.name, t.json)
}

// Diff compares a recorded body with fakeaws's rendering. It returns the
// paths only the recording holds or whose value differs, and the paths
// only the rendering holds, each sorted; equal is both empty. A path
// runs from below the root and names a set member's index in the body it
// was parsed from (or MergePages's tree), so a Subtree'd member keeps its
// body index and a member pruning drops still counts
// (vpcSet/item[2]/isDefault). A root's own value is named by
// diffRootPath, and a member with no counterpart is named whole. Two
// differently named XML roots are named and nothing under them compared.
// diffAlwaysIgnored's fields and key's ignore entries (applied here and
// nowhere else) are pruned from both trees before anything is compared.
// A nil tree is an empty body.
//
// A path is names shown through diffLabel, never a value.
func Diff(key LoadKey, recorded, rendered *Tree) (recordedOnly, renderedOnly []string) {
	recorded, rendered = diffOrEmpty(recorded), diffOrEmpty(rendered)
	if recorded.name != "" && rendered.name != "" && recorded.name != rendered.name {
		return []string{diffRootPath(recorded)}, []string{diffRootPath(rendered)}
	}
	d := treeDiffer{ignore: map[string]bool{}, forms: map[*Tree]string{}}
	for _, e := range loadIgnores {
		if e.Key == key {
			d.ignore[e.Path] = true
		}
	}
	recordedOnly, renderedOnly = d.node(d.pruneRoot(recorded), d.pruneRoot(rendered))
	for i, p := range recordedOnly {
		if p == "" {
			recordedOnly[i] = diffRootPath(recorded)
		}
	}
	for i, p := range renderedOnly {
		if p == "" {
			renderedOnly[i] = diffRootPath(rendered)
		}
	}
	sort.Strings(recordedOnly)
	sort.Strings(renderedOnly)
	return recordedOnly, renderedOnly
}

func diffOrEmpty(t *Tree) *Tree {
	if t == nil {
		return &Tree{}
	}
	return t
}

type treeDiffer struct {
	ignore map[string]bool
	forms  map[*Tree]string // each pruned node's form, built once
}

// pruneRoot is prune for a root, which stays, emptied, when nothing under
// it is compared.
func (d treeDiffer) pruneRoot(t *Tree) *Tree {
	if p := d.prune(t, ""); p != nil {
		return p
	}
	return &Tree{name: t.name, json: t.json}
}

// prune returns a copy of t without the fields Diff never compares and
// without any node that holds no value and no kids, before or after
// that, or nil when nothing is left: an empty element is absent. A kid
// kept keeps its index, so a dropped member still counts. shape is t's
// index-free path, which ignore entries name.
func (d treeDiffer) prune(t *Tree, shape string) *Tree {
	c := *t
	c.kids = nil
	for _, k := range t.kids {
		kShape := diffJoin(shape, k.name)
		if diffAlwaysIgnored[k.name] || d.ignore[kShape] {
			continue
		}
		if p := d.prune(k, kShape); p != nil {
			c.kids = append(c.kids, p)
		}
	}
	if !c.valued() && len(c.kids) == 0 {
		return nil
	}
	return &c
}

// diffGroupKey is what makes kids same-named siblings: compared as one
// group, and indexed within it.
type diffGroupKey struct {
	name   string
	json   bool
	member bool
}

func (t *Tree) group() diffGroupKey { return diffGroupKey{t.name, t.json, t.member} }

// diffGroups groups t's kids by name, the groups in a fixed order.
func diffGroups(t *Tree) (map[diffGroupKey][]*Tree, []diffGroupKey) {
	groups := map[diffGroupKey][]*Tree{}
	var order []diffGroupKey
	for _, k := range t.kids {
		g := k.group()
		if _, ok := groups[g]; !ok {
			order = append(order, g)
		}
		groups[g] = append(groups[g], k)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].name != order[j].name {
			return order[i].name < order[j].name
		}
		return !order[i].member && order[j].member
	})
	return groups, order
}

// node compares a recorded node with a rendered one, returning paths
// relative to the two, "" for the nodes' own values.
func (d treeDiffer) node(a, b *Tree) (rec, ren []string) {
	if a.text != b.text || a.kind != b.kind {
		if a.valued() {
			rec = append(rec, "")
		}
		if b.valued() {
			ren = append(ren, "")
		}
	}
	as, order := diffGroups(a)
	bs, bOrder := diffGroups(b)
	for _, g := range bOrder {
		if _, ok := as[g]; !ok {
			order = append(order, g)
		}
	}
	for _, g := range order {
		var r, n []string
		if g.member {
			r, n = d.members(diffLabel(g.name, g.json), as[g], bs[g])
		} else {
			r, n = d.fields(diffLabel(g.name, g.json), as[g], bs[g])
		}
		rec, ren = append(rec, r...), append(ren, n...)
	}
	return rec, ren
}

// fields pairs same-named kids that are not set members by position,
// each side naming its own index only when a name repeats.
func (d treeDiffer) fields(name string, as, bs []*Tree) (rec, ren []string) {
	for i := range max(len(as), len(bs)) {
		a, b := &Tree{}, &Tree{}
		if i < len(as) {
			a = as[i]
		}
		if i < len(bs) {
			b = bs[i]
		}
		segA, segB := name, name
		if len(as) > 1 || len(bs) > 1 || a.index > 0 || b.index > 0 {
			segA, segB = fmt.Sprintf("%s[%d]", name, a.index), fmt.Sprintf("%s[%d]", name, b.index)
		}
		r, n := d.node(a, b)
		rec, ren = append(rec, diffUnder(segA, r)...), append(ren, diffUnder(segB, n)...)
	}
	return rec, ren
}

// members pairs set members as a multiset. Equal members pair first, by
// form. Each remaining one pairs with the remaining member on the other
// side it differs from least, ties by index, scored by diffDistance
// rather than a node diff, so scoring never recurses: only the pairs
// chosen are node-diffed. A member left over is named whole.
//
// ponytail: O(n·m) diffDistance scores over the members no equal one
// pairs; fine for one account's read, index members by id if loads reach
// thousands.
func (d treeDiffer) members(name string, as, bs []*Tree) (rec, ren []string) {
	seg := func(t *Tree) string { return fmt.Sprintf("%s[%d]", name, t.index) }
	usedA, usedB := make([]bool, len(as)), make([]bool, len(bs))
	byForm := map[string][]int{}
	for j, b := range bs {
		f := d.form(b)
		byForm[f] = append(byForm[f], j)
	}
	for i, a := range as {
		f := d.form(a)
		if js := byForm[f]; len(js) > 0 {
			usedA[i], usedB[js[0]], byForm[f] = true, true, js[1:]
		}
	}
	leavesA, leavesB := make([][]uint64, len(as)), make([][]uint64, len(bs))
	for i, a := range as {
		if !usedA[i] {
			leavesA[i] = diffLeaves(a)
		}
	}
	for j, b := range bs {
		if !usedB[j] {
			leavesB[j] = diffLeaves(b)
		}
	}
	type pair struct{ i, j, distance int }
	var pairs []pair
	for i := range as {
		for j := range bs {
			if !usedA[i] && !usedB[j] {
				pairs = append(pairs, pair{i, j, diffDistance(leavesA[i], leavesB[j])})
			}
		}
	}
	sort.SliceStable(pairs, func(x, y int) bool { return pairs[x].distance < pairs[y].distance })
	for _, p := range pairs {
		if usedA[p.i] || usedB[p.j] {
			continue
		}
		usedA[p.i], usedB[p.j] = true, true
		r, n := d.node(as[p.i], bs[p.j])
		rec, ren = append(rec, diffUnder(seg(as[p.i]), r)...), append(ren, diffUnder(seg(bs[p.j]), n)...)
	}
	for i, used := range usedA {
		if !used {
			rec = append(rec, seg(as[i]))
		}
	}
	for j, used := range usedB {
		if !used {
			ren = append(ren, seg(bs[j]))
		}
	}
	return rec, ren
}

// diffLeaves returns t's leaves, each its index-free path, kind and
// value, hashed and sorted: the multiset diffDistance compares.
func diffLeaves(t *Tree) []uint64 {
	var out []uint64
	h := fnv.New64a()
	var walk func(n *Tree, path string)
	walk = func(n *Tree, path string) {
		if n.valued() {
			h.Reset()
			h.Write([]byte(path + "\x00" + string(byte(n.kind)) + n.text))
			out = append(out, h.Sum64())
		}
		for _, k := range n.kids {
			walk(k, path+"/"+k.name)
		}
	}
	walk(t, "")
	slices.Sort(out)
	return out
}

// diffDistance is the size of the symmetric difference of two sorted
// leaf multisets: a cheap stand-in for the number of paths a node diff
// of the two would name. A hash collision can only change which members
// pair, never what is reported, since each chosen pair is node-diffed.
func diffDistance(a, b []uint64) int {
	n, i, j := 0, 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			i, j = i+1, j+1
		case a[i] < b[j]:
			n, i = n+1, i+1
		default:
			n, j = n+1, j+1
		}
	}
	return n + len(a) - i + len(b) - j
}

// form spells a pruned node by the rules node compares by, so two nodes
// have the same form exactly when node finds no difference between them.
// Every part is length-prefixed, never quoted, so a child's form nests in
// its parent's as it is and a form grows linearly with depth. Each node's
// form is built once.
func (d treeDiffer) form(t *Tree) string {
	if f, ok := d.forms[t]; ok {
		return f
	}
	var b strings.Builder
	part := func(s string) { b.WriteString(strconv.Itoa(len(s)) + ":" + s) }
	b.WriteByte(byte(t.kind))
	part(t.text)
	groups, order := diffGroups(t)
	for _, g := range order {
		forms := make([]string, len(groups[g]))
		for i, k := range groups[g] {
			forms[i] = d.form(k)
		}
		if g.member {
			sort.Strings(forms)
		}
		part(g.name)
		b.WriteString(strconv.FormatBool(g.member) + strconv.Itoa(len(forms)) + ":")
		for _, f := range forms {
			part(f)
		}
	}
	f := b.String()
	d.forms[t] = f
	return f
}

// diffUnder prefixes each path relative to seg with seg.
func diffUnder(seg string, rels []string) []string {
	out := make([]string, len(rels))
	for i, r := range rels {
		out[i] = diffJoin(seg, r)
	}
	return out
}

func diffJoin(parent, child string) string {
	switch {
	case parent == "":
		return child
	case child == "":
		return parent
	}
	return parent + "/" + child
}
