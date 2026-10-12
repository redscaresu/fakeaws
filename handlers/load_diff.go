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
// read, spelt as TestLoadDiffIgnoreList's citeRE checks.
type IgnoreEntry struct {
	Key  LoadKey
	Path string
	Cite string
}

// loadIgnores holds every loader file's entries, each registered from
// that file's init through registerIgnores.
var loadIgnores []IgnoreEntry

func registerIgnores(entries ...IgnoreEntry) { loadIgnores = append(loadIgnores, entries...) }

// alwaysIgnored names fields no diff compares, at any depth: request ids
// and paging, which differ between any two answers.
var alwaysIgnored = map[string]bool{
	"requestId": true, "RequestId": true, "ResponseMetadata": true,
	"nextToken": true, "NextToken": true, "IsTruncated": true, "Marker": true,
}

// Tree is a parsed XML element or JSON value. A node with no value and no
// kids is never built: an empty element is absent. A set member (an XML
// item or member, a JSON array element) is compared with its same-named
// siblings as a multiset.
type Tree struct {
	name   string
	text   string
	kind   byte // 0 for XML; 's', 'n' or 'b' for a JSON string, number or bool
	json   bool // name is a JSON key
	member bool
	kids   []*Tree
}

var (
	// jsonMemberName is how AWS's JSON protocols spell a structure member.
	jsonMemberName = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	xmlMemberName  = regexp.MustCompile(`^@?[A-Za-z][A-Za-z0-9]*$`)
)

// label is how a path shows a name, and an allowlist: a name in its
// protocol's member spelling shows as itself, any other as {key}. A
// map-shaped member's keys (DynamoDB attribute names, tag keys) are
// data; one spelt like a member (a tag key Owner) still shows, and no
// loader's JSON 1.1 response has a map member.
func label(name string, json bool) string {
	switch {
	case name == "",
		json && jsonMemberName.MatchString(name),
		!json && xmlMemberName.MatchString(name):
		return name
	}
	return "{key}"
}

// valued says whether t holds a value of its own, which an XML element
// with text or any JSON scalar does.
func (t *Tree) valued() bool { return t.text != "" || t.kind != 0 }

// ParseXML parses body through encoding/xml tokens, so an element no
// struct names is kept. Comments, processing instructions and namespace
// declarations are dropped, whitespace-only text beside child elements
// too; an attribute becomes an @name leaf.
func ParseXML(body []byte) (*Tree, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var stack []*Tree
	var hasElems []bool // per stack entry: whether a child element opened, kept or not
	var root *Tree
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, xmlError(err)
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			if root != nil {
				return nil, errors.New("body is not XML: more than one root element")
			}
			if len(stack) > 0 {
				hasElems[len(stack)-1] = true
			}
			stack, hasElems = append(stack, xmlElement(tok)), append(hasElems, false)
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text += string(tok)
			} else if len(bytes.TrimSpace(tok)) > 0 {
				return nil, errors.New("body is not XML: text outside the root element")
			}
		case xml.EndElement:
			n, elems := stack[len(stack)-1], hasElems[len(stack)-1]
			stack, hasElems = stack[:len(stack)-1], hasElems[:len(stack)-1]
			if elems && strings.TrimSpace(n.text) == "" {
				n.text = ""
			}
			switch {
			case len(stack) == 0:
				root = n
			case n.valued() || len(n.kids) > 0:
				parent := stack[len(stack)-1]
				parent.kids = append(parent.kids, n)
			}
		}
	}
	if root == nil {
		return nil, errors.New("body is not XML: no root element")
	}
	return root, nil
}

func xmlElement(tok xml.StartElement) *Tree {
	n := &Tree{name: tok.Name.Local, member: tok.Name.Local == "item" || tok.Name.Local == "member"}
	for _, a := range tok.Attr {
		if a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns") {
			continue
		}
		n.kids = append(n.kids, &Tree{name: "@" + a.Name.Local, text: a.Value})
	}
	return n
}

// xmlError keeps only the line of a syntax error: the decoder's message
// can quote the body.
func xmlError(err error) error {
	var se *xml.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("body is not XML: syntax error on line %d", se.Line)
	}
	return errors.New("body is not XML")
}

// ParseJSON parses a JSON 1.1 body through a generic walk with UseNumber,
// so a key no struct names is kept. A null, an empty object and an empty
// array are absent; an array's elements are set members named by its key.
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
	if root := jsonValue("", v); root != nil {
		return root, nil
	}
	return &Tree{}, nil
}

// jsonField returns the nodes a field holds: one set member per array
// element, or the value itself.
func jsonField(name string, v any) []*Tree {
	arr, ok := v.([]any)
	if !ok {
		if n := jsonValue(name, v); n != nil {
			return []*Tree{n}
		}
		return nil
	}
	var out []*Tree
	for _, e := range arr {
		if n := jsonValue(name, e); n != nil {
			n.member = true
			out = append(out, n)
		}
	}
	return out
}

// jsonValue returns v as a node named name, or nil when v is absent. An
// array reaches it only nested in another, so its elements are unnamed.
func jsonValue(name string, v any) *Tree {
	n := &Tree{name: name, json: true}
	switch v := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			n.kids = append(n.kids, jsonField(k, v[k])...)
		}
	case []any:
		n.kids = jsonField("", v)
	case string:
		n.text, n.kind = v, 's'
	case json.Number:
		n.text, n.kind = numberValue(v), 'n'
	case bool:
		n.text, n.kind = strconv.FormatBool(v), 'b'
	}
	if !n.valued() && len(n.kids) == 0 {
		return nil
	}
	return n
}

// numberValue spells a JSON number's exact value one way, digits and a
// power of ten, so 1.7E9 and 1700000000 both give 17e8. It does no
// arithmetic, so no exponent can make it slow.
func numberValue(num json.Number) string {
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
// chain of its ancestors and nothing else, so its paths and ignore
// entries read as the whole body's. It returns nil when there is none.
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
				return &Tree{name: n.name, json: n.json, member: n.member, kids: []*Tree{got}}
			}
		}
		return nil
	}
	return walk(t, 0)
}

// MergePages returns the union of a paged list's pages: every set member
// of every page, and the first page's value of any other field (the
// paging fields differ by page, and Diff ignores them).
//
// ponytail: a list whose items are not set members (S3's and Route53's
// flattened lists) merges into one item; add a rule when a loader pages one.
func MergePages(pages ...*Tree) *Tree {
	var out *Tree
	for _, p := range pages {
		switch {
		case p == nil:
		case out == nil:
			out = clone(p)
		default:
			merge(out, p)
		}
	}
	return out
}

// merge adds src's kids to dst, which MergePages owns.
func merge(dst, src *Tree) {
	for _, k := range src.kids {
		i := -1
		if !k.member {
			i = slices.IndexFunc(dst.kids, func(d *Tree) bool { return !d.member && d.name == k.name })
		}
		if i < 0 {
			dst.kids = append(dst.kids, clone(k))
			continue
		}
		merge(dst.kids[i], k)
	}
}

func clone(t *Tree) *Tree {
	c := *t
	c.kids = make([]*Tree, len(t.kids))
	for i, k := range t.kids {
		c.kids[i] = clone(k)
	}
	return &c
}

// Diff compares a recorded body with fakeaws's rendering. It returns the
// paths only the recording holds or whose value differs, and the paths
// only the rendering holds, each sorted; equal is both empty. A path
// names a set member's index in its own tree (vpcSet/item[2]/isDefault),
// and a member with no counterpart is named whole. Two differently named
// XML roots are named and nothing under them compared. key's ignore
// entries apply here and nowhere else. A nil tree is an empty body.
//
// A path is names shown through label, never a value.
func Diff(key LoadKey, recorded, rendered *Tree) (recordedOnly, renderedOnly []string) {
	recorded, rendered = orEmpty(recorded), orEmpty(rendered)
	if recorded.name != "" && rendered.name != "" && recorded.name != rendered.name {
		return []string{label(recorded.name, recorded.json)}, []string{label(rendered.name, rendered.json)}
	}
	d := differ{ignore: map[string]bool{}}
	for _, e := range loadIgnores {
		if e.Key == key {
			d.ignore[e.Path] = true
		}
	}
	recordedOnly, renderedOnly = d.node(recorded, rendered, "")
	sort.Strings(recordedOnly)
	sort.Strings(renderedOnly)
	return recordedOnly, renderedOnly
}

func orEmpty(t *Tree) *Tree {
	if t == nil {
		return &Tree{}
	}
	return t
}

type differ struct{ ignore map[string]bool }

type groupKey struct {
	name   string
	json   bool
	member bool
}

// kids groups t's compared kids by name. shape is t's index-free path.
func (d differ) kids(t *Tree, shape string) map[groupKey][]*Tree {
	out := map[groupKey][]*Tree{}
	for _, k := range t.kids {
		if alwaysIgnored[k.name] || d.ignore[join(shape, k.name)] {
			continue
		}
		g := groupKey{k.name, k.json, k.member}
		out[g] = append(out[g], k)
	}
	return out
}

// node compares a recorded node with a rendered one at index-free path
// shape, returning paths relative to the two.
func (d differ) node(a, b *Tree, shape string) (rec, ren []string) {
	if a.text != b.text || a.kind != b.kind {
		if a.valued() {
			rec = append(rec, "")
		}
		if b.valued() {
			ren = append(ren, "")
		}
	}
	as, bs := d.kids(a, shape), d.kids(b, shape)
	for g := range bs {
		if _, ok := as[g]; !ok {
			as[g] = nil
		}
	}
	for g, ak := range as {
		var r, n []string
		if g.member {
			r, n = d.members(label(g.name, g.json), ak, bs[g], join(shape, g.name))
		} else {
			r, n = d.fields(label(g.name, g.json), ak, bs[g], join(shape, g.name))
		}
		rec, ren = append(rec, r...), append(ren, n...)
	}
	return rec, ren
}

// fields pairs same-named kids that are not set members by position,
// naming the index only when a name repeats.
func (d differ) fields(name string, as, bs []*Tree, shape string) (rec, ren []string) {
	for i := range max(len(as), len(bs)) {
		seg := name
		if len(as) > 1 || len(bs) > 1 {
			seg = fmt.Sprintf("%s[%d]", name, i)
		}
		a, b := &Tree{}, &Tree{}
		if i < len(as) {
			a = as[i]
		}
		if i < len(bs) {
			b = bs[i]
		}
		r, n := d.node(a, b, shape)
		rec, ren = append(rec, under(seg, r)...), append(ren, under(seg, n)...)
	}
	return rec, ren
}

// members pairs set members as a multiset. Equal members pair first, by
// form; each remaining one pairs with the remaining member on the other
// side it differs from on the fewest paths, ties by index. A member left
// over is named whole.
//
// ponytail: O(n·m) node diffs over the members no equal one pairs; fine
// for one account's read, index members by id if loads reach thousands.
func (d differ) members(name string, as, bs []*Tree, shape string) (rec, ren []string) {
	seg := func(i int) string { return fmt.Sprintf("%s[%d]", name, i) }
	usedA, usedB := make([]bool, len(as)), make([]bool, len(bs))
	byForm := map[string][]int{}
	for j, b := range bs {
		f := d.form(b, shape)
		byForm[f] = append(byForm[f], j)
	}
	for i, a := range as {
		f := d.form(a, shape)
		if js := byForm[f]; len(js) > 0 {
			usedA[i], usedB[js[0]], byForm[f] = true, true, js[1:]
		}
	}
	type pair struct {
		i, j     int
		rec, ren []string
	}
	var pairs []pair
	for i, a := range as {
		for j, b := range bs {
			if !usedA[i] && !usedB[j] {
				r, n := d.node(a, b, shape)
				pairs = append(pairs, pair{i, j, r, n})
			}
		}
	}
	sort.SliceStable(pairs, func(x, y int) bool {
		return len(pairs[x].rec)+len(pairs[x].ren) < len(pairs[y].rec)+len(pairs[y].ren)
	})
	for _, p := range pairs {
		if usedA[p.i] || usedB[p.j] {
			continue
		}
		usedA[p.i], usedB[p.j] = true, true
		rec, ren = append(rec, under(seg(p.i), p.rec)...), append(ren, under(seg(p.j), p.ren)...)
	}
	for i, used := range usedA {
		if !used {
			rec = append(rec, seg(i))
		}
	}
	for j, used := range usedB {
		if !used {
			ren = append(ren, seg(j))
		}
	}
	return rec, ren
}

// form spells t under the rules node compares by, so two members have
// the same form exactly when node finds no difference between them.
func (d differ) form(t *Tree, shape string) string {
	parts := []string{string(t.kind) + strconv.Quote(t.text)}
	for g, ks := range d.kids(t, shape) {
		forms := make([]string, len(ks))
		for i, k := range ks {
			forms[i] = d.form(k, join(shape, g.name))
		}
		if g.member {
			sort.Strings(forms)
		}
		parts = append(parts, fmt.Sprintf("%q %t %q", g.name, g.member, forms))
	}
	sort.Strings(parts[1:])
	return strings.Join(parts, ",")
}

// under prefixes each path relative to seg with seg.
func under(seg string, rels []string) []string {
	out := make([]string, len(rels))
	for i, r := range rels {
		out[i] = join(seg, r)
	}
	return out
}

func join(parent, child string) string {
	switch {
	case parent == "":
		return child
	case child == "":
		return parent
	}
	return parent + "/" + child
}
