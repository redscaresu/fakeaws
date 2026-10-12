package handlers

import (
	"cmp"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
)

// ec2NotModelled is fixed: infrafactory matches it to route a refusal
// to docs/mock-gaps.md instead of learning a pitfall from it.
const ec2NotModelled = "not modelled by fakeaws"

// ec2Filter is one Filter.N of an EC2 Describe. A row passes it when
// one of the row's values for name matches one of values; a row must
// pass every Filter.N.
type ec2Filter struct {
	n          string // the N of Filter.N, as sent, which names a filter fakeaws cannot read
	name       string
	values     []*regexp.Regexp
	unreadable bool // a non-digit N, a key that is neither one Name nor Value.<digits>, or a value that does not compile
}

// parseEC2Filters reads Filter.N.Name / Filter.N.Value.M into one
// ec2Filter per N, in N order. A name repeated across Filter.N stays
// separate filters, and every index is read, so a gap in N or M drops
// nothing (unlike queryListValues, which stops at the first gap). A
// Filter.N fakeaws cannot read is marked, never dropped, so refuse
// names it.
func parseEC2Filters(p url.Values) []ec2Filter {
	byN := map[string]*ec2Filter{}
	for k, vs := range p {
		rest, ok := strings.CutPrefix(k, "Filter.")
		if !ok {
			continue
		}
		n, field, _ := strings.Cut(rest, ".")
		f := byN[n]
		if f == nil {
			f = &ec2Filter{n: n, unreadable: !ec2IsIndex(n)}
			byN[n] = f
		}
		m, isValue := strings.CutPrefix(field, "Value.")
		switch {
		case field == "Name" && len(vs) == 1:
			f.name = vs[0]
		case isValue && ec2IsIndex(m):
			for _, v := range vs {
				re, err := ec2Wildcard(v)
				if err != nil {
					f.unreadable = true
					continue
				}
				f.values = append(f.values, re)
			}
		default:
			f.unreadable = true
		}
	}
	ns := slices.SortedFunc(maps.Keys(byN), func(a, b string) int {
		return cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(a, b))
	})
	out := make([]ec2Filter, len(ns))
	for i, n := range ns {
		out[i] = *byN[n]
	}
	return out
}

// ec2Wildcard compiles an AWS filter value: * matches any run of
// characters, / included, ? zero or one, and a backslash makes the
// next character literal. Not path.Match, whose * stops at /. It
// errors on a value too large to compile (millions of *).
func ec2Wildcard(value string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString(`(?s)^`)
	escaped := false
	for _, r := range value {
		switch {
		case escaped:
			b.WriteString(regexp.QuoteMeta(string(r)))
			escaped = false
		case r == '\\':
			escaped = true
		case r == '*':
			b.WriteString(`.*`)
		case r == '?':
			b.WriteString(`.?`)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	if escaped {
		b.WriteString(`\\`) // a trailing backslash is itself
	}
	b.WriteString(`$`)
	return ec2Compile(b.String())
}

// ec2Compile is regexp.Compile; a test swaps it to fail the way a
// multi-megabyte value does, without allocating one.
var ec2Compile = regexp.Compile

// ec2IsIndex reports whether s is a list index: non-empty, all digits.
func ec2IsIndex(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// ec2FilterTable is what one Describe honours: values maps each
// filter name to a row's values for it, "" meaning the row lacks the
// attribute, so it matches no value, * and ? included (an unattached
// ENI's attachment.instance-id). Setting tagID opts the table
// into tag:<Key>, tag-key and tag-value, matched against the tags of
// the resource tagID(row) names.
type ec2FilterTable[R any] struct {
	values map[string]func(R) []string
	tagID  func(R) string
}

// unmodelled lists what t cannot honour in filters: each name it
// lacks, and as Filter.<N> each Filter.N with no Name, no Value or
// anything unreadable, since there may be no name to print.
func (t ec2FilterTable[R]) unmodelled(filters []ec2Filter) []string {
	var out []string
	for _, f := range filters {
		switch {
		case f.name == "" || len(f.values) == 0 || f.unreadable:
			out = append(out, "Filter."+f.n)
		case t.valuesFor(f.name) == nil:
			out = append(out, f.name)
		}
	}
	return out
}

// matches reports whether row passes every filter. tags holds each
// resource's tagSet by id, as tagSets returns it. Call it only once
// refuse has passed: a name t lacks matches nothing.
func (t ec2FilterTable[R]) matches(row R, filters []ec2Filter, tags map[string][]ec2ResourceTagXML) bool {
	for _, f := range filters {
		get := t.valuesFor(f.name)
		if get == nil || !slices.ContainsFunc(get(row, tags), func(v string) bool {
			return slices.ContainsFunc(f.values, func(re *regexp.Regexp) bool { return re.MatchString(v) })
		}) {
			return false
		}
	}
	return true
}

// valuesFor returns how t reads filter name's values off a row, and
// nil for a name t does not honour (tag: with no key among them). A
// tag's value is kept even when "": tag-value=* matches it.
func (t ec2FilterTable[R]) valuesFor(name string) func(R, map[string][]ec2ResourceTagXML) []string {
	if get := t.values[name]; get != nil {
		return func(row R, _ map[string][]ec2ResourceTagXML) []string {
			// Clone first: get may hand back the row's own slice.
			return slices.DeleteFunc(slices.Clone(get(row)), func(v string) bool { return v == "" })
		}
	}
	if t.tagID == nil {
		return nil
	}
	var pick func(ec2ResourceTagXML) (string, bool)
	switch key, isKey := strings.CutPrefix(name, "tag:"); {
	case name == "tag-key":
		pick = func(tag ec2ResourceTagXML) (string, bool) { return tag.Key, true }
	case name == "tag-value":
		pick = func(tag ec2ResourceTagXML) (string, bool) { return tag.Value, true }
	case isKey && key != "":
		pick = func(tag ec2ResourceTagXML) (string, bool) { return tag.Value, tag.Key == key }
	default:
		return nil
	}
	return func(row R, tags map[string][]ec2ResourceTagXML) []string {
		var out []string
		for _, tag := range tags[t.tagID(row)] {
			if v, ok := pick(tag); ok {
				out = append(out, v)
			}
		}
		return out
	}
}

// refuse answers action with one 501 NotImplemented naming, deduped
// and sorted bytewise, all that t cannot honour in filters and each
// param the caller did not read (unread holds raw param keys), and
// reports whether it wrote. 501 is fakeaws's own refusal, not a claim
// about AWS: AWS answers an unknown filter name 400
// InvalidParameterValue, which would blame valid HCL.
func (t ec2FilterTable[R]) refuse(w http.ResponseWriter, action string, filters []ec2Filter, unread []string) bool {
	names := t.unmodelled(filters)
	for _, k := range unread {
		names = append(names, ec2ParamName(k))
	}
	if len(names) == 0 {
		return false
	}
	slices.Sort(names)
	awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusNotImplemented, "NotImplemented",
		fmt.Sprintf("%s: %s: %s", action, ec2NotModelled, strings.Join(slices.Compact(names), ", ")))
	return true
}

// ec2ParamName names a Query param by its shape, each list index
// written N: GroupName.2 is GroupName.N, AllowReassociation itself.
func ec2ParamName(k string) string {
	parts := strings.Split(k, ".")
	for i, s := range parts {
		if ec2IsIndex(s) {
			parts[i] = "N"
		}
	}
	return strings.Join(parts, ".")
}
