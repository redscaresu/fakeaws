package audit

// matrix.go — coverage_matrix.yaml's schema and the one rule both
// TestFullCoverageAudit and examples/load_round_trip_test.go read it by:
// which working examples a load round-trips.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"gopkg.in/yaml.v3"
)

// CoverageMatrixEntry mirrors the YAML schema documented in
// coverage_matrix.yaml and slices-43-48-plan.md S48-T7.
type CoverageMatrixEntry struct {
	AwsService              string `yaml:"aws_service"`
	AwsResourceType         string `yaml:"aws_resource_type"`
	ScenarioResourceType    string `yaml:"scenario_resource_type,omitempty"`
	WorkingExempt           bool   `yaml:"working_exempt,omitempty"`
	WorkingExemptReason     string `yaml:"working_exempt_reason,omitempty"`
	MisconfiguredExempt     bool   `yaml:"misconfigured_exempt,omitempty"`
	MisconfiguredReason     string `yaml:"misconfigured_exempt_reason,omitempty"`
	UpdatesExempt           bool   `yaml:"updates_exempt,omitempty"`
	UpdatesReason           string `yaml:"updates_exempt_reason,omitempty"`
	WorkingDirName          string `yaml:"working_dir_name,omitempty"`
	MisconfiguredDirName    string `yaml:"misconfigured_dir_name,omitempty"`
	UpdatesDirName          string `yaml:"updates_dir_name,omitempty"`
	IntegrationTestFuncName string `yaml:"integration_test_func_name,omitempty"`
	// Loadable marks a type a POST /mock/load of a recorded read gives a
	// fresh fakeaws, so a plan of its applied state against it is clean;
	// a row is loadable or names why not in LoadableExemptReason.
	Loadable             bool   `yaml:"loadable,omitempty"`
	LoadableExemptReason string `yaml:"loadable_exempt_reason,omitempty"`
}

// CoverageMatrix is the top-level YAML shape.
type CoverageMatrix struct {
	Entries []CoverageMatrixEntry `yaml:"entries"`
}

// LoadCoverageMatrix decodes the matrix at path, refusing a column the
// schema does not hold, so a misspelt one is an error, never a default.
func LoadCoverageMatrix(path string) (*CoverageMatrix, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	var m CoverageMatrix
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return &m, nil
}

// blockLine matches a resource or data block's type in a .tf file.
var blockLine = regexp.MustCompile(`(?m)^(resource|data) "([a-z0-9_]+)"`)

// ExampleTypes are the matrix rows the .tf files in dir declare, sorted
// and once each: a resource block's type, and a data block's
// "data.<type>" row, or its type's row when the matrix has none.
func (m *CoverageMatrix) ExampleTypes(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.tf"))
	if err != nil {
		return nil, err
	}
	var types []string
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, b := range blockLine.FindAllSubmatch(body, -1) {
			typ := string(b[2])
			if string(b[1]) == "data" && m.entry("data."+typ) != nil {
				typ = "data." + typ
			}
			types = append(types, typ)
		}
	}
	slices.Sort(types)
	return slices.Compact(types), nil
}

func (m *CoverageMatrix) entry(typ string) *CoverageMatrixEntry {
	i := slices.IndexFunc(m.Entries, func(e CoverageMatrixEntry) bool { return e.AwsResourceType == typ })
	if i < 0 {
		return nil
	}
	return &m.Entries[i]
}

// RoundTripExamples are the examples/working/ directories whose every
// type is a loadable row, the ones a load round-trips, each by name with
// its types. A type with no row is not loadable.
func (m *CoverageMatrix) RoundTripExamples(root string) (map[string][]string, error) {
	dirs, err := filepath.Glob(filepath.Join(root, "examples", "working", "*", "main.tf"))
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, f := range dirs {
		types, err := m.ExampleTypes(filepath.Dir(f))
		if err != nil {
			return nil, err
		}
		if len(types) > 0 && !slices.ContainsFunc(types, func(typ string) bool {
			e := m.entry(typ)
			return e == nil || !e.Loadable
		}) {
			out[filepath.Base(filepath.Dir(f))] = types
		}
	}
	return out, nil
}
