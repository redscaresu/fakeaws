// Package models holds the domain-error sentinels handlers and repository
// share. The four sentinels carry distinct wire-format implications:
//
//   - ErrNotFound        → 404 across all wire formats
//   - ErrInUse           → 409 with "in use by another resource" reason
//                          (FK-blocked delete; e.g., subnet referenced by instance)
//   - ErrTerminalState   → 409 with "resource state can't transition" reason
//                          (e.g., RestoreSecret after recovery window elapsed)
//   - ErrConflict        → 409 generic catch-all (new code should pick a more
//                          specific sentinel above; this is the fallback)
//
// Per concepts.md § "Lessons we are explicitly carrying over" item 4 and
// the standing-pattern "Distinct 409 sentinels" in S43-T10's seed.
package models

import "errors"

var (
	// ErrNotFound — the resource the caller named does not exist (or
	// is in a different account/region than the caller's request).
	ErrNotFound = errors.New("resource not found")

	// ErrInUse — caller is trying to delete a resource that another
	// resource depends on (FK-blocked delete).
	ErrInUse = errors.New("resource in use by another resource")

	// ErrTerminalState — caller is trying to transition a resource
	// that's already in a state from which the requested transition
	// is forbidden (e.g., destroyed, terminated, deleted).
	ErrTerminalState = errors.New("resource is in a terminal state")

	// ErrConflict — generic 409 fallback. New code should reach for
	// ErrInUse or ErrTerminalState first; ErrConflict is for cases
	// where neither fits cleanly.
	ErrConflict = errors.New("resource conflict")
)
