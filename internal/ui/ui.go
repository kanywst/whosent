// Package ui is the interactive view.
package ui

import (
	tea "charm.land/bubbletea/v2"

	"github.com/kanywst/whosent/pkg/diagnose"
)

// Session is one chain to show, with the inputs it is checked against. The
// view re-runs diagnose.Diagnose on it as the user scrubs time or simulates
// revocations, so it carries the inputs rather than a finished report.
type Session struct {
	// Name is a short identifier, such as a demo scenario's name or the
	// input file.
	Name string
	// Title and Summary describe the chain, for a demo scenario.
	Title   string
	Summary string
	Links   [][]byte
	Options diagnose.Options
	Input   diagnose.InputInfo
}

// Config is everything the view needs.
type Config struct {
	// Sessions are the chains to show. More than one makes them switchable,
	// as the demo tour does.
	Sessions []Session
	// Motion enables animation. Off when the user asked for none.
	Motion bool
	// ASCII replaces box-drawing and symbol glyphs with ASCII.
	ASCII bool
	// NoColor draws without colour even when NO_COLOR is unset.
	NoColor bool
}

// Run shows the view until the user quits.
func Run(cfg Config) error {
	_, err := tea.NewProgram(New(cfg)).Run()
	return err
}
