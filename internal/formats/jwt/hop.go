package jwt

import (
	"fmt"
	"strings"

	"github.com/kanywst/whosent/pkg/chain"
)

// hop describes what changed from link a to link b.
func (s *session) hop(plans []plan, a, b int) chain.Hop {
	pa, pb := plans[a], plans[b]
	h := chain.Hop{Parent: a, Child: b, Evaluable: true}
	if pb.tok < 0 || pa.tok < 0 {
		// Inside one token: the issuer says this actor acted for the one
		// before. Nothing about it can be compared.
		h.Changes = []chain.Change{{Kind: chain.ChangeInfo, Text: fmt.Sprintf("acts for %s, as the issuer states", linkTo(pa))}}
		if pb.tok >= 0 && pb.tok == pa.named {
			h.Changes[0].Text = fmt.Sprintf("acts for %s; this token makes it the current actor", linkTo(pa))
		}
		return h
	}
	prev, t := s.tokens[pa.tok], s.tokens[pb.tok]
	if prev.Problem != "" || t.Problem != "" {
		h.Evaluable = false
		h.Changes = []chain.Change{{Kind: chain.ChangeUnknown, Text: "a token of this exchange cannot be read"}}
		return h
	}
	var ch []chain.Change
	ch = append(ch, chain.Change{Kind: chain.ChangeAdded, Text: "exchanged: " + t.current().name() + " now acts for " + s.rootName()})
	if prev.ScopeClaim != "" || t.ScopeClaim != "" {
		for _, sc := range prev.Scopes {
			if contains(t.Scopes, sc) {
				ch = append(ch, chain.Change{Kind: chain.ChangeKept, Text: "scope " + sc})
			} else {
				ch = append(ch, chain.Change{Kind: chain.ChangeDropped, Text: "scope " + sc + " dropped"})
			}
		}
		for _, sc := range t.Scopes {
			if !contains(prev.Scopes, sc) {
				c := chain.Change{Kind: chain.ChangeWidened, Text: "scope " + sc + " was not in the token exchanged"}
				if prev.ScopeClaim == "" {
					c = chain.Change{Kind: chain.ChangeUnknown, Text: "scope " + sc + " (the token exchanged names no scope)"}
				}
				ch = append(ch, c)
			}
		}
	}
	switch {
	case prev.Exp != nil && t.Exp != nil && t.Exp.Before(*prev.Exp):
		ch = append(ch, chain.Change{Kind: chain.ChangeNarrowed, Text: "expires " + chain.Human(prev.Exp.Sub(*t.Exp)) + " sooner"})
	case prev.Exp != nil && t.Exp != nil && t.Exp.After(*prev.Exp):
		ch = append(ch, chain.Change{Kind: chain.ChangeWidened, Text: "expires " + chain.Human(t.Exp.Sub(*prev.Exp)) + " later"})
	case prev.Exp != nil && t.Exp == nil:
		ch = append(ch, chain.Change{Kind: chain.ChangeWidened, Text: "no longer expires"})
	}
	if a, b := orNone(strings.Join(prev.Aud, ", ")), orNone(strings.Join(t.Aud, ", ")); a != b {
		ch = append(ch, chain.Change{Kind: chain.ChangeInfo, Before: a, Text: b, Notes: []string{"audience"}})
	}
	if prev.Sub != t.Sub {
		ch = append(ch, chain.Change{Kind: chain.ChangeWidened, Before: prev.Sub, Text: t.Sub, Notes: []string{"the subject changed"}})
	}
	if prev.Iss != t.Iss {
		ch = append(ch, chain.Change{Kind: chain.ChangeInfo, Before: prev.Iss, Text: t.Iss, Notes: []string{"a different issuer: a cross-domain exchange (identity chaining)"}})
	}
	h.Changes = ch
	return h
}

// matrix is scopes by link. Within one token only the current actor's
// authority is known: a prior actor's is not in the token, so its cells are
// unknown rather than absent.
func (s *session) matrix(plans []plan) *chain.Matrix {
	type rowInfo struct {
		label  string
		origin int
		root   bool
	}
	var rows []rowInfo
	index := map[string]int{}
	firstTok := -1
	for i, p := range plans {
		if p.tok < 0 {
			continue
		}
		t := s.tokens[p.tok]
		if firstTok < 0 {
			firstTok = i
		}
		for _, sc := range t.Scopes {
			if _, ok := index[sc]; ok {
				continue
			}
			index[sc] = len(rows)
			origin := 0
			if i != firstTok {
				origin = i
			}
			rows = append(rows, rowInfo{label: sc, origin: origin, root: i == firstTok})
		}
	}
	if len(rows) == 0 {
		return nil
	}
	m := &chain.Matrix{Title: "SCOPES", Scope: "held by each token", Retained: make([]int, len(plans)), UnknownLabel: "not in the token"}
	for _, r := range rows {
		if r.root {
			m.RootRows++
		}
	}
	for _, r := range rows {
		row := chain.Row{Label: r.label, Origin: r.origin}
		for i, p := range plans {
			cell := chain.Cell{Kind: chain.CellAbsent}
			switch {
			case p.tok < 0:
				cell.Kind = chain.CellUnknown
			default:
				t := s.tokens[p.tok]
				held := contains(t.Scopes, r.label)
				var before bool
				if i > 0 && plans[i-1].tok >= 0 {
					before = contains(s.tokens[plans[i-1].tok].Scopes, r.label)
				}
				switch {
				case held && i == firstTok:
					cell.Kind = chain.CellHeld
				case held && before:
					cell.Kind = chain.CellHeld
				case held:
					cell = chain.Cell{Kind: chain.CellWidened, Changed: true}
				case before:
					cell.Changed = true
				}
				if held {
					row.Lineage = append(row.Lineage, chain.LineageEntry{Link: i, Kind: cell.Kind, Changed: cell.Changed,
						Texts: []string{fmt.Sprintf("%s in token %d", r.label, p.tok)}})
					if r.root {
						m.Retained[i]++
					}
				}
			}
			row.Cells = append(row.Cells, cell)
		}
		m.Rows = append(m.Rows, row)
	}
	aud := chain.SummaryRow{Label: "audience"}
	exp := chain.SummaryRow{Label: "expires"}
	for _, p := range plans {
		if p.tok < 0 || s.tokens[p.tok].Problem != "" {
			aud.Cells = append(aud.Cells, chain.SummaryCell{Text: "?", Dim: true})
			exp.Cells = append(exp.Cells, chain.SummaryCell{Text: "?", Dim: true})
			continue
		}
		t := s.tokens[p.tok]
		a := "none"
		if len(t.Aud) > 0 {
			a = hostOf(t.Aud[0])
			if len(t.Aud) > 1 {
				a += fmt.Sprintf(" +%d", len(t.Aud)-1)
			}
		}
		aud.Cells = append(aud.Cells, chain.SummaryCell{Text: a})
		if t.Exp == nil {
			exp.Cells = append(exp.Cells, chain.SummaryCell{Text: "never", Infinite: true})
		} else {
			exp.Cells = append(exp.Cells, chain.SummaryCell{Text: t.Exp.UTC().Format("15:04")})
		}
	}
	m.Extra = []chain.SummaryRow{aud, exp}
	return m
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
