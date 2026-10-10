package diagnose

import "github.com/kanywst/whosent/internal/mandatum/mda"

// buildMatrix traces every capability from the link that grants it down to
// the leaf, so that a renderer can draw authority narrowing as it goes.
//
// A row starts at the sponsor's grant, one per capability. At each hop a
// child capability joins the row of the parent capability it came from (the
// same attribution the hop diff uses). A child capability no parent covers
// starts a row of its own at that link, marked widened: that is authority
// appearing from nowhere, and it is the thing the matrix exists to make
// visible.
func buildMatrix(r *Report) Matrix {
	n := len(r.Links)
	var m Matrix
	rowOf := make([][]int, n) // rowOf[link][cap] = row index
	// cur is the capability that stands for each row at the link last
	// processed: what the row's authority amounts to by then.
	var cur []mda.Capability
	newRow := func(origin int, c mda.Capability) int {
		m.Rows = append(m.Rows, Row{
			Label:  CapLabel(c),
			Origin: origin,
			Root:   c,
			Cells:  make([]Cell, n),
		})
		cur = append(cur, c)
		return len(m.Rows) - 1
	}

	for i := range r.Links {
		c := r.Links[i].Claims
		if c == nil {
			continue
		}
		caps := c.Mandatum.Capabilities
		rowOf[i] = make([]int, len(caps))
		parent := (*mda.Claims)(nil)
		if i > 0 {
			parent = r.Links[i-1].Claims
		}
		switch {
		case i == 0:
			for j, cp := range caps {
				row := newRow(0, cp)
				rowOf[i][j] = row
				m.Rows[row].Cells[i] = Cell{Kind: CellHeld, Caps: []int{j}}
			}
		case parent == nil:
			for j, cp := range caps {
				row := newRow(i, cp)
				rowOf[i][j] = row
				m.Rows[row].Cells[i] = Cell{Kind: CellOrphan, Changed: true, Caps: []int{j}}
			}
		default:
			pcaps := parent.Mandatum.Capabilities
			for j, cp := range caps {
				owner, same := -1, false
				for k, pp := range pcaps {
					if !entails(pp, cp) {
						continue
					}
					if entails(cp, pp) {
						owner, same = k, true
						break
					}
					if owner < 0 {
						owner = k
					}
				}
				if owner < 0 {
					row := newRow(i, cp)
					rowOf[i][j] = row
					m.Rows[row].Cells[i] = Cell{Kind: CellWidened, Changed: true, Caps: []int{j}}
					continue
				}
				row := rowOf[i-1][owner]
				rowOf[i][j] = row
				cell := &m.Rows[row].Cells[i]
				above := m.Rows[row].Cells[i-1]
				if len(cell.Caps) == 0 {
					cur[row] = cp
				}
				cell.Caps = append(cell.Caps, j)
				kind := CellNarrowed
				if same && len(cell.Caps) == 1 {
					// Passed on unchanged, so it is whatever it was above:
					// held, narrowed, or still widened.
					kind = above.Kind
				}
				if !same || len(cell.Caps) > 1 {
					cell.Changed = true
				}
				// A narrowed or widened holding never goes back to held.
				if cell.Kind == CellAbsent || rank(kind) > rank(cell.Kind) {
					cell.Kind = kind
				}
			}
			// A row no child capability joined is not necessarily dropped.
			// If some child capability covers the row's authority whole (a
			// broader grant, or a duplicate attributed elsewhere), the link
			// still holds it, unchanged. The row carries on, and the next
			// link is asked the same question about it.
			for row := range m.Rows {
				cell := &m.Rows[row].Cells[i]
				above := m.Rows[row].Cells[i-1].Kind
				if len(cell.Caps) > 0 || m.Rows[row].Origin >= i || above == CellAbsent || above == CellUnknown {
					continue
				}
				for j, cp := range caps {
					// Only a capability with a row of its own descending
					// from above counts; one that widened is not a holding.
					if r := rowOf[i][j]; m.Rows[r].Origin < i && entails(cp, cur[row]) {
						cell.Kind, cell.Caps = above, []int{j}
						break
					}
				}
			}
		}
	}

	// Mark what each link dropped, and what an unparsed link hides.
	for ri := range m.Rows {
		row := &m.Rows[ri]
		for i := range r.Links {
			if i < row.Origin {
				continue
			}
			if r.Links[i].Claims == nil {
				row.Cells[i] = Cell{Kind: CellUnknown}
				continue
			}
			if i > row.Origin && row.Cells[i].Kind == CellAbsent {
				above := row.Cells[i-1].Kind
				row.Cells[i].Changed = above != CellAbsent && above != CellUnknown
			}
		}
	}

	for _, row := range m.Rows {
		if row.Origin == 0 {
			m.RootRows++
		}
	}
	m.Retained = make([]int, n)
	for i := range r.Links {
		for _, row := range m.Rows {
			if row.Origin != 0 {
				continue
			}
			if k := row.Cells[i].Kind; k == CellHeld || k == CellNarrowed {
				m.Retained[i]++
			}
		}
	}
	return m
}

// rank orders cell kinds so that a cell holding several capabilities shows
// the most notable one.
func rank(k CellKind) int {
	switch k {
	case CellWidened:
		return 4
	case CellOrphan:
		return 3
	case CellNarrowed:
		return 2
	case CellHeld:
		return 1
	}
	return 0
}
