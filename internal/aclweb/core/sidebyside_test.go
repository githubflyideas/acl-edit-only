package core

import "testing"

// TestSideBySidePairsTheChange walks the shape the page shows: unchanged lines on
// both sides with matching numbers, the added rule alone on the right, and the
// elided run reported with its length so the numbering below it stays true.
func TestSideBySidePairsTheChange(t *testing.T) {
	unified := " Advanced IPv4 ACL 3767, 2 rules,\n" +
		"@@ 4 unchanged lines @@\n" +
		" rule 200 permit udp tos max-reliability\n" +
		"+rule 2000 permit tcp destination 10.0.0.1 0 destination-port eq 443\n"
	rows := SideBySideDiff(unified)
	if len(rows) != 4 { t.Fatalf("got %d rows: %#v", len(rows), rows) }

	if rows[0].Kind != "equal" || rows[0].LeftNo != 1 || rows[0].RightNo != 1 {
		t.Errorf("first row: %#v", rows[0])
	}
	if rows[1].Kind != "skip" || rows[1].Left != "略过 4 行未变更" {
		t.Errorf("skip row: %#v", rows[1])
	}
	// The skip stood for four lines, so the next line is the sixth on both sides.
	if rows[2].Kind != "equal" || rows[2].LeftNo != 6 || rows[2].RightNo != 6 {
		t.Errorf("row after the skip: %#v", rows[2])
	}
	if rows[3].Kind != "add" || rows[3].LeftNo != 0 || rows[3].RightNo != 7 {
		t.Errorf("added row: %#v", rows[3])
	}
	if rows[3].Left != "" {
		t.Errorf("an added rule has nothing on the left, got %q", rows[3].Left)
	}
	added, removed := DiffCounts(rows)
	if added != 1 || removed != 0 { t.Errorf("counts: +%d -%d", added, removed) }
}

// TestSideBySideSetsChangedLinesOpposite covers a delete run and an insert run
// that meet: each rewritten line must sit beside the line it replaces, or the
// two columns stop lining up and the comparison is worthless.
func TestSideBySideSetsChangedLinesOpposite(t *testing.T) {
	rows := SideBySideDiff(" head\n-old one\n-old two\n+new one\n+new two\n+new three\n")
	want := []struct{ kind, left, right string }{
		{"equal", "head", "head"},
		{"replace", "old one", "new one"},
		{"replace", "old two", "new two"},
		{"add", "", "new three"},
	}
	if len(rows) != len(want) { t.Fatalf("got %d rows: %#v", len(rows), rows) }
	for i, w := range want {
		if rows[i].Kind != w.kind || rows[i].Left != w.left || rows[i].Right != w.right {
			t.Errorf("row %d: %#v, want %v", i, rows[i], w)
		}
	}
	if added, removed := DiffCounts(rows); added != 3 || removed != 2 {
		t.Errorf("counts: +%d -%d, want +3 -2", added, removed)
	}
}
