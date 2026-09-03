package core

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// skipRe reads the count out of the elision marker the diff writes.
var skipRe = regexp.MustCompile(`^@@ (\d+) `)

// DiffRow is one line of the side-by-side view: what the configuration says now
// on the left, what it will say after the change on the right.
//
// Kind is what the row means, and the page colours it accordingly:
//
//	equal   both sides carry the same line
//	replace both sides carry a line and they differ
//	add     only the right side carries a line
//	remove  only the left side carries a line
//	skip    a run of unchanged lines that the diff left out
type DiffRow struct {
	Kind        string
	LeftNo      int // 1-based line number in the before text, 0 when there is no left line
	RightNo     int // 1-based line number in the after text, 0 when there is no right line
	Left, Right string
}

// SideBySideDiff turns the stored unified diff into rows for the two-column
// view. It reads the stored text rather than diffing the two configurations
// again, because that text is the artifact whose hash is recorded and whose
// content the operator's approval refers to: a second comparison could disagree
// with it, and then the page would be showing something nobody approved.
func SideBySideDiff(unified string) []DiffRow {
	var rows []DiffRow
	// Line numbers are counted rather than read from a hunk header, because the
	// diff this project writes has no per-hunk numbers. Its elision marker does
	// carry how many lines it stands for, so the count stays exact across a
	// skipped run — without that the numbers below every skip would be wrong,
	// and a wrong line number in the artifact an operator approves is worse than
	// no line number at all.
	leftNo, rightNo := 0, 0
	var dels, adds []string

	// flush pairs up the delete run and the insert run that just ended. Lines
	// that have a counterpart become one row each, so a rewritten line sits
	// beside the line it replaces; the remainder become one-sided rows.
	flush := func() {
		for i := 0; i < len(dels) || i < len(adds); i++ {
			switch {
			case i < len(dels) && i < len(adds):
				leftNo++; rightNo++
				rows = append(rows, DiffRow{Kind: "replace", LeftNo: leftNo, RightNo: rightNo,
					Left: dels[i], Right: adds[i]})
			case i < len(dels):
				leftNo++
				rows = append(rows, DiffRow{Kind: "remove", LeftNo: leftNo, Left: dels[i]})
			default:
				rightNo++
				rows = append(rows, DiffRow{Kind: "add", RightNo: rightNo, Right: adds[i]})
			}
		}
		dels, adds = nil, nil
	}

	for _, line := range strings.Split(unified, "\n") {
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ "):
			continue
		case strings.HasPrefix(line, "@@"):
			flush()
			n := 0
			if m := skipRe.FindStringSubmatch(line); m != nil {
				n, _ = strconv.Atoi(m[1])
				leftNo += n
				rightNo += n
			}
			rows = append(rows, DiffRow{Kind: "skip",
				Left: fmt.Sprintf("略过 %d 行未变更", n), Right: fmt.Sprintf("略过 %d 行未变更", n)})
		case strings.HasPrefix(line, "-"):
			dels = append(dels, line[1:])
		case strings.HasPrefix(line, "+"):
			adds = append(adds, line[1:])
		default: // a context line, which the diff writes with a leading space
			flush()
			leftNo++; rightNo++
			text := strings.TrimPrefix(line, " ")
			rows = append(rows, DiffRow{Kind: "equal", LeftNo: leftNo, RightNo: rightNo,
				Left: text, Right: text})
		}
	}
	flush()
	return rows
}

// DiffCounts reports how many lines the change adds and removes, so the page can
// say so above the table instead of leaving it to be counted by eye.
func DiffCounts(rows []DiffRow) (added, removed int) {
	for _, r := range rows {
		switch r.Kind {
		case "add":
			added++
		case "remove":
			removed++
		case "replace":
			added++; removed++
		}
	}
	return added, removed
}
