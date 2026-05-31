package portscan

import (
	"sort"
	"strconv"
	"strings"
)

// FormatPortSpec builds a comma-separated port list with ranges from the
// given port set. The output is compatible with both masscan (-p) and
// zmap (-p) arguments — collapsing consecutive ports into "start-end"
// keeps the command line short for large port sweeps.
//
// Example: [22, 80, 443, 444, 445, 8080] → "22,80,443-445,8080".
func FormatPortSpec(ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}

	sorted := append([]uint16(nil), ports...)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	var b strings.Builder

	writeRange := func(start, end uint16) {
		if b.Len() > 0 {
			b.WriteByte(',')
		}

		if start == end {
			b.WriteString(strconv.FormatUint(uint64(start), 10))

			return
		}

		b.WriteString(strconv.FormatUint(uint64(start), 10))
		b.WriteByte('-')
		b.WriteString(strconv.FormatUint(uint64(end), 10))
	}

	rangeStart := sorted[0]
	prev := sorted[0]

	for i := 1; i < len(sorted); i++ {
		p := sorted[i]
		if p == prev {
			continue
		}

		if p == prev+1 {
			prev = p

			continue
		}

		writeRange(rangeStart, prev)
		rangeStart = p
		prev = p
	}

	writeRange(rangeStart, prev)

	return b.String()
}

// StripCRTail returns the visible tail of a stdout line after the last
// carriage return. masscan and zmap both interleave progress lines (no
// newline, just '\r') with their normal output, so a single physical line
// may look like "rate: 1000 pps\r{json}".
func StripCRTail(line string) string {
	if i := strings.LastIndex(line, "\r"); i >= 0 {
		line = line[i+1:]
	}

	return strings.TrimSpace(line)
}
