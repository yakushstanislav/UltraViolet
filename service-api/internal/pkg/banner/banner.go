package banner

import (
	"fmt"
	"runtime"
	"strings"
	"unicode/utf8"
)

const (
	cReset  = "\033[0m"
	cRed    = "\033[91m"
	cOrange = "\033[33m"
	cYellow = "\033[93m"
	cLGreen = "\033[92m"
	cGreen  = "\033[32m"
	cLCyan  = "\033[96m"
	cCyan   = "\033[36m"
	cLBlue  = "\033[94m"
	cBlue   = "\033[34m"
	cMag    = "\033[35m"
	cLMag   = "\033[95m"
	cGray   = "\033[90m"
)

type glyph struct {
	rows  [5]string
	color string
	gap   bool // insert extra space before this glyph
}

var glyphs = []glyph{
	{rows: [5]string{"█   █", "█   █", "█   █", "█   █", " ███ "}, color: cRed},              // U
	{rows: [5]string{"█    ", "█    ", "█    ", "█    ", "█████"}, color: cOrange},           // L
	{rows: [5]string{"█████", "  █  ", "  █  ", "  █  ", "  █  "}, color: cYellow},           // T
	{rows: [5]string{"████ ", "█   █", "████ ", "█ █  ", "█  █ "}, color: cLGreen},           // R
	{rows: [5]string{" ███ ", "█   █", "█████", "█   █", "█   █"}, color: cGreen},            // A
	{rows: [5]string{"█   █", "█   █", " █ █ ", " █ █ ", "  █  "}, color: cLCyan, gap: true}, // V
	{rows: [5]string{"███", " █ ", " █ ", " █ ", "███"}, color: cCyan},                       // I
	{rows: [5]string{" ███ ", "█   █", "█   █", "█   █", " ███ "}, color: cLBlue},            // O
	{rows: [5]string{"█    ", "█    ", "█    ", "█    ", "█████"}, color: cBlue},             // L
	{rows: [5]string{"█████", "█    ", "████ ", "█    ", "█████"}, color: cMag},              // E
	{rows: [5]string{"█████", "  █  ", "  █  ", "  █  ", "  █  "}, color: cLMag},             // T
}

// Print writes the startup banner to stdout.
func Print(service, tagline string) {
	var rows [5]strings.Builder

	for i, g := range glyphs {
		if i > 0 {
			sep := " "
			if g.gap {
				sep = "   "
			}

			for r := range 5 {
				rows[r].WriteString(sep)
			}
		}

		for r := range 5 {
			rows[r].WriteString(g.color + g.rows[r] + cReset)
		}
	}

	rule := cGray + strings.Repeat("─", glyphWidth()) + cReset

	info := cLCyan + service + cReset +
		cGray + "  ·  " + cReset +
		cLMag + tagline + cReset +
		cGray + "  ·  " + cReset +
		cGray + runtime.Version() + cReset

	fmt.Println()

	for _, row := range rows {
		fmt.Printf("  %s\n", row.String())
	}

	fmt.Printf("  %s\n", rule)
	fmt.Printf("  %s\n\n", info)
}

func glyphWidth() int {
	width := 0

	for i, g := range glyphs {
		if i > 0 {
			if g.gap {
				width += 3
			} else {
				width++
			}
		}

		width += utf8.RuneCountInString(g.rows[0])
	}

	return width
}
