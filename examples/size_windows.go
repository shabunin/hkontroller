package main

import "golang.org/x/term"

// watchSize sets terminal width once, windows has no resize signal.
// Unknown size is reported as 0, then default 80 columns stay.
func watchSize(fd int, t *term.Terminal) {
	if w, h, err := term.GetSize(fd); err == nil && w > 0 && h > 0 {
		_ = t.SetSize(w, h)
	}
}
