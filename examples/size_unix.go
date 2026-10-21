//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

// watchSize keeps terminal width up to date, so long lines are wrapped right.
// Unknown size is reported as 0, then default 80 columns stay.
func watchSize(fd int, t *term.Terminal) {
	resize := func() {
		if w, h, err := term.GetSize(fd); err == nil && w > 0 && h > 0 {
			_ = t.SetSize(w, h)
		}
	}
	resize()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			resize()
		}
	}()
}
