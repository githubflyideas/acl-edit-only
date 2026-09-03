package device

import "io"

// StreamWriter is an optional writer that receives raw terminal output
// as it arrives (line-by-line or chunk-by-chunk). Set it on Session before
// calling Open; nil means discard.
type StreamWriter interface {
	Write(p []byte) (n int, err error)
}

// SetStream attaches a live output writer to the session.
// Lines written here match what an operator would see on a real terminal,
// minus the auth phase (password is never streamed).
func (s *Session) SetStream(w io.Writer) {
	s.stream = w
}

// SetWire asks for a Go-quoted copy of every chunk the device sends, before any
// normalising, so that line endings and control bytes can be read off a bug
// report instead of guessed at.
func (s *Session) SetWire(w io.Writer) {
	s.wire = w
}
