package core

import (
	"fmt"
	"io"
	"strings"

	"github.com/chzyer/readline"
)

// TerminalIO defines the interface for interacting with the terminal UI.
// This decouples the core logic from the specific library (readline) and simple fmt.Print calls.
type TerminalIO interface {
	Readline() (string, error)
	SetPrompt(p string)
	SetEntryCompleter(completer *readline.PrefixCompleter)
	ReadPassword(prompt string) ([]byte, error)
	Printf(format string, a ...interface{}) (n int, err error)
	Println(a ...interface{}) (n int, err error)
	Close() error
	Refresh() // For log integration
	GetOutput() io.Writer
}

// RealTerminalIO implements TerminalIO using readline and standard output.
type RealTerminalIO struct {
	rl *readline.Instance
}

func NewRealTerminalIO(rl *readline.Instance) *RealTerminalIO {
	return &RealTerminalIO{rl: rl}
}

func (io *RealTerminalIO) Readline() (string, error) {
	return io.rl.Readline()
}

func (io *RealTerminalIO) SetPrompt(p string) {
	io.rl.SetPrompt(p)
}

func (io *RealTerminalIO) SetEntryCompleter(completer *readline.PrefixCompleter) {
	io.rl.Config.AutoComplete = completer
}

func (io *RealTerminalIO) ReadPassword(prompt string) ([]byte, error) {
	return io.rl.ReadPassword(prompt)
}

func (io *RealTerminalIO) Printf(format string, a ...interface{}) (n int, err error) {
	// Typically we want to write to the readline's stdout if possible, or just fmt.Printf
	// But readline has no simple Printf, it usually captures stdout.
	return fmt.Printf(format, a...)
}

func (io *RealTerminalIO) Println(a ...interface{}) (n int, err error) {
	return fmt.Println(a...)
}

func (io *RealTerminalIO) Close() error {
	return io.rl.Close()
}

func (io *RealTerminalIO) Refresh() {
	io.rl.Refresh()
}

func (io *RealTerminalIO) GetOutput() io.Writer {
	return io.rl.Config.Stdout
}

// MockTerminalIO implements TerminalIO for testing.
type MockTerminalIO struct {
	InputBuffer  []string
	OutputBuffer strings.Builder
	LastPassword string
	Prompt       string
	InputIndex   int
}

func NewMockTerminalIO() *MockTerminalIO {
	return &MockTerminalIO{
		InputBuffer: make([]string, 0),
	}
}

func (m *MockTerminalIO) Readline() (string, error) {
	if m.InputIndex >= len(m.InputBuffer) {
		return "", io.EOF
	}
	line := m.InputBuffer[m.InputIndex]
	m.InputIndex++
	return line, nil
}

func (m *MockTerminalIO) SetPrompt(p string) {
	m.Prompt = p
}

func (m *MockTerminalIO) SetEntryCompleter(completer *readline.PrefixCompleter) {
	// No-op for mock
}

func (m *MockTerminalIO) ReadPassword(prompt string) ([]byte, error) {
	// Mock implementation: return dummy or predefined password
	return []byte("mock_password"), nil
}

func (m *MockTerminalIO) Printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(&m.OutputBuffer, format, a...)
}

func (m *MockTerminalIO) Println(a ...interface{}) (n int, err error) {
	return fmt.Fprintln(&m.OutputBuffer, a...)
}

func (m *MockTerminalIO) Close() error {
	return nil
}

func (m *MockTerminalIO) Refresh() {
	// No-op
}

func (m *MockTerminalIO) GetOutput() io.Writer {
	return &m.OutputBuffer
}
