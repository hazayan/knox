// Package client implements the Knox CLI client commands.
package client

import (
	"flag"
	"strings"
)

// Command represents a CLI command with its execution logic and metadata.
type Command struct {
	// Run contains the command execution logic.
	// If Run is nil, the command is not runnable.
	Run func(cmd *Command, args []string) *ErrorStatus

	// Flag is a flag set for parsing command-line flags.
	Flag flag.FlagSet

	// UsageLine is the one-line usage message.
	// The first word in the usage line is taken as the command name.
	UsageLine string

	// Short is the short description shown in 'knox help' output.
	Short string

	// Long is the long message shown in 'knox help <this-command>' output.
	Long string
}

// Runnable reports whether the command can be run; otherwise it is a documentation pseudo-command.
func (c *Command) Runnable() bool {
	return c.Run != nil
}

// Name returns the command's name: the first word in the usage line.
func (c *Command) Name() string {
	name := c.UsageLine
	if i := strings.Index(name, " "); i >= 0 {
		name = name[:i]
	}
	return name
}

// Usage prints the command's usage information to standard output.
func (c *Command) Usage() {
	// This method would typically print usage information and call os.Exit(2)
	// For now, we provide a minimal implementation that can be expanded later
}

// ErrorStatus represents the result of executing a command.
// It contains both the error information and whether it's a server-side error.
type ErrorStatus struct {
	error       error
	serverError bool
}

// Error returns the error message.
func (e *ErrorStatus) Error() string {
	if e.error == nil {
		return ""
	}
	return e.error.Error()
}

// ShouldExit indicates whether the error should cause the program to exit.
// This is typically true for server errors and false for client/user errors.
func (e *ErrorStatus) ShouldExit() bool {
	return e.serverError
}

// VisibilityParams contains parameters for controlling command visibility and logging.
type VisibilityParams struct {
	// Logf is a function for logging informational messages.
	Logf func(format string, v ...any)

	// Errorf is a function for logging error messages.
	Errorf func(format string, v ...any)

	// SummaryMetrics is a function for reporting summary metrics.
	SummaryMetrics func(metrics map[string]uint64)

	// InvokeMetrics is a function for reporting invoke metrics.
	InvokeMetrics func(metrics map[string]string)

	// GetKeyMetrics is a function for reporting get key metrics.
	GetKeyMetrics func(metrics map[string]string)
}
