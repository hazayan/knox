// Package dbus implements the FreeDesktop Secret Service API.
// Spec: https://specifications.freedesktop.org/secret-service-spec/latest/
package dbus

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/hazayan/knox/pkg/observability/metrics"
)

// PromptHandler defines the interface for handling user prompts.
// Applications can implement this interface to provide custom prompt behavior.
type PromptHandler interface {
	// ShowPrompt displays a prompt to the user and returns their decision.
	// windowID: The window ID that triggered the prompt (can be empty)
	// message: The message to display to the user
	// Returns: true if approved, false if rejected, error if failed
	ShowPrompt(windowID, message string) (bool, error)
}

// DefaultPromptHandler is the default implementation that auto-approves prompts.
// This maintains backward compatibility while allowing for future enhancement.
type DefaultPromptHandler struct{}

// ShowPrompt implements the PromptHandler interface with auto-approval.
func (d *DefaultPromptHandler) ShowPrompt(windowID, message string) (bool, error) {
	// Auto-approve for backward compatibility
	// In a production environment, this could be extended to show actual dialogs
	log.Printf("Prompt auto-approved: %s (window: %s)", message, windowID)
	return true, nil
}

// Prompt represents a user prompt for confirmation or input.
// This is used for operations that require user approval.
type Prompt struct {
	conn      *dbus.Conn
	path      dbus.ObjectPath
	props     *prop.Properties
	callback  func(bool) // Callback to execute when prompt completes
	completed bool       // Whether the prompt has been completed
	handler   PromptHandler
	message   string        // The message to display to the user
	createdAt time.Time     // When the prompt was created
	timeout   time.Duration // Timeout for prompt response
}

// PromptOption represents a function that configures a Prompt.
type PromptOption func(*Prompt)

// WithPromptHandler sets a custom prompt handler for the prompt.
func WithPromptHandler(handler PromptHandler) PromptOption {
	return func(p *Prompt) {
		p.handler = handler
	}
}

// WithPromptMessage sets the message to display in the prompt.
func WithPromptMessage(message string) PromptOption {
	return func(p *Prompt) {
		p.message = message
	}
}

// WithPromptTimeout sets the timeout for prompt response.
func WithPromptTimeout(timeout time.Duration) PromptOption {
	return func(p *Prompt) {
		p.timeout = timeout
	}
}

// NewPrompt creates a new prompt object.
func NewPrompt(conn *dbus.Conn, callback func(bool), opts ...PromptOption) *Prompt {
	prompt := &Prompt{
		conn:      conn,
		path:      makePromptPath(generateID()),
		callback:  callback,
		completed: false,
		handler:   &DefaultPromptHandler{},
		message:   "Confirm operation?",
		createdAt: time.Now(),
		timeout:   30 * time.Second, // Default 30 second timeout
	}

	// Apply options
	for _, opt := range opts {
		opt(prompt)
	}

	prompt.setupProperties()
	return prompt
}

// Path returns the D-Bus object path for this prompt.
func (p *Prompt) Path() dbus.ObjectPath {
	return p.path
}

// Export exports the prompt to D-Bus.
func (p *Prompt) Export() error {
	if err := p.conn.Export(p, p.path, PromptInterface); err != nil {
		return fmt.Errorf("failed to export prompt: %w", err)
	}

	// Export introspection
	node := introspect.Node{
		Name: string(p.path),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			{
				Name:    PromptInterface,
				Methods: p.getMethods(),
				Signals: p.getSignals(),
			},
		},
	}
	if err := p.conn.Export(introspect.NewIntrospectable(&node), p.path, "org.freedesktop.DBus.Introspectable"); err != nil {
		return fmt.Errorf("failed to export introspection: %w", err)
	}

	return nil
}

// Unexport removes the prompt from D-Bus.
func (p *Prompt) Unexport() error {
	if err := p.conn.Export(nil, p.path, PromptInterface); err != nil {
		return fmt.Errorf("failed to unexport prompt: %w", err)
	}
	return nil
}

// Prompt methods

// Prompt prompts the user for confirmation.
// This method shows a prompt to the user and waits for their response.
func (p *Prompt) Prompt(windowID string) *dbus.Error {
	if p.completed {
		metrics.RecordDBusPrompt("Prompt", "already_completed")
		return dbus.MakeFailedError(errors.New("prompt already completed"))
	}

	p.completed = true

	// Use the prompt handler to show the prompt to the user
	approved, err := p.handler.ShowPrompt(windowID, p.message)
	if err != nil {
		metrics.RecordDBusPrompt("Prompt", "error")
		return dbus.MakeFailedError(fmt.Errorf("failed to show prompt: %w", err))
	}

	// Record prompt result
	if approved {
		metrics.RecordDBusPrompt("Prompt", "approved")
	} else {
		metrics.RecordDBusPrompt("Prompt", "rejected")
	}

	// Execute the callback with the user's decision
	if p.callback != nil {
		p.callback(approved)
	}

	// Emit Completed signal as required by FreeDesktop Secret Service spec
	// Signal signature: Completed(dismissed bool, result Variant)
	// dismissed=false because user interacted with the prompt
	p.emitCompletedSignal(false, approved)

	return nil
}

// Dismiss dismisses the prompt without user action.
// This is equivalent to the user rejecting the prompt.
func (p *Prompt) Dismiss() *dbus.Error {
	if p.completed {
		metrics.RecordDBusPrompt("Dismiss", "already_completed")
		return dbus.MakeFailedError(errors.New("prompt already completed"))
	}

	p.completed = true

	// Record prompt dismissal
	metrics.RecordDBusPrompt("Dismiss", "dismissed")

	// Execute callback with rejection
	if p.callback != nil {
		p.callback(false)
	}

	// Emit Completed signal as required by FreeDesktop Secret Service spec
	// Signal signature: Completed(dismissed bool, result Variant)
	// dismissed=true because the prompt was dismissed without user interaction
	p.emitCompletedSignal(true, false)

	return nil
}

// Helper methods

func (p *Prompt) setupProperties() {
	var err error
	p.props, err = prop.Export(p.conn, p.path, map[string]map[string]*prop.Prop{
		PromptInterface: {
			"Completed": {
				Value:    p.completed,
				Writable: false,
				Emit:     prop.EmitTrue,
				Callback: nil,
			},
		},
	})
	if err != nil {
		// Log error but don't fail - properties are optional
		log.Printf("failed to export prompt properties: %v", err)
	}
}

// emitCompletedSignal emits the Completed signal as required by the FreeDesktop spec.
// The signal notifies D-Bus clients that the prompt has been completed.
func (p *Prompt) emitCompletedSignal(dismissed, approved bool) {
	// Skip if connection is nil (e.g., in tests)
	if p.conn == nil {
		return
	}

	// Prepare result variant
	// - If dismissed, result is empty variant
	// - If approved, result contains empty variant (spec allows implementation-specific data)
	var result dbus.Variant
	if dismissed {
		result = dbus.MakeVariant("")
	} else {
		result = dbus.MakeVariant(approved)
	}

	// Emit the signal: Completed(dismissed bool, result Variant)
	err := p.conn.Emit(
		p.path,
		PromptInterface+".Completed",
		dismissed,
		result,
	)
	if err != nil {
		// Log but don't fail - signal emission is best effort
		log.Printf("failed to emit Completed signal: %v", err)
	}

	// Update the Completed property
	if p.props != nil {
		p.props.SetMust(PromptInterface, "Completed", true)
	}
}

// GetMessage returns the prompt message.
func (p *Prompt) GetMessage() string {
	return p.message
}

// SetMessage sets the prompt message.
func (p *Prompt) SetMessage(message string) {
	p.message = message
}

// GetHandler returns the current prompt handler.
func (p *Prompt) GetHandler() PromptHandler {
	return p.handler
}

// SetHandler sets a new prompt handler.
func (p *Prompt) SetHandler(handler PromptHandler) {
	p.handler = handler
}

// IsCompleted returns whether the prompt has been completed.
func (p *Prompt) IsCompleted() bool {
	return p.completed
}

// GetCreatedAt returns when the prompt was created.
func (p *Prompt) GetCreatedAt() time.Time {
	return p.createdAt
}

// GetTimeout returns the prompt timeout duration.
func (p *Prompt) GetTimeout() time.Duration {
	return p.timeout
}

func (p *Prompt) getMethods() []introspect.Method {
	return []introspect.Method{
		{
			Name: "Prompt",
			Args: []introspect.Arg{
				{Name: "window_id", Type: "s", Direction: "in"},
			},
		},
		{
			Name: "Dismiss",
			Args: []introspect.Arg{},
		},
	}
}

func (p *Prompt) getSignals() []introspect.Signal {
	return []introspect.Signal{
		{
			Name: "Completed",
			Args: []introspect.Arg{
				{Name: "dismissed", Type: "b"},
				{Name: "result", Type: "v"},
			},
		},
	}
}

// ObjectPath helpers

func makePromptPath(id string) dbus.ObjectPath {
	return dbus.ObjectPath("/org/freedesktop/secrets/prompt/" + id)
}

// generateID generates a unique ID for prompts.
func generateID() string {
	return fmt.Sprintf("prompt_%d", time.Now().UnixNano())
}
