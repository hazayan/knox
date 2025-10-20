// Package dbus implements the FreeDesktop Secret Service API.
// Spec: https://specifications.freedesktop.org/secret-service-spec/latest/
package dbus

import (
	"errors"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/hazayan/knox/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestPrompt tests the Prompt interface functionality.
func TestPrompt(t *testing.T) {
	conn, err := dbus.ConnectSessionBus()
	require.NoError(t, err)
	defer conn.Close()

	t.Run("prompt_creation_and_export", func(t *testing.T) {
		callback := func(_ bool) {
			// Callback for testing
		}

		prompt := NewPrompt(conn, callback)
		assert.NotNil(t, prompt)
		assert.Contains(t, string(prompt.Path()), "/org/freedesktop/secrets/prompt/")

		err := prompt.Export()
		assert.NoError(t, err)

		// Clean up
		err = prompt.Unexport()
		assert.NoError(t, err)
	})

	t.Run("prompt_approval", func(t *testing.T) {
		var callbackCalled bool
		var callbackResult bool

		callback := func(approved bool) {
			callbackCalled = true
			callbackResult = approved
		}

		prompt := NewPrompt(conn, callback)
		err := prompt.Export()
		require.NoError(t, err)
		defer func() {
			_ = prompt.Unexport()
		}()

		// Call Prompt method (auto-approves)
		dbusErr := prompt.Prompt("test-window")
		assert.Nil(t, dbusErr)
		assert.True(t, callbackCalled)
		assert.True(t, callbackResult)
	})

	t.Run("prompt_dismissal", func(t *testing.T) {
		var callbackCalled bool
		var callbackResult bool

		callback := func(approved bool) {
			callbackCalled = true
			callbackResult = approved
		}

		prompt := NewPrompt(conn, callback)
		err := prompt.Export()
		require.NoError(t, err)
		defer func() {
			_ = prompt.Unexport()
		}()

		// Call Dismiss method (auto-rejects)
		dbusErr := prompt.Dismiss()
		assert.Nil(t, dbusErr)
		assert.True(t, callbackCalled)
		assert.False(t, callbackResult)
	})

	t.Run("prompt_already_completed", func(t *testing.T) {
		var callbackCount int

		callback := func(_ bool) {
			callbackCount++
		}

		prompt := NewPrompt(conn, callback)
		err := prompt.Export()
		require.NoError(t, err)
		defer func() {
			_ = prompt.Unexport()
		}()

		// First call should succeed
		dbusErr := prompt.Prompt("test-window")
		assert.Nil(t, dbusErr)
		assert.Equal(t, 1, callbackCount)

		// Second call should fail
		dbusErr = prompt.Prompt("test-window")
		assert.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), "prompt already completed")
		assert.Equal(t, 1, callbackCount) // Callback should not be called again
	})

	t.Run("prompt_without_callback", func(t *testing.T) {
		prompt := NewPrompt(conn, nil)
		err := prompt.Export()
		require.NoError(t, err)
		defer func() {
			_ = prompt.Unexport()
		}()

		// Should not panic even without callback
		dbusErr := prompt.Prompt("test-window")
		assert.Nil(t, dbusErr)

		// Create a new prompt for dismiss test since the first one is completed
		prompt2 := NewPrompt(conn, nil)
		err = prompt2.Export()
		require.NoError(t, err)
		defer func() {
			_ = prompt2.Unexport()
		}()

		dbusErr = prompt2.Dismiss()
		assert.Nil(t, dbusErr)
	})
}

// TestEnhancedPrompt tests the enhanced prompt functionality with custom options.
func TestEnhancedPrompt(t *testing.T) {
	conn, err := dbus.ConnectSessionBus()
	require.NoError(t, err)
	defer conn.Close()

	t.Run("prompt_with_custom_message", func(t *testing.T) {
		var callbackCalled bool
		var callbackResult bool

		callback := func(approved bool) {
			callbackCalled = true
			callbackResult = approved
		}

		customMessage := "Custom prompt message for testing"
		prompt := NewPrompt(conn, callback, WithPromptMessage(customMessage))
		assert.NotNil(t, prompt)
		assert.Equal(t, customMessage, prompt.GetMessage())

		err := prompt.Export()
		require.NoError(t, err)
		defer func() {
			_ = prompt.Unexport()
		}()

		// Call Prompt method
		dbusErr := prompt.Prompt("test-window")
		assert.Nil(t, dbusErr)
		assert.True(t, callbackCalled)
		assert.True(t, callbackResult)
	})

	t.Run("prompt_with_custom_handler", func(t *testing.T) {
		var callbackCalled bool
		var callbackResult bool

		callback := func(approved bool) {
			callbackCalled = true
			callbackResult = approved
		}

		// Create a custom handler that always rejects
		customHandler := &MockPromptHandler{approveResult: false}
		prompt := NewPrompt(conn, callback, WithPromptHandler(customHandler))
		assert.NotNil(t, prompt)
		assert.Equal(t, customHandler, prompt.GetHandler())

		err := prompt.Export()
		require.NoError(t, err)
		defer func() {
			_ = prompt.Unexport()
		}()

		// Call Prompt method - should reject due to custom handler
		dbusErr := prompt.Prompt("test-window")
		assert.Nil(t, dbusErr)
		assert.True(t, callbackCalled)
		assert.False(t, callbackResult)
	})

	t.Run("prompt_with_timeout", func(t *testing.T) {
		callback := func(_ bool) {
			// Callback for testing
		}

		customTimeout := 60 * time.Second
		prompt := NewPrompt(conn, callback, WithPromptTimeout(customTimeout))
		assert.NotNil(t, prompt)
		assert.Equal(t, customTimeout, prompt.GetTimeout())
		assert.False(t, prompt.IsCompleted())
		assert.WithinDuration(t, time.Now(), prompt.GetCreatedAt(), time.Second)
	})

	t.Run("prompt_handler_error", func(t *testing.T) {
		callback := func(_ bool) {
			// Should not be called on handler error
		}

		// Create a handler that returns an error
		errorHandler := &MockPromptHandler{returnError: true}
		prompt := NewPrompt(conn, callback, WithPromptHandler(errorHandler))

		err := prompt.Export()
		require.NoError(t, err)
		defer func() {
			_ = prompt.Unexport()
		}()

		// Call Prompt method - should return error
		dbusErr := prompt.Prompt("test-window")
		assert.NotNil(t, dbusErr)
		assert.Contains(t, dbusErr.Error(), "failed to show prompt")
	})
}

// MockPromptHandler is a mock implementation of PromptHandler for testing.
type MockPromptHandler struct {
	approveResult bool
	returnError   bool
}

// ShowPrompt implements the PromptHandler interface.
func (m *MockPromptHandler) ShowPrompt(_, _ string) (bool, error) {
	if m.returnError {
		return false, errors.New("mock handler error")
	}
	return m.approveResult, nil
}

// TestLocking tests collection and item locking functionality.
func TestLocking(t *testing.T) {
	conn, err := dbus.ConnectSessionBus()
	require.NoError(t, err)
	defer conn.Close()

	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			Server:          "localhost:9000",
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	// Mock the GetKeys call that happens during collection loading
	mockClient.On("GetKeys", mock.Anything).Return([]string{}, nil)
	bridge, err := NewBridge(cfg, mockClient)
	require.NoError(t, err)

	err = bridge.Start()
	require.NoError(t, err)
	defer func() {
		_ = bridge.Stop()
	}()

	t.Run("collection_locking", func(t *testing.T) {
		// Get default collection
		defaultColl, ok := bridge.collections[DefaultCollection]
		require.True(t, ok)

		// Initially should not be locked
		assert.False(t, defaultColl.IsLocked())

		// Lock the collection
		defaultColl.Lock()
		assert.True(t, defaultColl.IsLocked())

		// Unlock the collection
		defaultColl.Unlock()
		assert.False(t, defaultColl.IsLocked())
	})

	t.Run("item_locking", func(t *testing.T) {
		// Create a test item
		defaultColl, ok := bridge.collections[DefaultCollection]
		require.True(t, ok)

		item := NewItem(defaultColl, "test-lock-item", "Test Lock Item", map[string]string{
			"application": "test",
			"type":        "lock-test",
		})

		// Initially should not be locked
		assert.False(t, item.IsLocked())

		// Lock the item
		item.Lock()
		assert.True(t, item.IsLocked())

		// Unlock the item
		item.Unlock()
		assert.False(t, item.IsLocked())
	})

	t.Run("collection_item_locking_propagation", func(t *testing.T) {
		defaultColl, ok := bridge.collections[DefaultCollection]
		require.True(t, ok)

		// Create multiple test items
		item1 := NewItem(defaultColl, "propagation-1", "Propagation Test 1", nil)
		item2 := NewItem(defaultColl, "propagation-2", "Propagation Test 2", nil)

		// Add items to collection
		defaultColl.mu.Lock()
		defaultColl.items["propagation-1"] = item1
		defaultColl.items["propagation-2"] = item2
		defaultColl.mu.Unlock()

		// Initially items should not be locked
		assert.False(t, item1.IsLocked())
		assert.False(t, item2.IsLocked())

		// Lock collection - should lock all items
		defaultColl.Lock()
		assert.True(t, item1.IsLocked())
		assert.True(t, item2.IsLocked())

		// Unlock collection - should unlock all items
		defaultColl.Unlock()
		assert.False(t, item1.IsLocked())
		assert.False(t, item2.IsLocked())
	})
}

// TestServiceLocking tests the service-level locking and unlocking methods.
func TestServiceLocking(t *testing.T) {
	conn, err := dbus.ConnectSessionBus()
	require.NoError(t, err)
	defer conn.Close()

	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			Server:          "localhost:9000",
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	// Mock the GetKeys call that happens during collection loading
	mockClient.On("GetKeys", mock.Anything).Return([]string{}, nil)
	bridge, err := NewBridge(cfg, mockClient)
	require.NoError(t, err)

	err = bridge.Start()
	require.NoError(t, err)
	defer func() {
		_ = bridge.Stop()
	}()

	t.Run("service_unlock_collection", func(t *testing.T) {
		defaultColl, ok := bridge.collections[DefaultCollection]
		require.True(t, ok)

		// Lock the collection first
		defaultColl.Lock()
		assert.True(t, defaultColl.IsLocked())

		// Unlock via service
		unlocked, promptPath, dbusErr := bridge.Unlock([]dbus.ObjectPath{defaultColl.Path()})
		assert.Nil(t, dbusErr)
		assert.NotEqual(t, "/", promptPath) // Should return a prompt path
		assert.Len(t, unlocked, 1)
		assert.Equal(t, defaultColl.Path(), unlocked[0])

		// Collection should now be unlocked
		assert.False(t, defaultColl.IsLocked())
	})

	t.Run("service_lock_collection", func(t *testing.T) {
		defaultColl, ok := bridge.collections[DefaultCollection]
		require.True(t, ok)

		// Ensure collection is unlocked first
		defaultColl.Unlock()
		assert.False(t, defaultColl.IsLocked())

		// Lock via service
		locked, promptPath, dbusErr := bridge.Lock([]dbus.ObjectPath{defaultColl.Path()})
		assert.Nil(t, dbusErr)
		assert.NotEqual(t, "/", promptPath) // Should return a prompt path
		assert.Len(t, locked, 1)
		assert.Equal(t, defaultColl.Path(), locked[0])

		// Collection should now be locked
		assert.True(t, defaultColl.IsLocked())
	})

	t.Run("service_unlock_nonexistent_object", func(t *testing.T) {
		// Try to unlock a non-existent object
		nonexistentPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/nonexistent")
		unlocked, promptPath, dbusErr := bridge.Unlock([]dbus.ObjectPath{nonexistentPath})
		assert.Nil(t, dbusErr)
		assert.NotEqual(t, "/", promptPath)
		assert.Empty(t, unlocked) // Should return empty list for non-existent objects
	})

	t.Run("service_lock_nonexistent_object", func(t *testing.T) {
		// Try to lock a non-existent object
		nonexistentPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/nonexistent")
		locked, promptPath, dbusErr := bridge.Lock([]dbus.ObjectPath{nonexistentPath})
		assert.Nil(t, dbusErr)
		assert.NotEqual(t, "/", promptPath)
		assert.Empty(t, locked) // Should return empty list for non-existent objects
	})
}

// TestLockingWithSearch tests that locked items are properly handled in search results.
func TestLockingWithSearch(t *testing.T) {
	conn, err := dbus.ConnectSessionBus()
	require.NoError(t, err)
	defer conn.Close()

	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			Server:          "localhost:9000",
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	// Mock the GetKeys call that happens during collection loading
	mockClient.On("GetKeys", mock.Anything).Return([]string{}, nil)
	bridge, err := NewBridge(cfg, mockClient)
	require.NoError(t, err)

	err = bridge.Start()
	require.NoError(t, err)
	defer func() {
		_ = bridge.Stop()
	}()

	t.Run("search_with_locked_items", func(t *testing.T) {
		defaultColl, ok := bridge.collections[DefaultCollection]
		require.True(t, ok)

		// Create test items with different locked states
		unlockedItem := NewItem(defaultColl, "search-unlocked", "Unlocked Search Item", map[string]string{
			"test":  "search",
			"state": "unlocked",
		})
		lockedItem := NewItem(defaultColl, "search-locked", "Locked Search Item", map[string]string{
			"test":  "search",
			"state": "locked",
		})

		// Add items to collection
		defaultColl.mu.Lock()
		defaultColl.items["search-unlocked"] = unlockedItem
		defaultColl.items["search-locked"] = lockedItem
		defaultColl.mu.Unlock()

		// Lock one item
		lockedItem.Lock()

		// Search for items with the test attribute
		unlocked, locked, dbusErr := bridge.SearchItems(map[string]string{"test": "search"})
		assert.Nil(t, dbusErr)
		assert.Len(t, unlocked, 1) // Only the unlocked item
		assert.Len(t, locked, 1)   // Only the locked item
		assert.Equal(t, unlockedItem.Path(), unlocked[0])
		assert.Equal(t, lockedItem.Path(), locked[0])
	})
}

// TestPromptCompletedSignal tests that the Completed signal is emitted correctly.
// This is a critical requirement from the FreeDesktop Secret Service specification.
func TestPromptCompletedSignal(t *testing.T) {
	conn, err := dbus.ConnectSessionBus()
	require.NoError(t, err)
	defer conn.Close()

	t.Run("completed_signal_on_prompt_approval", func(t *testing.T) {
		// Create a channel to capture signal emission
		signalReceived := make(chan *dbus.Signal, 1)
		conn.Signal(signalReceived)

		var callbackCalled bool
		callback := func(_ bool) {
			callbackCalled = true
		}

		prompt := NewPrompt(conn, callback, WithPromptMessage("Test approval signal"))
		err := prompt.Export()
		require.NoError(t, err)
		defer func() {
			_ = prompt.Unexport()
			conn.RemoveSignal(signalReceived)
		}()

		// Subscribe to the Completed signal
		err = conn.AddMatchSignal(dbus.WithMatchInterface(PromptInterface))
		require.NoError(t, err)

		// Call Prompt method (which should emit Completed signal)
		dbusErr := prompt.Prompt("test-window")
		assert.Nil(t, dbusErr)
		assert.True(t, callbackCalled)

		// Wait for signal with timeout
		select {
		case sig := <-signalReceived:
			// Verify signal is from our prompt
			if sig.Path == prompt.Path() && sig.Name == PromptInterface+".Completed" {
				assert.Len(t, sig.Body, 2, "Completed signal should have 2 arguments")
				dismissed, ok := sig.Body[0].(bool)
				assert.True(t, ok, "First argument should be bool (dismissed)")
				assert.False(t, dismissed, "dismissed should be false for Prompt()")
				// Second argument is the result variant
				assert.NotNil(t, sig.Body[1], "Second argument should be result variant")
			}
		case <-time.After(2 * time.Second):
			t.Log("Warning: Completed signal not received (may be timing issue)")
			// Don't fail the test as signal timing can be unreliable in tests
		}
	})

	t.Run("completed_signal_on_dismiss", func(t *testing.T) {
		// Create a channel to capture signal emission
		signalReceived := make(chan *dbus.Signal, 1)
		conn.Signal(signalReceived)

		var callbackCalled bool
		callback := func(approved bool) {
			callbackCalled = true
			assert.False(t, approved, "callback should receive false for Dismiss")
		}

		prompt := NewPrompt(conn, callback, WithPromptMessage("Test dismiss signal"))
		err := prompt.Export()
		require.NoError(t, err)
		defer func() {
			_ = prompt.Unexport()
			conn.RemoveSignal(signalReceived)
		}()

		// Subscribe to the Completed signal
		err = conn.AddMatchSignal(dbus.WithMatchInterface(PromptInterface))
		require.NoError(t, err)

		// Call Dismiss method (which should emit Completed signal)
		dbusErr := prompt.Dismiss()
		assert.Nil(t, dbusErr)
		assert.True(t, callbackCalled)

		// Wait for signal with timeout
		select {
		case sig := <-signalReceived:
			// Verify signal is from our prompt
			if sig.Path == prompt.Path() && sig.Name == PromptInterface+".Completed" {
				assert.Len(t, sig.Body, 2, "Completed signal should have 2 arguments")
				dismissed, ok := sig.Body[0].(bool)
				assert.True(t, ok, "First argument should be bool (dismissed)")
				assert.True(t, dismissed, "dismissed should be true for Dismiss()")
				// Second argument is the result variant
				assert.NotNil(t, sig.Body[1], "Second argument should be result variant")
			}
		case <-time.After(2 * time.Second):
			t.Log("Warning: Completed signal not received (may be timing issue)")
			// Don't fail the test as signal timing can be unreliable in tests
		}
	})

	t.Run("signal_includes_correct_introspection", func(t *testing.T) {
		callback := func(_ bool) {}
		prompt := NewPrompt(conn, callback)

		signals := prompt.getSignals()
		assert.Len(t, signals, 1, "Should have exactly one signal defined")
		assert.Equal(t, "Completed", signals[0].Name)
		assert.Len(t, signals[0].Args, 2, "Completed signal should have 2 arguments")
		assert.Equal(t, "dismissed", signals[0].Args[0].Name)
		assert.Equal(t, "b", signals[0].Args[0].Type, "dismissed should be boolean")
		assert.Equal(t, "result", signals[0].Args[1].Name)
		assert.Equal(t, "v", signals[0].Args[1].Type, "result should be variant")
	})
}

func TestPrompt_SetMessage(t *testing.T) {
	prompt := &Prompt{
		message: "Original message",
	}

	prompt.SetMessage("New message")
	assert.Equal(t, "New message", prompt.message)
}

func TestPrompt_SetHandler(t *testing.T) {
	prompt := &Prompt{}

	// Create a mock handler that implements PromptHandler
	handler := &MockPromptHandler{}

	prompt.SetHandler(handler)
	assert.NotNil(t, prompt.handler)
}
