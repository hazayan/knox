package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewCLILogger(t *testing.T) {
	tests := []struct {
		name       string
		jsonOutput bool
		wantJSON   bool
	}{
		{"Text output", false, false},
		{"JSON output", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewCLILogger(tt.jsonOutput, &buf)

			if logger == nil {
				t.Fatal("NewCLILogger returned nil")
			}

			if logger.jsonOutput != tt.wantJSON {
				t.Errorf("Expected json=%v, got %v", tt.wantJSON, logger.jsonOutput)
			}

			// Test that logger can write
			logger.Info("test message")
			if buf.Len() == 0 {
				t.Error("Logger did not write any output")
			}
		})
	}
}

func TestCLILogger_Info(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(false, &buf)

	logger.Info("test info message")
	output := buf.String()

	if !strings.Contains(output, "test info message") {
		t.Errorf("Expected output to contain 'test info message', got: %s", output)
	}
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Expected output to contain '[INFO]', got: %s", output)
	}
}

func TestCLILogger_Success(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(false, &buf)

	logger.Success("operation completed")
	output := buf.String()

	if !strings.Contains(output, "operation completed") {
		t.Errorf("Expected output to contain 'operation completed', got: %s", output)
	}
	if !strings.Contains(output, "status=success") {
		t.Errorf("Expected output to contain 'status=success', got: %s", output)
	}
}

func TestCLILogger_Error(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(false, &buf)

	testErr := &testError{msg: "test error"}
	logger.Error("operation failed", testErr)
	output := buf.String()

	if !strings.Contains(output, "operation failed") {
		t.Errorf("Expected output to contain 'operation failed', got: %s", output)
	}
	if !strings.Contains(output, "[ERROR]") {
		t.Errorf("Expected output to contain '[ERROR]', got: %s", output)
	}
	if !strings.Contains(output, "test error") {
		t.Errorf("Expected output to contain 'test error', got: %s", output)
	}
}

func TestCLILogger_Warn(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(false, &buf)

	logger.Warn("warning message")
	output := buf.String()

	if !strings.Contains(output, "warning message") {
		t.Errorf("Expected output to contain 'warning message', got: %s", output)
	}
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("Expected output to contain '[WARN]', got: %s", output)
	}
}

func TestCLILogger_Debug(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(false, &buf)

	// Debug should not output by default
	logger.Debug("debug message")
	if buf.Len() > 0 {
		t.Error("Debug message should not be output by default")
	}

	// Enable debug level
	logger.SetLevel("debug")
	logger.Debug("debug message")
	output := buf.String()

	if !strings.Contains(output, "debug message") {
		t.Errorf("Expected output to contain 'debug message', got: %s", output)
	}
	if !strings.Contains(output, "[DEBUG]") {
		t.Errorf("Expected output to contain '[DEBUG]', got: %s", output)
	}
}

func TestCLILogger_WithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(false, &buf)

	fields := map[string]any{
		"key_id":     "test:key",
		"operation":  "create",
		"version_id": 123,
	}

	logger.WithFields(fields).Info("key operation")
	output := buf.String()

	if !strings.Contains(output, "key operation") {
		t.Errorf("Expected output to contain 'key operation', got: %s", output)
	}
	if !strings.Contains(output, "key_id=test:key") {
		t.Errorf("Expected output to contain 'key_id=test:key', got: %s", output)
	}
	if !strings.Contains(output, "operation=create") {
		t.Errorf("Expected output to contain 'operation=create', got: %s", output)
	}
	if !strings.Contains(output, "version_id=123") {
		t.Errorf("Expected output to contain 'version_id=123', got: %s", output)
	}
}

func TestCLILogger_Print_JSON(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(true, &buf)

	testData := map[string]any{
		"key":   "test:key",
		"value": "secret",
	}

	err := logger.Print(testData)
	if err != nil {
		t.Fatalf("Print failed: %v", err)
	}

	output := buf.String()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if decoded["key"] != "test:key" {
		t.Errorf("Expected key='test:key', got %v", decoded["key"])
	}
	if decoded["value"] != "secret" {
		t.Errorf("Expected value='secret', got %v", decoded["value"])
	}
}

func TestCLILogger_Print_Text(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(false, &buf)

	err := logger.Print("test message")
	if err != nil {
		t.Fatalf("Print failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("Expected output to contain 'test message', got: %s", output)
	}
}

func TestCLILogger_Printf(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(false, &buf)

	logger.Printf("Formatted %s %d", "test", 42)
	output := buf.String()

	if !strings.Contains(output, "Formatted test 42") {
		t.Errorf("Expected output to contain 'Formatted test 42', got: %s", output)
	}
}

func TestCLILogger_Println(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(false, &buf)

	logger.Println("line", "with", "multiple", "args")
	output := buf.String()

	if !strings.Contains(output, "linewithmultipleargs") {
		t.Errorf("Expected output to contain 'linewithmultipleargs', got: %s", output)
	}
}

func TestCLILogger_PrintData_JSON(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(true, &buf)

	testData := map[string]string{
		"key":   "test:key",
		"value": "secret",
	}

	logger.PrintData(testData, "key data")
	output := buf.String()

	var decoded map[string]string
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if decoded["key"] != "test:key" {
		t.Errorf("Expected key='test:key', got %v", decoded["key"])
	}
	if decoded["value"] != "secret" {
		t.Errorf("Expected value='secret', got %v", decoded["value"])
	}
}

func TestCLILogger_PrintData_Text(t *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(false, &buf)

	testData := map[string]string{"key": "test:key"}
	logger.PrintData(testData, "key data")
	output := buf.String()

	if !strings.Contains(output, "key data") {
		t.Errorf("Expected output to contain 'key data', got: %s", output)
	}
}

func TestCLILogger_SetLevel(_ *testing.T) {
	var buf bytes.Buffer
	logger := NewCLILogger(false, &buf)

	// Test different log levels
	levels := []string{"debug", "info", "warn", "error", "invalid"}
	for _, level := range levels {
		logger.SetLevel(level)
		// Just verify it doesn't panic - actual level testing is in Debug test
	}
}

func TestGlobalFunctions(t *testing.T) {
	// Reset default logger for testing
	oldLogger := DefaultCLILogger
	defer func() { DefaultCLILogger = oldLogger }()

	var buf bytes.Buffer
	DefaultCLILogger = NewCLILogger(false, &buf)

	// Test global functions
	CLIInfo("global info")
	if !strings.Contains(buf.String(), "global info") {
		t.Error("Global CLIInfo function failed")
	}

	buf.Reset()
	CLISuccess("global success")
	if !strings.Contains(buf.String(), "global success") {
		t.Error("Global CLISuccess function failed")
	}

	buf.Reset()
	CLIError("global error", nil)
	if !strings.Contains(buf.String(), "global error") {
		t.Error("Global CLIError function failed")
	}

	buf.Reset()
	CLIWarn("global warn")
	if !strings.Contains(buf.String(), "global warn") {
		t.Error("Global CLIWarn function failed")
	}
}

// testError is a simple error implementation for testing.
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
