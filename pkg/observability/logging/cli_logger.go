// Package logging provides structured logging for Knox CLI components.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// CLILogger provides structured logging for CLI operations.
type CLILogger struct {
	writer     io.Writer
	jsonOutput bool
	level      string
	fields     map[string]any
}

// LogEntry represents a structured log entry.
type LogEntry struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// NewCLILogger creates a new CLI logger instance.
func NewCLILogger(jsonOutput bool, writer io.Writer) *CLILogger {
	return &CLILogger{
		writer:     writer,
		jsonOutput: jsonOutput,
		level:      "info",
		fields:     make(map[string]any),
	}
}

// log writes a log entry with the specified level.
func (l *CLILogger) log(level, msg string, fields ...map[string]any) {
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     level,
		Message:   msg,
	}

	// Start with instance fields
	entry.Fields = make(map[string]any)
	for k, v := range l.fields {
		entry.Fields[k] = v
	}

	// Merge additional fields
	for _, fieldMap := range fields {
		for k, v := range fieldMap {
			entry.Fields[k] = v
		}
	}

	if l.jsonOutput {
		jsonData, err := json.Marshal(entry)
		if err != nil {
			// Fallback to simple output if JSON marshaling fails
			fmt.Fprintf(l.writer, "{\"error\": \"failed to marshal log entry: %v\"}\n", err)
			return
		}
		fmt.Fprintln(l.writer, string(jsonData))
	} else {
		// Simple text format: [LEVEL] timestamp message [key=value ...]
		var fieldStrs []string
		for k, v := range entry.Fields {
			fieldStrs = append(fieldStrs, fmt.Sprintf("%s=%v", k, v))
		}

		fieldsStr := ""
		if len(fieldStrs) > 0 {
			fieldsStr = " [" + strings.Join(fieldStrs, " ") + "]"
		}

		fmt.Fprintf(l.writer, "[%s] %s %s%s\n", strings.ToUpper(level), entry.Timestamp, msg, fieldsStr)
	}
}

// Info logs an informational message.
func (l *CLILogger) Info(msg string, fields ...map[string]any) {
	l.log("info", msg, fields...)
}

// Success logs a success message.
func (l *CLILogger) Success(msg string, fields ...map[string]any) {
	fields = append(fields, map[string]any{"status": "success"})
	l.log("info", msg, fields...)
}

// Error logs an error message.
func (l *CLILogger) Error(msg string, err error, fields ...map[string]any) {
	if err != nil {
		fields = append(fields, map[string]any{"error": err.Error()})
	}
	l.log("error", msg, fields...)
}

// Warn logs a warning message.
func (l *CLILogger) Warn(msg string, fields ...map[string]any) {
	l.log("warn", msg, fields...)
}

// Debug logs a debug message.
func (l *CLILogger) Debug(msg string, fields ...map[string]any) {
	if l.level == "debug" {
		l.log("debug", msg, fields...)
	}
}

// Print outputs data directly (for JSON output mode).
func (l *CLILogger) Print(data any) error {
	if l.jsonOutput {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Fprintln(l.writer, string(jsonData))
		return nil
	}

	// For non-JSON mode, use simple output
	switch v := data.(type) {
	case string:
		fmt.Fprintln(l.writer, v)
	case []byte:
		fmt.Fprintln(l.writer, string(v))
	default:
		fmt.Fprintln(l.writer, v)
	}
	return nil
}

// Printf formats and prints output (for backward compatibility).
func (l *CLILogger) Printf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if l.jsonOutput {
		l.Info(msg)
	} else {
		fmt.Fprintln(l.writer, msg)
	}
}

// Println prints a line with newline (for backward compatibility).
func (l *CLILogger) Println(args ...any) {
	msg := fmt.Sprint(args...)
	if l.jsonOutput {
		l.Info(msg)
	} else {
		fmt.Fprintln(l.writer, msg)
	}
}

// PrintData prints structured data in appropriate format.
func (l *CLILogger) PrintData(data any, description string) {
	if l.jsonOutput {
		jsonData, err := json.Marshal(data)
		if err != nil {
			l.Error("Failed to marshal data", err)
			return
		}
		fmt.Fprintln(l.writer, string(jsonData))
	} else {
		l.Info(description, map[string]any{"data": data})
	}
}

// WithFields creates a new logger with additional fields.
func (l *CLILogger) WithFields(fields map[string]any) *CLILogger {
	newLogger := *l
	newLogger.fields = make(map[string]any)

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new fields
	for k, v := range fields {
		newLogger.fields[k] = v
	}

	return &newLogger
}

// WithField creates a new logger with an additional field.
func (l *CLILogger) WithField(key string, value any) *CLILogger {
	return l.WithFields(map[string]any{key: value})
}

// SetLevel sets the log level.
func (l *CLILogger) SetLevel(level string) {
	l.level = strings.ToLower(level)
}

// DefaultCLILogger is the default CLI logger instance.
var DefaultCLILogger = NewCLILogger(false, os.Stdout)

// Helper functions for common operations

// CLIInfo logs an informational message using the default logger.
func CLIInfo(msg string, fields ...map[string]any) {
	DefaultCLILogger.Info(msg, fields...)
}

// CLISuccess logs a success message using the default logger.
func CLISuccess(msg string, fields ...map[string]any) {
	DefaultCLILogger.Success(msg, fields...)
}

// CLIError logs an error message using the default logger.
func CLIError(msg string, err error, fields ...map[string]any) {
	DefaultCLILogger.Error(msg, err, fields...)
}

// CLIWarn logs a warning message using the default logger.
func CLIWarn(msg string, fields ...map[string]any) {
	DefaultCLILogger.Warn(msg, fields...)
}

// CLIDebug logs a debug message using the default logger.
func CLIDebug(msg string, fields ...map[string]any) {
	DefaultCLILogger.Debug(msg, fields...)
}

// CLIPrint outputs data using the default logger.
func CLIPrint(data any) error {
	return DefaultCLILogger.Print(data)
}

// CLIPrintf formats and prints output using the default logger.
func CLIPrintf(format string, args ...any) {
	DefaultCLILogger.Printf(format, args...)
}

// CLIPrintln prints a line with newline using the default logger.
func CLIPrintln(args ...any) {
	DefaultCLILogger.Println(args...)
}

// CLIPrintData prints structured data using the default logger.
func CLIPrintData(data any, description string) {
	DefaultCLILogger.PrintData(data, description)
}
