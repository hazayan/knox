// Package logging provides structured logging for Knox.
package logging

import (
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	// Logger is the global logger instance.
	Logger = logrus.New()

	// AuditLogger is a separate logger for audit events.
	AuditLogger = logrus.New()
)

// Config holds logging configuration.
type Config struct {
	Level  string // debug, info, warn, error
	Format string // text, json
}

// AuditConfig holds audit logging configuration.
type AuditConfig struct {
	Enabled bool
	Output  string // file path or "stdout"
}

// Initialize configures the global logger.
func Initialize(cfg Config) error {
	// Set log level
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		return err
	}
	Logger.SetLevel(level)

	// Set log format
	if cfg.Format == "json" {
		Logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	} else {
		Logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	}

	return nil
}

// InitializeAudit configures the audit logger.
func InitializeAudit(cfg AuditConfig) error {
	if !cfg.Enabled {
		// Disable audit logging by sending to nowhere
		AuditLogger.SetOutput(io.Discard)
		return nil
	}

	// Always use JSON format for audit logs
	AuditLogger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
	})

	// Always log everything for audit
	AuditLogger.SetLevel(logrus.InfoLevel)

	// Configure output
	if cfg.Output == "stdout" || cfg.Output == "" {
		AuditLogger.SetOutput(os.Stdout)
	} else {
		file, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		AuditLogger.SetOutput(file)
	}

	return nil
}

// WithFields creates a new log entry with the given fields.
func WithFields(fields logrus.Fields) *logrus.Entry {
	return Logger.WithFields(fields)
}

// WithField creates a new log entry with a single field.
func WithField(key string, value interface{}) *logrus.Entry {
	return Logger.WithField(key, value)
}

// Debug logs a debug message.
func Debug(args ...interface{}) {
	Logger.Debug(args...)
}

// Debugf logs a formatted debug message.
func Debugf(format string, args ...interface{}) {
	Logger.Debugf(format, args...)
}

// Info logs an info message.
func Info(args ...interface{}) {
	Logger.Info(args...)
}

// Infof logs a formatted info message.
func Infof(format string, args ...interface{}) {
	Logger.Infof(format, args...)
}

// Warn logs a warning message.
func Warn(args ...interface{}) {
	Logger.Warn(args...)
}

// Warnf logs a formatted warning message.
func Warnf(format string, args ...interface{}) {
	Logger.Warnf(format, args...)
}

// Error logs an error message.
func Error(args ...interface{}) {
	Logger.Error(args...)
}

// Errorf logs a formatted error message.
func Errorf(format string, args ...interface{}) {
	Logger.Errorf(format, args...)
}

// Fatal logs a fatal message and exits.
func Fatal(args ...interface{}) {
	Logger.Fatal(args...)
}

// Fatalf logs a formatted fatal message and exits.
func Fatalf(format string, args ...interface{}) {
	Logger.Fatalf(format, args...)
}

// Audit logs an audit event.
func Audit(event string, fields logrus.Fields) {
	fields["event"] = event
	AuditLogger.WithFields(fields).Info("audit event")
}

// AuditKeyAccess logs a key access audit event.
func AuditKeyAccess(keyID, principalID, principalType, action, result string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"key_id":         keyID,
		"principal_id":   principalID,
		"principal_type": principalType,
		"action":         action,
		"result":         result,
	}

	if metadata != nil {
		fields["metadata"] = metadata
	}

	Audit("key.access", fields)
}

// AuditKeyCreate logs a key creation audit event.
func AuditKeyCreate(keyID, principalID, principalType string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"key_id":         keyID,
		"principal_id":   principalID,
		"principal_type": principalType,
	}

	if metadata != nil {
		fields["metadata"] = metadata
	}

	Audit("key.create", fields)
}

// AuditKeyDelete logs a key deletion audit event.
func AuditKeyDelete(keyID, principalID, principalType string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"key_id":         keyID,
		"principal_id":   principalID,
		"principal_type": principalType,
	}

	if metadata != nil {
		fields["metadata"] = metadata
	}

	Audit("key.delete", fields)
}

// AuditACLChange logs an ACL change audit event.
func AuditACLChange(keyID, principalID, principalType, operation string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"key_id":         keyID,
		"principal_id":   principalID,
		"principal_type": principalType,
		"operation":      operation,
	}

	if metadata != nil {
		fields["metadata"] = metadata
	}

	Audit("acl.change", fields)
}

// AuditAuthAttempt logs an authentication attempt audit event.
func AuditAuthAttempt(principalID, principalType, provider, result string, metadata map[string]interface{}) {
	fields := logrus.Fields{
		"principal_id":   principalID,
		"principal_type": principalType,
		"provider":       provider,
		"result":         result,
	}

	if metadata != nil {
		fields["metadata"] = metadata
	}

	Audit("auth.attempt", fields)
}

// SanitizeDatabaseURL removes credentials from database connection strings for safe logging.
// Supports postgres://, mysql://, and other database URL formats.
func SanitizeDatabaseURL(dbURL string) string {
	if dbURL == "" {
		return ""
	}

	// Try parsing as URL
	u, err := url.Parse(dbURL)
	if err != nil {
		// If not a valid URL, do simple string-based sanitization
		return sanitizeSimpleFormat(dbURL)
	}

	// Remove password from URL
	if u.User != nil {
		username := u.User.Username()
		if username != "" {
			u.User = url.User(username) // Keep username, remove password
		}
	}

	return u.String()
}

// sanitizeSimpleFormat handles non-URL formats like "user:pass@host/db"
func sanitizeSimpleFormat(dbURL string) string {
	// Find @ symbol
	atIndex := strings.LastIndex(dbURL, "@")
	if atIndex == -1 {
		return dbURL // No credentials
	}

	// Find : before @
	colonIndex := strings.LastIndex(dbURL[:atIndex], ":")
	if colonIndex == -1 {
		return dbURL // No password separator
	}

	// Replace password with ****
	return dbURL[:colonIndex+1] + "****" + dbURL[atIndex:]
}
