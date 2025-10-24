// Package client implements the Knox CLI client commands.
package client

import (
	"log"
	"os"
)

// cli is the global HTTP client interface used by command implementations.
var cli APIClient

// commands is the list of all available CLI commands.
var commands []*Command

// fatalf logs a fatal error message and exits the program.
func fatalf(format string, v ...any) {
	log.Printf("FATAL: "+format, v...)
	os.Exit(1)
}

// logf logs an informational message.
func logf(format string, v ...any) {
	log.Printf(format, v...)
}

// daemonReportMetrics reports daemon metrics for monitoring.
func daemonReportMetrics(metrics map[string]uint64) {
	// This would typically report metrics to a monitoring system
	// For now, we just log the metrics
	logf("Daemon metrics: %v", metrics)
}

// clientGetKeyMetrics reports client get key metrics.
func clientGetKeyMetrics(metrics map[string]string) {
	// TODO: Implement proper metrics reporting
	logf("Client get key metrics: %v", metrics)
}

// init initializes the global variables and sets up the command list.
func init() {
	// Initialize the command list
	commands = []*Command{
		cmdAdd,
		cmdCreate,
		cmdDaemon,
		cmdDeactivate,
		cmdDelete,
		cmdGet,
		cmdGetACL,
		cmdGetKeys,
		cmdGetVersions,
		cmdListKeyTemplates,
		cmdPromote,
		cmdReactivate,
		cmdRegister,
		cmdUnregister,
		cmdUpdateAccess,
		cmdVersion,
		helpAuth,
	}
}

// initCommandFlags initializes the flag sets for all commands.
func initCommandFlags() {
	// TODO: Implement flag initialization when needed
	// Currently flags are initialized in individual command files
}
