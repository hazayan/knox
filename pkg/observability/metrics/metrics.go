// Package metrics provides Prometheus metrics for Knox.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RequestsTotal counts total HTTP requests.
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "knox_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	// RequestDuration measures HTTP request latency.
	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "knox_request_duration_seconds",
			Help:    "HTTP request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// KeysTotal tracks the total number of keys.
	KeysTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "knox_keys_total",
			Help: "Total number of keys in storage",
		},
	)

	// StorageOperationsTotal counts storage backend operations.
	StorageOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "knox_storage_operations_total",
			Help: "Total number of storage operations",
		},
		[]string{"backend", "operation", "status"},
	)

	// StorageOperationDuration measures storage operation latency.
	StorageOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "knox_storage_operation_duration_seconds",
			Help:    "Storage operation latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"backend", "operation"},
	)

	// AuthAttemptsTotal counts authentication attempts.
	AuthAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "knox_auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"provider", "status"},
	)

	// KeyAccessTotal counts key access events.
	KeyAccessTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "knox_key_access_total",
			Help: "Total number of key access events",
		},
		[]string{"key_id", "principal_type", "access_type", "result"},
	)

	// KeyVersionsTotal tracks the number of versions per key.
	KeyVersionsTotal = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "knox_key_versions",
			Help:    "Number of versions per key",
			Buckets: []float64{1, 2, 5, 10, 20, 50},
		},
		[]string{"key_id"},
	)

	// ACLEntriesTotal tracks the number of ACL entries per key.
	ACLEntriesTotal = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "knox_acl_entries",
			Help:    "Number of ACL entries per key",
			Buckets: []float64{1, 2, 5, 10, 20, 50},
		},
		[]string{"key_id"},
	)
)

// RecordRequest records an HTTP request metric.
func RecordRequest(method, path, status string, duration float64) {
	RequestsTotal.WithLabelValues(method, path, status).Inc()
	RequestDuration.WithLabelValues(method, path).Observe(duration)
}

// RecordStorageOperation records a storage operation metric.
func RecordStorageOperation(backend, operation, status string, duration float64) {
	StorageOperationsTotal.WithLabelValues(backend, operation, status).Inc()
	StorageOperationDuration.WithLabelValues(backend, operation).Observe(duration)
}

// RecordAuthAttempt records an authentication attempt.
func RecordAuthAttempt(provider, status string) {
	AuthAttemptsTotal.WithLabelValues(provider, status).Inc()
}

// RecordKeyAccess records a key access event.
func RecordKeyAccess(keyID, principalType, accessType, result string) {
	KeyAccessTotal.WithLabelValues(keyID, principalType, accessType, result).Inc()
}

// UpdateKeyMetrics updates key-related metrics.
func UpdateKeyMetrics(keyID string, numVersions, numACLEntries int) {
	KeyVersionsTotal.WithLabelValues(keyID).Observe(float64(numVersions))
	ACLEntriesTotal.WithLabelValues(keyID).Observe(float64(numACLEntries))
}

// SetKeysTotal sets the total number of keys.
func SetKeysTotal(count int64) {
	KeysTotal.Set(float64(count))
}
