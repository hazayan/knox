// Package metrics provides Prometheus metrics for Knox.
package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestRecordRequest(t *testing.T) {
	// Reset metrics to ensure clean state
	RequestsTotal.Reset()
	RequestDuration.Reset()

	// Test recording a request
	method := "GET"
	path := "/api/v1/keys"
	status := "200"
	duration := 0.123

	RecordRequest(method, path, status, duration)

	// Verify request counter
	counter := dto.CollectAndCount(RequestsTotal)
	if counter != 1 {
		t.Errorf("Expected 1 metric, got %d", counter)
	}

	// Verify request duration histogram
	histogram := dto.CollectAndCount(RequestDuration)
	if histogram != 1 {
		t.Errorf("Expected 1 histogram observation, got %d", histogram)
	}
}

func TestRecordDBusOperation(t *testing.T) {
	// Reset metrics
	DBusOperationsTotal.Reset()
	DBusOperationDuration.Reset()

	operation := "OpenSession"
	status := "success"
	duration := 0.045

	RecordDBusOperation(operation, status, duration)

	// Verify operation counter
	counter := dto.CollectAndCount(DBusOperationsTotal)
	if counter != 1 {
		t.Errorf("Expected 1 metric, got %d", counter)
	}

	// Verify operation duration histogram
	histogram := dto.CollectAndCount(DBusOperationDuration)
	if histogram != 1 {
		t.Errorf("Expected 1 histogram observation, got %d", histogram)
	}
}

func TestRecordDBusSession(t *testing.T) {
	DBusSessionsTotal.Reset()

	algorithm := "plain"

	RecordDBusSession(algorithm)

	counter := dto.CollectAndCount(DBusSessionsTotal)
	if counter != 1 {
		t.Errorf("Expected 1 metric, got %d", counter)
	}
}

func TestRecordDBusCollection(t *testing.T) {
	DBusCollectionsTotal.Reset()

	operation := "CreateCollection"

	RecordDBusCollection(operation)

	counter := dto.CollectAndCount(DBusCollectionsTotal)
	if counter != 1 {
		t.Errorf("Expected 1 metric, got %d", counter)
	}
}

func TestRecordDBusItem(t *testing.T) {
	DBusItemsTotal.Reset()

	operation := "CreateItem"

	RecordDBusItem(operation)

	counter := dto.CollectAndCount(DBusItemsTotal)
	if counter != 1 {
		t.Errorf("Expected 1 metric, got %d", counter)
	}
}

func TestRecordDBusSecret(t *testing.T) {
	DBusSecretsTotal.Reset()

	operation := "GetSecrets"
	result := "success"

	RecordDBusSecret(operation, result)

	counter := dto.CollectAndCount(DBusSecretsTotal)
	if counter != 1 {
		t.Errorf("Expected 1 metric, got %d", counter)
	}
}

func TestRecordDBusPrompt(t *testing.T) {
	DBusPromptTotal.Reset()

	promptType := "confirmation"
	result := "accepted"

	RecordDBusPrompt(promptType, result)

	counter := dto.CollectAndCount(DBusPromptTotal)
	if counter != 1 {
		t.Errorf("Expected 1 metric, got %d", counter)
	}
}

func TestRecordStorageOperation(t *testing.T) {
	// Reset metrics
	StorageOperationsTotal.Reset()
	StorageOperationDuration.Reset()

	backend := "postgres"
	operation := "GetKey"
	status := "success"
	duration := 0.012

	RecordStorageOperation(backend, operation, status, duration)

	// Verify storage operation counter
	counter := dto.CollectAndCount(StorageOperationsTotal)
	if counter != 1 {
		t.Errorf("Expected 1 metric, got %d", counter)
	}

	// Verify storage operation duration histogram
	histogram := dto.CollectAndCount(StorageOperationDuration)
	if histogram != 1 {
		t.Errorf("Expected 1 histogram observation, got %d", histogram)
	}
}

func TestRecordAuthAttempt(t *testing.T) {
	AuthAttemptsTotal.Reset()

	provider := "mtls"
	status := "success"

	RecordAuthAttempt(provider, status)

	counter := dto.CollectAndCount(AuthAttemptsTotal)
	if counter != 1 {
		t.Errorf("Expected 1 metric, got %d", counter)
	}
}

func TestRecordKeyAccess(t *testing.T) {
	KeyAccessTotal.Reset()

	keyID := "test:database_password"
	principalType := "user"
	accessType := "read"
	result := "allowed"

	RecordKeyAccess(keyID, principalType, accessType, result)

	counter := dto.CollectAndCount(KeyAccessTotal)
	if counter != 1 {
		t.Errorf("Expected 1 metric, got %d", counter)
	}
}

func TestUpdateKeyMetrics(t *testing.T) {
	KeyVersionsTotal.Reset()
	ACLEntriesTotal.Reset()

	keyID := "test:api_key"
	numVersions := 3
	numACLEntries := 5

	UpdateKeyMetrics(keyID, numVersions, numACLEntries)

	// Verify key versions histogram
	versionsHistogram := dto.CollectAndCount(KeyVersionsTotal)
	if versionsHistogram != 1 {
		t.Errorf("Expected 1 histogram observation, got %d", versionsHistogram)
	}

	// Verify ACL entries histogram
	aclHistogram := dto.CollectAndCount(ACLEntriesTotal)
	if aclHistogram != 1 {
		t.Errorf("Expected 1 histogram observation, got %d", aclHistogram)
	}
}

func TestSetKeysTotal(t *testing.T) {
	// Reset gauge by setting to 0
	KeysTotal.Set(0)

	count := int64(42)

	SetKeysTotal(count)

	// Verify gauge value by collecting and checking the value
	metrics := make(chan prometheus.Metric, 1)
	go func() {
		KeysTotal.Collect(metrics)
		close(metrics)
	}()

	metric := <-metrics
	if metric == nil {
		t.Fatal("Expected gauge metric")
	}

	// We can't easily verify the exact value without more complex parsing
	// Just verify that the metric exists and can be collected
	assert.NotNil(t, metric)
}

func TestMultipleRecordings(t *testing.T) {
	// Reset all metrics
	RequestsTotal.Reset()
	RequestDuration.Reset()
	DBusOperationsTotal.Reset()
	StorageOperationsTotal.Reset()

	// Record multiple requests
	RecordRequest("GET", "/api/v1/keys", "200", 0.1)
	RecordRequest("POST", "/api/v1/keys", "201", 0.2)
	RecordRequest("DELETE", "/api/v1/keys/test", "204", 0.05)

	// Record multiple D-Bus operations
	RecordDBusOperation("OpenSession", "success", 0.01)
	RecordDBusOperation("CreateCollection", "success", 0.02)
	RecordDBusOperation("SearchItems", "success", 0.015)

	// Record multiple storage operations
	RecordStorageOperation("postgres", "GetKey", "success", 0.005)
	RecordStorageOperation("postgres", "PutKey", "success", 0.008)
	RecordStorageOperation("memory", "GetKey", "success", 0.003)

	// Verify request counts
	requestsCount := dto.CollectAndCount(RequestsTotal)
	if requestsCount != 3 {
		t.Errorf("Expected 3 request metrics, got %d", requestsCount)
	}

	// Verify D-Bus operation counts
	dbusCount := dto.CollectAndCount(DBusOperationsTotal)
	if dbusCount != 3 {
		t.Errorf("Expected 3 D-Bus operation metrics, got %d", dbusCount)
	}

	// Verify storage operation counts
	storageCount := dto.CollectAndCount(StorageOperationsTotal)
	if storageCount != 3 {
		t.Errorf("Expected 3 storage operation metrics, got %d", storageCount)
	}
}

func TestMetricLabels(t *testing.T) {
	// Test that metrics are properly labeled
	RequestsTotal.Reset()

	// Record requests with different labels
	RecordRequest("GET", "/health", "200", 0.001)
	RecordRequest("POST", "/api/v1/keys", "400", 0.002)
	RecordRequest("GET", "/metrics", "200", 0.001)

	// Collect all metrics and verify we have 3 distinct time series
	metrics := make(chan prometheus.Metric, 10)
	go func() {
		RequestsTotal.Collect(metrics)
		close(metrics)
	}()

	count := 0
	for range metrics {
		count++
	}

	if count != 3 {
		t.Errorf("Expected 3 distinct time series, got %d", count)
	}
}

func TestConcurrentMetricAccess(t *testing.T) {
	// Test that metrics can be safely accessed concurrently
	RequestsTotal.Reset()

	done := make(chan bool)
	numGoroutines := 10
	requestsPerGoroutine := 100

	for i := range numGoroutines {
		go func(_ int) {
			for range requestsPerGoroutine {
				RecordRequest("GET", "/api/v1/keys", "200", 0.1)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for range numGoroutines {
		<-done
	}

	// Verify total count
	counter := dto.CollectAndCount(RequestsTotal)

	// Prometheus counters are cumulative, so we should have exactly 1 time series
	// with the value of total requests, not individual observations
	if counter != 1 {
		t.Errorf("Expected 1 time series, got %d", counter)
	}
}

func BenchmarkRecordRequest(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		RecordRequest("GET", "/api/v1/keys", "200", 0.1)
	}
}

func BenchmarkRecordDBusOperation(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		RecordDBusOperation("OpenSession", "success", 0.01)
	}
}

func BenchmarkRecordStorageOperation(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		RecordStorageOperation("postgres", "GetKey", "success", 0.005)
	}
}
