package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	acmetest "github.com/cert-manager/cert-manager/test/acme"
)

type MockBunnyDNSClient struct {
	zones        map[string]int64          // domain -> zoneID
	records      map[int64][]MockDNSRecord // zoneID -> records
	nextRecordID int64
	// For simulating errors
	shouldFailGetZoneID    bool
	shouldFailCreateRecord bool
	shouldFailDeleteRecord bool
	shouldFailFindRecord   bool
}

type MockDNSRecord struct {
	ID    int64
	Name  string
	Value string
	Type  string
	TTL   int32
}

func NewMockBunnyDNSClient() *MockBunnyDNSClient {
	return &MockBunnyDNSClient{
		zones:        make(map[string]int64),
		records:      make(map[int64][]MockDNSRecord),
		nextRecordID: 1,
	}
}

func (m *MockBunnyDNSClient) GetZoneID(domain string) (int64, error) {
	if m.shouldFailGetZoneID {
		return 0, fmt.Errorf("mock error: failed to get zone ID")
	}

	if zoneID, exists := m.zones[domain]; exists {
		return zoneID, nil
	}
	return 0, fmt.Errorf("domain %s not found in BunnyDNS zones", domain)
}

func (m *MockBunnyDNSClient) CreateRecord(zoneID int64, record *DNSRecord) (int64, error) {
	if m.shouldFailCreateRecord {
		return 0, fmt.Errorf("mock error: failed to create record")
	}

	recordID := m.nextRecordID
	m.nextRecordID++

	recordType, ok := record.Type.(string)
	if !ok {
		return 0, fmt.Errorf("invalid record type: %T", record.Type)
	}

	mockRecord := MockDNSRecord{
		ID:    recordID,
		Name:  record.Name,
		Value: record.Value,
		Type:  recordType,
		TTL:   record.TTL,
	}

	m.records[zoneID] = append(m.records[zoneID], mockRecord)
	return recordID, nil
}

func (m *MockBunnyDNSClient) DeleteRecord(zoneID, recordID int64) error {
	if m.shouldFailDeleteRecord {
		return fmt.Errorf("mock error: failed to delete record")
	}

	records := m.records[zoneID]
	for i, record := range records {
		if record.ID == recordID {
			m.records[zoneID] = append(records[:i], records[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("record not found: %d", recordID)
}

func (m *MockBunnyDNSClient) FindRecordByNameAndValue(zoneID int64, name, value string) (int64, error) {
	if m.shouldFailFindRecord {
		return 0, fmt.Errorf("mock error: failed to find record")
	}

	records := m.records[zoneID]
	for _, record := range records {
		if record.Name == name && record.Value == value && record.Type == "TXT" {
			return record.ID, nil
		}
	}
	return 0, fmt.Errorf("record not found: name=%s, value=%s", name, value)
}

func (m *MockBunnyDNSClient) SetupTestZone(domain string, zoneID int64) {
	m.zones[domain] = zoneID
}

func (m *MockBunnyDNSClient) GetRecords(zoneID int64) []MockDNSRecord {
	return m.records[zoneID]
}

func TestBunnyDNSProviderSolver_Present(t *testing.T) {
	tests := []struct {
		name           string
		fqdn           string
		key            string
		domain         string
		zoneID         int64
		expectedRecord MockDNSRecord
		setupMock      func(*MockBunnyDNSClient)
		expectError    bool
		errorContains  string
	}{
		{
			name:   "successful record creation",
			fqdn:   "_acme-challenge.example.com",
			key:    "test-challenge-key",
			domain: "example.com",
			zoneID: 123,
			expectedRecord: MockDNSRecord{
				ID:    1,
				Name:  "_acme-challenge",
				Value: "test-challenge-key",
				Type:  "TXT",
				TTL:   DefaultTTL,
			},
			setupMock: func(mock *MockBunnyDNSClient) {
				mock.SetupTestZone("example.com", 123)
			},
			expectError: false,
		},
		{
			name:   "zone not found",
			fqdn:   "_acme-challenge.nonexistent.com",
			key:    "test-key",
			domain: "nonexistent.com",
			setupMock: func(mock *MockBunnyDNSClient) {
			},
			expectError:   true,
			errorContains: "error getting zone ID",
		},
		{
			name:   "create record fails",
			fqdn:   "_acme-challenge.example.com",
			key:    "test-key",
			domain: "example.com",
			zoneID: 123,
			setupMock: func(mock *MockBunnyDNSClient) {
				mock.SetupTestZone("example.com", 123)
				mock.shouldFailCreateRecord = true
			},
			expectError:   true,
			errorContains: "error creating DNS record",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := NewMockBunnyDNSClient()
			tt.setupMock(mockClient)

			solver := &bunnyDNSProviderSolver{
				dnsClientFactory: func(apiKey string) BunnyDNSClientInterface {
					return mockClient
				},
			}

			challengeRequest := &v1alpha1.ChallengeRequest{
				ResolvedFQDN:      tt.fqdn,
				Key:               tt.key,
				ResourceNamespace: "default",
				Config:            nil,
			}

			os.Setenv("BUNNYDNS_API_KEY", "test-api-key")
			defer os.Unsetenv("BUNNYDNS_API_KEY")

			err := solver.Present(challengeRequest)

			if tt.expectError {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Fatalf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			records := mockClient.GetRecords(tt.zoneID)
			if len(records) != 1 {
				t.Fatalf("Expected 1 record, got %d", len(records))
			}

			record := records[0]
			if record.Name != tt.expectedRecord.Name {
				t.Errorf("Expected name '%s', got '%s'", tt.expectedRecord.Name, record.Name)
			}
			if record.Value != tt.expectedRecord.Value {
				t.Errorf("Expected value '%s', got '%s'", tt.expectedRecord.Value, record.Value)
			}
			if record.Type != tt.expectedRecord.Type {
				t.Errorf("Expected type '%s', got '%s'", tt.expectedRecord.Type, record.Type)
			}
			if record.TTL != tt.expectedRecord.TTL {
				t.Errorf("Expected TTL %d, got %d", tt.expectedRecord.TTL, record.TTL)
			}
		})
	}
}

func TestBunnyDNSProviderSolver_CleanUp(t *testing.T) {
	tests := []struct {
		name          string
		fqdn          string
		key           string
		domain        string
		zoneID        int64
		setupMock     func(*MockBunnyDNSClient)
		expectError   bool
		errorContains string
	}{
		{
			name:   "successful record cleanup",
			fqdn:   "_acme-challenge.example.com",
			key:    "test-challenge-key",
			domain: "example.com",
			zoneID: 123,
			setupMock: func(mock *MockBunnyDNSClient) {
				mock.SetupTestZone("example.com", 123)
				mock.CreateRecord(123, &DNSRecord{
					Name:  "_acme-challenge",
					Value: "test-challenge-key",
					Type:  "TXT",
					TTL:   DefaultTTL,
				})
			},
			expectError: false,
		},
		{
			name:   "record not found (already cleaned up)",
			fqdn:   "_acme-challenge.example.com",
			key:    "nonexistent-key",
			domain: "example.com",
			zoneID: 123,
			setupMock: func(mock *MockBunnyDNSClient) {
				mock.SetupTestZone("example.com", 123)
			},
			expectError: false,
		},
		{
			name:   "zone not found",
			fqdn:   "_acme-challenge.nonexistent.com",
			key:    "test-key",
			domain: "nonexistent.com",
			setupMock: func(mock *MockBunnyDNSClient) {
			},
			expectError:   true,
			errorContains: "error getting zone ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := NewMockBunnyDNSClient()
			tt.setupMock(mockClient)

			solver := &bunnyDNSProviderSolver{
				dnsClientFactory: func(apiKey string) BunnyDNSClientInterface {
					return mockClient
				},
			}

			challengeRequest := &v1alpha1.ChallengeRequest{
				ResolvedFQDN:      tt.fqdn,
				Key:               tt.key,
				ResourceNamespace: "default",
				Config:            nil,
			}

			os.Setenv("BUNNYDNS_API_KEY", "test-api-key")
			defer os.Unsetenv("BUNNYDNS_API_KEY")

			err := solver.CleanUp(challengeRequest)

			if tt.expectError {
				if err == nil {
					t.Fatalf("Expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Fatalf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			records := mockClient.GetRecords(tt.zoneID)
			for _, record := range records {
				if record.Name == "_acme-challenge" && record.Value == tt.key {
					t.Errorf("Record should have been deleted but still exists: %+v", record)
				}
			}
		})
	}
}

func TestBunnyDNSProviderSolver_PresentAndCleanUp_Integration(t *testing.T) {
	mockClient := NewMockBunnyDNSClient()
	mockClient.SetupTestZone("example.com", 123)

	solver := &bunnyDNSProviderSolver{
		dnsClientFactory: func(apiKey string) BunnyDNSClientInterface {
			return mockClient
		},
	}

	challengeRequest := &v1alpha1.ChallengeRequest{
		ResolvedFQDN:      "_acme-challenge.example.com",
		Key:               "integration-test-key",
		ResourceNamespace: "default",
		Config:            nil,
	}

	// Set environment variable for API key
	os.Setenv("BUNNYDNS_API_KEY", "test-api-key")
	defer os.Unsetenv("BUNNYDNS_API_KEY")

	// Present the challenge
	err := solver.Present(challengeRequest)
	if err != nil {
		t.Fatalf("Present failed: %v", err)
	}

	records := mockClient.GetRecords(123)
	if len(records) != 1 {
		t.Fatalf("Expected 1 record after Present, got %d", len(records))
	}

	err = solver.CleanUp(challengeRequest)
	if err != nil {
		t.Fatalf("CleanUp failed: %v", err)
	}

	records = mockClient.GetRecords(123)
	if len(records) != 0 {
		t.Fatalf("Expected 0 records after CleanUp, got %d", len(records))
	}
}

func maskAPIKey(key string) string {
	if len(key) < 8 {
		return "***"
	}
	return key[:4] + "****"
}

func TestRunsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	zone := os.Getenv("TEST_ZONE_NAME")
	if zone == "" {
		t.Skip("TEST_ZONE_NAME not specified, skipping DNS conformance tests")
	}

	apiKey := os.Getenv("BUNNYDNS_API_KEY")
	if apiKey == "" {
		t.Skip("BUNNYDNS_API_KEY not specified, skipping DNS conformance tests")
	}

	t.Logf("Running integration test with zone: %s", zone)
	t.Logf("Using API key: %s...", maskAPIKey(apiKey))

	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

	fixture := acmetest.NewFixture(&bunnyDNSProviderSolver{},
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(true),
		acmetest.SetManifestPath("testdata/bunnydns"),
	)

	fixture.RunConformance(t)
}
