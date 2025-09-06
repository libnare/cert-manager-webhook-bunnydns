package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

const (
	bunnyDNSBaseURL = "https://api.bunny.net/dnszone"
	maxRetries      = 3
	baseDelay       = 1 * time.Second
)

// BunnyDNS enum mappings (API returns numeric, but accepts string)
var recordTypeMap = map[float64]string{
	1:  "A",
	2:  "AAAA",
	3:  "TXT",
	4:  "MX",
	5:  "CNAME",
	6:  "Redirect",
	7:  "Flatten",
	8:  "PullZone",
	9:  "SRV",
	10: "CAA",
	11: "PTR",
	12: "Script",
	13: "NS",
}

var monitorTypeMap = map[float64]string{
	0: "None",
	1: "Ping",
	2: "Http",
	3: "Monitor",
}

var smartRoutingTypeMap = map[float64]string{
	0: "None",
	1: "Latency",
	2: "Geolocation",
}

var monitorStatusMap = map[float64]string{
	0: "Unknown",
	1: "Online",
	2: "Offline",
}

func parseRecordType(typeField interface{}) string {
	return parseEnumField(typeField, recordTypeMap)
}

func parseMonitorType(typeField interface{}) string {
	return parseEnumField(typeField, monitorTypeMap)
}

func parseSmartRoutingType(typeField interface{}) string {
	return parseEnumField(typeField, smartRoutingTypeMap)
}

func parseMonitorStatus(statusField interface{}) string {
	return parseEnumField(statusField, monitorStatusMap)
}

// parseEnumField is a generic helper for parsing BunnyDNS enum fields
func parseEnumField(field interface{}, enumMap map[float64]string) string {
	switch t := field.(type) {
	case string:
		return t
	case float64:
		if mappedValue, exists := enumMap[t]; exists {
			return mappedValue
		}
	case int:
		if mappedValue, exists := enumMap[float64(t)]; exists {
			return mappedValue
		}
	case int64:
		if mappedValue, exists := enumMap[float64(t)]; exists {
			return mappedValue
		}
	}
	return ""
}

// BunnyDNSClientInterface defines the interface for BunnyDNS operations
type BunnyDNSClientInterface interface {
	GetZoneID(domain string) (int64, error)
	CreateRecord(zoneID int64, record *DNSRecord) (int64, error)
	DeleteRecord(zoneID, recordID int64) error
	FindRecordByNameAndValue(zoneID int64, name, value string) (int64, error)
}

// BunnyDNSClient represents a client for the BunnyDNS API
type BunnyDNSClient struct {
	apiKey     string
	httpClient *http.Client
}

func NewBunnyDNSClient(apiKey string) *BunnyDNSClient {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	return &BunnyDNSClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout:   HTTPClientTimeout,
			Transport: transport,
		},
	}
}

func (c *BunnyDNSClient) retryableHTTPRequest(req *http.Request) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		reqClone := req.Clone(req.Context())
		if req.Body != nil {
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read request body: %v", err)
			}
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			reqClone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		resp, err := c.httpClient.Do(reqClone)
		if err == nil {
			if resp.StatusCode < 500 {
				return resp, nil
			}
			resp.Body.Close()
			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		if attempt < maxRetries {
			delay := time.Duration(math.Pow(2, float64(attempt))) * baseDelay
			time.Sleep(delay)
		}
	}

	return nil, fmt.Errorf("request failed after %d attempts: %v", maxRetries+1, lastErr)
}

// DNSZone represents a DNS zone in BunnyDNS
type DNSZone struct {
	ID                            int64       `json:"Id"`
	Domain                        string      `json:"Domain"`
	Records                       []DNSRecord `json:"Records"`
	DateModified                  string      `json:"DateModified"`
	DateCreated                   string      `json:"DateCreated"`
	NameserversDetected           bool        `json:"NameserversDetected"`
	CustomNameserversEnabled      bool        `json:"CustomNameserversEnabled"`
	Nameserver1                   string      `json:"Nameserver1"`
	Nameserver2                   string      `json:"Nameserver2"`
	SoaEmail                      string      `json:"SoaEmail"`
	NameserversNextCheck          string      `json:"NameserversNextCheck"`
	LoggingEnabled                bool        `json:"LoggingEnabled"`
	LoggingIPAnonymizationEnabled bool        `json:"LoggingIPAnonymizationEnabled"`
	LogAnonymizationType          int         `json:"LogAnonymizationType"`
	DnsSecEnabled                 bool        `json:"DnsSecEnabled"`
	CertificateKeyType            int         `json:"CertificateKeyType"`
}

// DNSRecord represents a DNS record in BunnyDNS
type DNSRecord struct {
	ID                    int64                   `json:"Id,omitempty"`
	Type                  interface{}             `json:"Type"` // String for requests, numeric for responses
	TTL                   int32                   `json:"Ttl"`
	Value                 string                  `json:"Value"`
	Name                  string                  `json:"Name"`
	Weight                int32                   `json:"Weight,omitempty"`
	Priority              int32                   `json:"Priority,omitempty"`
	Port                  int32                   `json:"Port,omitempty"`
	Flags                 int                     `json:"Flags,omitempty"`
	Tag                   string                  `json:"Tag,omitempty"`
	Accelerated           bool                    `json:"Accelerated,omitempty"`
	AcceleratedPullZoneId int64                   `json:"AcceleratedPullZoneId,omitempty"`
	LinkName              string                  `json:"LinkName,omitempty"`
	IPGeoLocationInfo     interface{}             `json:"IPGeoLocationInfo,omitempty"`
	GeolocationInfo       interface{}             `json:"GeolocationInfo,omitempty"`
	MonitorStatus         interface{}             `json:"MonitorStatus,omitempty"` // String for requests, numeric for responses
	MonitorType           interface{}             `json:"MonitorType,omitempty"`   // String for requests, numeric for responses
	GeolocationLatitude   float64                 `json:"GeolocationLatitude,omitempty"`
	GeolocationLongitude  float64                 `json:"GeolocationLongitude,omitempty"`
	EnviromentalVariables []EnvironmentalVariable `json:"EnviromentalVariables,omitempty"`
	LatencyZone           string                  `json:"LatencyZone,omitempty"`
	SmartRoutingType      interface{}             `json:"SmartRoutingType,omitempty"` // String for requests, numeric for responses
	Disabled              bool                    `json:"Disabled,omitempty"`
	Comment               string                  `json:"Comment,omitempty"`
	AutoSslIssuance       bool                    `json:"AutoSslIssuance,omitempty"`
}

type EnvironmentalVariable struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

type DNSZoneListResponse struct {
	Items        []DNSZone `json:"Items"`
	CurrentPage  int       `json:"CurrentPage"`
	TotalItems   int       `json:"TotalItems"`
	HasMoreItems bool      `json:"HasMoreItems"`
}

type BunnyDNSError struct {
	ErrorKey string `json:"ErrorKey"`
	Field    string `json:"Field"`
	Message  string `json:"Message"`
}

func (e *BunnyDNSError) Error() string {
	return fmt.Sprintf("BunnyDNS API error: %s (field: %s, key: %s)", e.Message, e.Field, e.ErrorKey)
}

func (c *BunnyDNSClient) GetZoneID(domain string) (int64, error) {
	url := fmt.Sprintf("%s?search=%s", bunnyDNSBaseURL, domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("AccessKey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.retryableHTTPRequest(req)
	if err != nil {
		return 0, fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, c.handleErrorResponse(resp.StatusCode, body)
	}

	var zoneListResp DNSZoneListResponse
	if err := json.Unmarshal(body, &zoneListResp); err != nil {
		return 0, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	// Find the exact domain match
	for _, zone := range zoneListResp.Items {
		if zone.Domain == domain {
			return zone.ID, nil
		}
	}

	return 0, fmt.Errorf("domain %s not found in BunnyDNS zones", domain)
}

func (c *BunnyDNSClient) CreateRecord(zoneID int64, record *DNSRecord) (int64, error) {
	url := fmt.Sprintf("%s/%d/records", bunnyDNSBaseURL, zoneID)

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal record: %v", err)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(recordJSON))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("AccessKey", c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.retryableHTTPRequest(req)
	if err != nil {
		return 0, fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return 0, c.handleErrorResponse(resp.StatusCode, body)
	}

	var createdRecord DNSRecord
	if err := json.Unmarshal(body, &createdRecord); err != nil {
		return 0, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return createdRecord.ID, nil
}

func (c *BunnyDNSClient) DeleteRecord(zoneID, recordID int64) error {
	url := fmt.Sprintf("%s/%d/records/%d", bunnyDNSBaseURL, zoneID, recordID)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("AccessKey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.retryableHTTPRequest(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	return c.handleErrorResponse(resp.StatusCode, body)
}

func (c *BunnyDNSClient) FindRecordByNameAndValue(zoneID int64, name, value string) (int64, error) {
	url := fmt.Sprintf("%s/%d", bunnyDNSBaseURL, zoneID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("AccessKey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.retryableHTTPRequest(req)
	if err != nil {
		return 0, fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, c.handleErrorResponse(resp.StatusCode, body)
	}

	var zone DNSZone
	if err := json.Unmarshal(body, &zone); err != nil {
		return 0, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	for _, record := range zone.Records {
		recordType := parseRecordType(record.Type)

		if recordType == "TXT" && record.Name == name {
			recordValue := record.Value
			if len(recordValue) >= 2 && recordValue[0] == '"' && recordValue[len(recordValue)-1] == '"' {
				recordValue = recordValue[1 : len(recordValue)-1]
			}

			if recordValue == value {
				return record.ID, nil
			}
		}
	}

	return 0, fmt.Errorf("record not found: name=%s, value=%s", name, value)
}

func (c *BunnyDNSClient) handleErrorResponse(statusCode int, body []byte) error {
	switch statusCode {
	case http.StatusBadRequest:
		var bunnyErr BunnyDNSError
		if err := json.Unmarshal(body, &bunnyErr); err != nil {
			return fmt.Errorf("HTTP %d: failed to parse error response: %v", statusCode, err)
		}
		return &bunnyErr
	case http.StatusUnauthorized:
		return fmt.Errorf("HTTP %d: unauthorized - check your API key", statusCode)
	case http.StatusNotFound:
		return fmt.Errorf("HTTP %d: not found - zone or record does not exist", statusCode)
	case http.StatusInternalServerError:
		return fmt.Errorf("HTTP %d: internal server error", statusCode)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("HTTP %d: service unavailable", statusCode)
	default:
		return fmt.Errorf("HTTP %d: unexpected error: %s", statusCode, string(body))
	}
}
