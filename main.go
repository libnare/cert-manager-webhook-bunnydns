package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// Build-time variables (set via -ldflags)
var Version = "dev"

const (
	DefaultTTL           = 300
	HealthCheckPort      = ":8081"
	HTTPClientTimeout    = 30 * time.Second
	ShutdownTimeout      = 5 * time.Second
	GracefulShutdownWait = 1 * time.Second
)

var (
	GroupName    = os.Getenv("GROUP_NAME")
	healthServer *http.Server
)

func main() {
	if err := validateConfiguration(); err != nil {
		klog.ErrorS(err, "Configuration validation failed")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go startHealthCheckServer(ctx)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	webhookDone := make(chan struct{})
	go func() {
		defer close(webhookDone)

		cmd.RunWebhookServer(GroupName,
			&bunnyDNSProviderSolver{},
		)
	}()

	select {
	case sig := <-sigChan:
		klog.InfoS("Received shutdown signal, starting graceful shutdown", "signal", sig)

		cancel()

		time.Sleep(GracefulShutdownWait)

		klog.InfoS("Graceful shutdown completed")

	case <-webhookDone:
		klog.InfoS("Webhook server stopped")
		cancel()
	}
}

func startHealthCheckServer(ctx context.Context) {
	mux := http.NewServeMux()

	// Liveness probe - always returns OK if the process is running
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Readiness probe - checks if the service is ready to handle requests
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if GroupName == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Not Ready: GROUP_NAME not set"))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ready"))
	})

	// Health check with detailed status
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status := map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   Version,
			"groupName": GroupName,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	healthServer = &http.Server{
		Addr:    HealthCheckPort,
		Handler: mux,
	}

	go func() {
		klog.V(1).InfoS("Starting health check server", "addr", healthServer.Addr)
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			klog.ErrorS(err, "Health check server failed")
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()

	klog.V(1).InfoS("Shutting down health check server")
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		klog.ErrorS(err, "Failed to shutdown health check server gracefully")
	}
}

func validateConfiguration() error {
	klog.V(1).InfoS("Validating configuration")

	if GroupName == "" {
		return fmt.Errorf("GROUP_NAME environment variable is required")
	}

	if len(GroupName) == 0 || len(GroupName) > 253 {
		return fmt.Errorf("GROUP_NAME must be between 1 and 253 characters")
	}

	if apiKey := os.Getenv("BUNNYDNS_API_KEY"); apiKey != "" {
		klog.V(2).InfoS("Validating BunnyDNS API connectivity")

		client := NewBunnyDNSClient(apiKey)
		if client == nil {
			return fmt.Errorf("failed to create BunnyDNS client")
		}

		klog.V(2).InfoS("BunnyDNS client created successfully")
	} else {
		klog.V(1).InfoS("BUNNYDNS_API_KEY not set - API connectivity will be validated at runtime")
	}

	klog.V(1).InfoS("Configuration validation completed successfully",
		"groupName", GroupName,
	)

	return nil
}

type bunnyDNSProviderSolver struct {
	client           kubernetes.Interface
	dnsClientFactory func(apiKey string) BunnyDNSClientInterface
}

type bunnyDNSProviderConfig struct {
	APIKeySecretRef *cmmeta.SecretKeySelector `json:"apiKeySecretRef,omitempty"`
	TTL             *int32                    `json:"ttl,omitempty"`
}

func (c *bunnyDNSProviderSolver) Name() string {
	return "bunnydns"
}

func (c *bunnyDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	startTime := time.Now()

	klog.V(2).InfoS("Starting DNS challenge presentation",
		"fqdn", ch.ResolvedFQDN,
		"namespace", ch.ResourceNamespace,
		"solver", "bunnydns",
	)

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.ErrorS(err, "Failed to decode solver config",
			"fqdn", ch.ResolvedFQDN,
			"namespace", ch.ResourceNamespace,
		)
		return fmt.Errorf("error decoding solver config: %v", err)
	}

	apiKey, err := c.getAPIKey(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("error getting API key: %v", err)
	}

	var dnsClient BunnyDNSClientInterface
	if c.dnsClientFactory != nil {
		dnsClient = c.dnsClientFactory(apiKey)
	} else {
		dnsClient = NewBunnyDNSClient(apiKey)
	}

	domain := extractDomain(ch.ResolvedFQDN)
	if domain == "" {
		return fmt.Errorf("could not extract domain from FQDN: %s", ch.ResolvedFQDN)
	}

	zoneID, err := dnsClient.GetZoneID(domain)
	if err != nil {
		return fmt.Errorf("error getting zone ID for domain %s: %v", domain, err)
	}

	recordName := extractRecordName(ch.ResolvedFQDN, domain)

	ttl := int32(DefaultTTL)
	if cfg.TTL != nil {
		ttl = *cfg.TTL
	}

	record := &DNSRecord{
		Type:  "TXT", // For creation, use string
		Name:  recordName,
		Value: ch.Key,
		TTL:   ttl,
	}

	recordID, err := dnsClient.CreateRecord(zoneID, record)
	if err != nil {
		klog.ErrorS(err, "Failed to create DNS record",
			"fqdn", ch.ResolvedFQDN,
			"domain", domain,
			"zoneID", zoneID,
			"recordName", recordName,
		)
		return fmt.Errorf("error creating DNS record: %v", err)
	}

	duration := time.Since(startTime)
	klog.V(2).InfoS("Successfully presented DNS challenge",
		"fqdn", ch.ResolvedFQDN,
		"domain", domain,
		"zoneID", zoneID,
		"recordID", recordID,
		"recordName", recordName,
		"duration", duration,
	)

	klog.V(3).InfoS("DNS record created successfully", "recordID", recordID)

	return nil
}

func (c *bunnyDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	startTime := time.Now()

	klog.V(2).InfoS("Starting DNS challenge cleanup",
		"fqdn", ch.ResolvedFQDN,
		"namespace", ch.ResourceNamespace,
		"solver", "bunnydns",
	)

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.ErrorS(err, "Failed to decode solver config during cleanup",
			"fqdn", ch.ResolvedFQDN,
			"namespace", ch.ResourceNamespace,
		)
		return fmt.Errorf("error decoding solver config: %v", err)
	}

	apiKey, err := c.getAPIKey(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("error getting API key: %v", err)
	}

	var dnsClient BunnyDNSClientInterface
	if c.dnsClientFactory != nil {
		dnsClient = c.dnsClientFactory(apiKey)
	} else {
		dnsClient = NewBunnyDNSClient(apiKey)
	}

	domain := extractDomain(ch.ResolvedFQDN)
	if domain == "" {
		return fmt.Errorf("could not extract domain from FQDN: %s", ch.ResolvedFQDN)
	}

	zoneID, err := dnsClient.GetZoneID(domain)
	if err != nil {
		return fmt.Errorf("error getting zone ID for domain %s: %v", domain, err)
	}

	recordName := extractRecordName(ch.ResolvedFQDN, domain)

	recordID, err := dnsClient.FindRecordByNameAndValue(zoneID, recordName, ch.Key)
	if err != nil {
		if strings.Contains(err.Error(), "record not found") {
			klog.V(2).InfoS("Record already cleaned up or not found",
				"fqdn", ch.ResolvedFQDN,
				"recordName", recordName,
				"value", ch.Key)
			return nil
		}
		return fmt.Errorf("error finding DNS record: %v", err)
	}

	err = dnsClient.DeleteRecord(zoneID, recordID)
	if err != nil {
		klog.ErrorS(err, "Failed to delete DNS record",
			"fqdn", ch.ResolvedFQDN,
			"domain", domain,
			"zoneID", zoneID,
			"recordID", recordID,
		)
		return fmt.Errorf("error deleting DNS record: %v", err)
	}

	duration := time.Since(startTime)
	klog.V(2).InfoS("Successfully cleaned up DNS challenge",
		"fqdn", ch.ResolvedFQDN,
		"domain", domain,
		"zoneID", zoneID,
		"recordID", recordID,
		"duration", duration,
	)

	return nil
}

func (c *bunnyDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (bunnyDNSProviderConfig, error) {
	cfg := bunnyDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *bunnyDNSProviderSolver) getAPIKey(cfg bunnyDNSProviderConfig, namespace string) (string, error) {
	if apiKey := os.Getenv("BUNNYDNS_API_KEY"); apiKey != "" {
		return apiKey, nil
	}

	if cfg.APIKeySecretRef == nil {
		return "", fmt.Errorf("no API key provided: set BUNNYDNS_API_KEY environment variable or provide apiKeySecretRef in config")
	}

	secretName := cfg.APIKeySecretRef.Name
	secretKey := cfg.APIKeySecretRef.Key

	secret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting secret %s/%s: %v", namespace, secretName, err)
	}

	apiKeyBytes, exists := secret.Data[secretKey]
	if !exists {
		return "", fmt.Errorf("key %s not found in secret %s/%s", secretKey, namespace, secretName)
	}

	return string(apiKeyBytes), nil
}

func extractDomain(fqdn string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")

	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return ""
	}

	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}

	return ""
}

func extractRecordName(fqdn, domain string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	domain = strings.TrimSuffix(domain, ".")

	if strings.HasSuffix(fqdn, "."+domain) {
		return strings.TrimSuffix(fqdn, "."+domain)
	}

	if fqdn == domain {
		return ""
	}

	return fqdn
}
