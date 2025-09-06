GO ?= $(shell which go)
OS ?= $(shell $(GO) env GOOS)
ARCH ?= $(shell $(GO) env GOARCH)

IMAGE_NAME := "cert-manager-webhook-bunnydns"
IMAGE_TAG := "latest"

OUT := $(shell pwd)/_out

KUBEBUILDER_VERSION=1.28.0

HELM_FILES := $(shell find deploy/cert-manager-webhook-bunnydns -name "*.yaml" -o -name "*.tpl" 2>/dev/null || true)

.PHONY: test test-unit test-integration
test: _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/etcd _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kube-apiserver _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kubectl
	@echo "Running tests..."
	@if [ -n "$(TEST_ZONE_NAME)" ] && [ -n "$(BUNNYDNS_API_KEY)" ]; then \
		echo "Integration test environment detected:"; \
		echo "  - Zone: $(TEST_ZONE_NAME)"; \
		echo "  - API Key: $(shell echo $(BUNNYDNS_API_KEY) | cut -c1-8)********"; \
		echo "Running unit tests + integration tests..."; \
		echo "Step 1/2: Running unit tests..."; \
		$(MAKE) test-unit; \
		echo "Step 2/2: Running integration tests..."; \
		$(MAKE) test-integration; \
	else \
		echo "Running unit tests only (Mock-based, fast)"; \
		echo "To run integration tests, set: TEST_ZONE_NAME=your-domain.com BUNNYDNS_API_KEY=your-key"; \
		$(MAKE) test-unit; \
	fi

# Run only unit tests (fast, no external dependencies)
test-unit: _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/etcd _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kube-apiserver _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kubectl
	@echo "Running unit tests only..."
	TEST_ASSET_ETCD=_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/etcd \
	TEST_ASSET_KUBE_APISERVER=_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kube-apiserver \
	TEST_ASSET_KUBECTL=_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kubectl \
	$(GO) test -v -short .

# Run integration tests (requires real API credentials)
test-integration: _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/etcd _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kube-apiserver _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kubectl
	@if [ -z "$(TEST_ZONE_NAME)" ] || [ -z "$(BUNNYDNS_API_KEY)" ]; then \
		echo "ERROR: Integration test requires environment variables:"; \
		echo "   TEST_ZONE_NAME=your-domain.com"; \
		echo "   BUNNYDNS_API_KEY=your-api-key"; \
		echo ""; \
		echo "Example: TEST_ZONE_NAME=example.com BUNNYDNS_API_KEY=your-key make test-integration"; \
		exit 1; \
	fi
	@echo "Running integration tests with real BunnyDNS API..."
	@echo "  - Zone: $(TEST_ZONE_NAME)"
	@echo "  - API Key: $(shell echo $(BUNNYDNS_API_KEY) | cut -c1-8)********"
	TEST_ASSET_ETCD=_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/etcd \
	TEST_ASSET_KUBE_APISERVER=_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kube-apiserver \
	TEST_ASSET_KUBECTL=_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kubectl \
	TEST_ZONE_NAME=$(TEST_ZONE_NAME) \
	BUNNYDNS_API_KEY=$(BUNNYDNS_API_KEY) \
	$(GO) test -v -count=1 -run TestRunsSuite .

_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH).tar.gz: | _test
	curl -fsSL https://go.kubebuilder.io/test-tools/$(KUBEBUILDER_VERSION)/$(OS)/$(ARCH) -o $@

_test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/etcd _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kube-apiserver _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)/kubectl: _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH).tar.gz | _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH)
	tar xfO $< kubebuilder/bin/$(notdir $@) > $@ && chmod +x $@

.PHONY: clean
clean:
	rm -rf _test $(OUT)

.PHONY: build
build:
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)" \
		--build-arg VERSION=$(shell git describe --tags --always --dirty) \
		.

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml: $(OUT)/rendered-manifest.yaml

$(OUT)/rendered-manifest.yaml: $(HELM_FILES) | $(OUT)
	helm template \
	    --name cert-manager-webhook-bunnydns \
            --set image.repository=$(IMAGE_NAME) \
            --set image.tag=$(IMAGE_TAG) \
            deploy/cert-manager-webhook-bunnydns > $@

.PHONY: verify
verify:
	$(GO) mod tidy
	$(GO) fmt ./...
	$(GO) vet ./...

_test $(OUT) _test/kubebuilder-$(KUBEBUILDER_VERSION)-$(OS)-$(ARCH):
	mkdir -p $@
