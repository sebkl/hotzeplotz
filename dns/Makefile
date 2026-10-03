-include ../config.mk

# Toolchain configuration
GO ?= go
GCLOUD ?= gcloud
BIN := testserver
TOKENGEN_BIN := tokengen

# Cloud Function deployment settings
RUNTIME ?= go127
ENTRY_POINT ?= UpdateHTTP
FUNCTION_NAME ?= update-dns
REGION ?= europe-west1
PROJECT_ID ?= change-project-id
UPDATE_TOKEN ?= "MY_SECRET_TOKEN"

UPDATE_URL := "https://$(REGION)-$(PROJECT_ID).cloudfunctions.net/$(FUNCTION_NAME)
KMS_SIGN_KEY_RESOURCE ?= "projects/$(PROJECT_ID)/locations/$(REGION)/keyRings/$(KMS_KEYRING)/cryptoKeys/$(KMS_SIGN_KEYNAME)/cryptoKeyVersions/1"

# List of all Go packages in the repository
PKGS := $(shell $(GO) list ./... | grep -v /vendor/)

.PHONY: all build help test test-coverage lint fmt vet tidy benchmark clean create_keys run_testerver run run_update dploy deploy_update dploy_cf tokens

# Default target runs formatting checks, static analysis, and tests
all: fmt vet lint build test

## help: Display available Makefile commands
help:
	@echo "Usage:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## test: Run unit tests across all packages
test:
	$(GO) test -v -race -timeout 30s $(PKGS)

## test-coverage: Run tests with code coverage analysis and generate HTML report
test-coverage:
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic $(PKGS)
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated at coverage.html"

## fmt: Automatically format Go source files using gofmt
fmt:
	$(GO) fmt $(PKGS)

## vet: Run static code analysis using go vet
vet:
	$(GO) vet $(PKGS)

## lint: Rungolangci-lint (requires golangci-lint installed)
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint is not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## benchmark: Run benchmark tests
benchmark:
	$(GO) test -bench=. -benchmem $(PKGS)

## tidy: Clean up go.mod and sync dependencies
tidy:
	$(GO) mod tidy
	$(GO) mod verify

## clean: Remove temporary test reports and build artifacts
clean:
	rm -f coverage.out coverage.html $(TOKENGEN_BIN)
	$(GO) clean

$(BIN):
	cd testing/ && $(GO) build -o $(BIN) ./dnsserver.go

$(TOKENGEN_BIN):
	$(GO) build -o $(TOKENGEN_BIN) ./cmd/tokengen

## build: build all go packages
build: $(BIN)
	$(GO) build $(PKGS)


## Create all keys
create_keys: $(KMS_SIGN_KEYNAME)

## Make sure the keyring is created in KMS
$(KMS_KEYRING):
	@if $(GCLOUD) kms keyrings describe $(KMS_KEYRING) --location $(REGION) > /dev/null 2>&1; then \
		echo "KeyRing $(KMS_KEYRING) already exists."; \
	else \
		$(GCLOUD) kms keyrings create $(KMS_KEYRING) \
			--location $(REGION); \
	fi

## Make sure the signing key is created in KMS
$(KMS_SIGN_KEYNAME): $(KMS_KEYRING)
	@if $(GCLOUD) kms keys describe $(KMS_SIGN_KEYNAME) --location $(REGION) --keyring $(KMS_KEYRING) > /dev/null 2>&1; then \
		echo "Key $(KMS_SIGN_KEYNAME) already exists."; \
	else \
		$(GCLOUD) kms keys create $(KMS_SIGN_KEYNAME) \
			--location $(REGION) \
			--keyring $(KMS_KEYRING) \
			--purpose asymmetric-signing \
			--default-algorithm rsa-sign-pkcs1-4096-sha256 \
			--protection-level hsm; \
	fi

## Generate all tokens
tokens: $(UPDATE_HOST).token

## Generate a token for the update host
$(UPDATE_HOST).token: $(KMS_SIGN_KEYNAME) $(TOKENGEN_BIN)
	$(TOKENGEN_BIN) --key "$(KMS_SIGN_KEY_RESOURCE)" --hosts "$(UPDATE_HOST)" > $@ 
	chmod 600 $@

## Build and run local HTTP function server
run_testserver: build
	cd testing && ./$(BIN)

## Trigger client DNS update check (alias for run_update)
run: run_update

## Execute the client DNS update script
run_update:
	./dns/update.sh "$(UPDATE_HOST)" "$(UPDATE_TOKEN)" "$(UPDATE_URL)" "$(UPDATE_MANAGED_ZONE)"

## Copy update script to remote deployment target
deploy_update: $(UPDATE_HOST).token
	scp update.sh $(DEPLOY_TARGET)
	scp $(UPDATE_HOST).token $(DEPLOY_TARGET)/$(UPDATE_HOST).token

## Deploy Cloud Function to Google Cloud
deploy_cf:
	$(GCLOUD) functions deploy $(FUNCTION_NAME) \
		--project=$(PROJECT_ID) \
		--region=$(REGION) \
		--gen2 \
		--runtime=$(RUNTIME) \
		--source=./ \
		--entry-point=$(ENTRY_POINT) \
		--trigger-http \
		--allow-unauthenticated \
		--set-env-vars GOOGLE_CLOUD_PROJECT=$(PROJECT_ID),KMS_SIGN_KEYNAME=$(KMS_SIGN_KEY_RESOURCE)

## Deploy both client update script and Cloud Function
deploy: deploy_update deploy_cf