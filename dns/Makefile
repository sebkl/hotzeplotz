# Toolchain configuration
GO ?= go
GCLOUD ?= gcloud
BIN := testserver

# Cloud Function deployment settings
RUNTIME ?= go127
ENTRY_POINT ?= UpdateHTTP
FUNCTION_NAME ?= update-dns
REGION ?= europe-west1
PROJECT_ID ?= change-project-id
UPDATE_TOKEN ?= "MY_SECRET_TOKEN"

UPDATE_URL := "https://$(REGION)-$(PROJECT_ID).cloudfunctions.net/$(FUNCTION_NAME)

# List of all Go packages in the repository
PKGS := $(shell $(GO) list ./... | grep -v /vendor/)

.PHONY: all build help test test-coverage lint fmt vet tidy benchmark clean testerver run run_update dploy deploy_update dploy_cf

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
	rm -f coverage.out coverage.html
	$(GO) clean

## build: build all go packages
build:
	cd testing/ && $(GO) build -o $(BIN) ./dnsserver.go
	$(GO) build $(PKGS)

## Build and run local HTTP function server
testserver: build
	cd testing && ./$(BIN)

## Trigger client DNS update check (alias for run_update)
run: run_update

## Execute the client DNS update script
run_update:
	./dns/update.sh "$(UPDATE_HOST)" "$(UPDATE_TOKEN)" "$(UPDATE_URL)" "$(UPDATE_MANAGED_ZONE)"

## Copy update script to remote deployment target
deploy_update:
	scp dns/update.sh $(DEPLOY_TARGET)

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
		--set-env-vars GOOGLE_CLOUD_PROJECT=$(PROJECT_ID)

## Deploy both client update script and Cloud Function
deploy: deploy_update deploy_cf

