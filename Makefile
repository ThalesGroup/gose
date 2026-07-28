.PHONY: all clean lint lint-fix vet coverage notices
GOCMD:=go
GOCLEAN:=$(GOCMD) clean
GOTEST:=$(GOCMD) test
GOGET:=$(GOCMD) get
GOVET:=$(GOCMD) vet
SRCS:=$(wildcard *.go) $(wildcard jose/*.go)

all: clean lint vet coverage

clean:
		$(GOCLEAN)
		rm -f coverage.out

# ── Lint ─────────────────────────────────────────────────────────────────────
# Runs golangci-lint (v2) against .golangci.yml — the same checks as the CI
# Lint workflow, so you can catch issues before pushing.
#
# Install the linter (v2, matching CI's `version: latest`):
#   go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
# Ensure $(go env GOPATH)/bin is on your PATH, then `golangci-lint version`.
GOLANGCI_LINT ?= golangci-lint

lint:
		@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		    echo "golangci-lint not found. Install the v2 binary with:"; \
		    echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
		    exit 1; \
		}
		$(GOLANGCI_LINT) run ./...

# Auto-fix the mechanically-fixable findings (formatting, some conversions):
lint-fix:
		$(GOLANGCI_LINT) run --fix ./...

vet:
		$(GOVET) ./...

test:
		$(GOTEST) -gcflags=-l -short -race ./...

coverage: coverage.out

coverage.out: $(SRCS)
		$(GOTEST) -gcflags=-l -coverprofile coverage.out ./...

## Licenses
notices:
		@go-licenses report ./... --ignore github.com/eclipse-keypont/gose,github.com/eclipse-keypont/crypto11/v2,github.com/eclipse-keypont/pkcs11-go --template go-licenses.tpl > NOTICES.md
		@echo "NOTICES.md generated"
