# Build variables
BINARY_NAME=whosent
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT?=$(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go build flags
LDFLAGS=-ldflags "-X github.com/kanywst/whosent/internal/version.Version=$(VERSION) \
                  -X github.com/kanywst/whosent/internal/version.GitCommit=$(GIT_COMMIT) \
                  -X github.com/kanywst/whosent/internal/version.BuildDate=$(BUILD_DATE)"

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/whosent

# Build for development (without version info)
.PHONY: build-dev
build-dev:
	go build -o $(BINARY_NAME) ./cmd/whosent

# Install the binary
.PHONY: install
install:
	go install $(LDFLAGS) ./cmd/whosent

# Regenerate the shell completion scripts from the binary. Cobra's output calls
# back into the binary to complete, so it stays correct on its own; run this
# after adding a flag or a subcommand so the packaged copies follow.
.PHONY: completions
completions: build-dev
	@mkdir -p completions
	@for shell in bash zsh fish; do \
		./$(BINARY_NAME) completion $$shell > completions/$(BINARY_NAME).$$shell; \
	done
	@./$(BINARY_NAME) completion powershell > completions/$(BINARY_NAME).ps1
	@echo "regenerated completions/"

# Run tests. There is no fixture step: every chain a test needs is minted at
# run time with throwaway keys, because a committed assertion expires on its own.
.PHONY: test
test:
	go test -v $(GOTEST_ARGS) ./...

# The same, with the race detector. The guard property test is the slow part;
# GOTEST_ARGS=-short trims its matrix.
.PHONY: test-race
test-race:
	go test -race $(GOTEST_ARGS) ./...

# Run tests with JSON output (useful for CI)
.PHONY: test-json
test-json:
	@go test -v -json $(GOTEST_ARGS) ./...

# Run tests with coverage and fail if it slips below the threshold. Without a
# gate the number only ever drifts down, one untested branch at a time.
COVERAGE_THRESHOLD ?= 85.0

# Generated code is not counted: protoc writes it, and its getters and
# reflection plumbing are exercised by the decoder's tests without each one
# being worth a test of its own.
COVERAGE_EXCLUDE ?= /internal/formats/biscuit/pb/

.PHONY: test-coverage
test-coverage:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	@$(MAKE) --no-print-directory check-coverage

# Split out so the gate can be re-run against an existing profile, and so every
# way of not knowing the coverage is an error. A gate that fails open is worse
# than no gate: it reads as protection while providing none.
.PHONY: check-coverage
check-coverage:
	@case '$(COVERAGE_THRESHOLD)' in \
		''|*[!0-9.]*|*.*.*) bad=1 ;; \
		*[0-9]*) bad= ;; \
		*) bad=1 ;; \
	esac; \
	if [ -n "$$bad" ]; then \
		echo "COVERAGE_THRESHOLD must be a number, got '$(COVERAGE_THRESHOLD)'" >&2; exit 1; \
	fi; \
	grep -v '$(COVERAGE_EXCLUDE)' coverage.out > coverage.gate.out || { \
		echo "could not filter coverage.out" >&2; exit 1; }; \
	summary=$$(go tool cover -func=coverage.gate.out) || { \
		echo "go tool cover failed to read coverage.out" >&2; exit 1; }; \
	total=$$(printf '%s\n' "$$summary" | awk '/^total:/ { sub(/%$$/, "", $$3); print $$3 }'); \
	if [ -z "$$total" ]; then \
		echo "no total line in the coverage summary" >&2; exit 1; \
	fi; \
	if awk -v total="$$total" -v min='$(COVERAGE_THRESHOLD)' 'BEGIN { exit !(total + 0 < min + 0) }'; then \
		echo "coverage $$total% is below the $(COVERAGE_THRESHOLD)% threshold" >&2; exit 1; \
	fi; \
	echo "coverage $$total% meets the $(COVERAGE_THRESHOLD)% threshold"

# Fuzz the parts that read untrusted bytes, briefly. CI runs the unit tests,
# which replay the seed corpus; this is for when you touch a parser.
FUZZTIME ?= 30s

.PHONY: fuzz
fuzz:
	go test ./pkg/diagnose -run '^$$' -fuzz '^FuzzGuard$$' -fuzztime $(FUZZTIME)
	go test ./internal/termsafe -run '^$$' -fuzz '^FuzzText$$' -fuzztime $(FUZZTIME)
	go test ./internal/termsafe -run '^$$' -fuzz '^FuzzJSON$$' -fuzztime $(FUZZTIME)
	go test ./internal/formats/jwt -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME)
	go test ./internal/formats/biscuit -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./internal/formats/biscuit/datalog -run '^$$' -fuzz '^FuzzParseProgram$$' -fuzztime $(FUZZTIME)
	go test ./internal/trust -run '^$$' -fuzz '^FuzzParseDocumentAgreesWithTheLibrary$$' -fuzztime $(FUZZTIME)
	go test ./internal/mandatum/mda -run '^$$' -fuzz '^FuzzClaimsValidate$$' -fuzztime $(FUZZTIME)
	go test ./internal/mandatum/jose -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME)
	go test ./internal/mandatum/verify -run '^$$' -fuzz '^FuzzVerify$$' -fuzztime $(FUZZTIME)
	go test ./internal/mandatum/revoke -run '^$$' -fuzz '^FuzzParseSet$$' -fuzztime $(FUZZTIME)
	go test ./internal/formats/macaroon -run '^$$' -fuzz '^FuzzDecode$$' -fuzztime $(FUZZTIME)

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY_NAME) coverage.out coverage.gate.out
	rm -rf dist/
	go clean

# Build for multiple platforms
.PHONY: build-all
build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 ./cmd/whosent
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 ./cmd/whosent
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 ./cmd/whosent
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe ./cmd/whosent

# Create a release
.PHONY: release
release: clean test build-all

# Show version info
.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"

# Take the tour: every demo scenario, minted fresh, n and p to switch.
.PHONY: run
run: build-dev
	./$(BINARY_NAME) demo

.PHONY: demo
demo: run

# Re-record demo.gif (requires vhs). The tape builds the binary itself.
.PHONY: demo-gif
demo-gif:
	vhs demo.tape

# Format code
.PHONY: fmt
fmt:
	go fmt ./...

# Lint code
.PHONY: lint
lint:
	go tool golangci-lint run ./...

# Vulnerability check
.PHONY: vulncheck
vulncheck:
	go tool govulncheck ./...

# Tidy dependencies
.PHONY: tidy
tidy:
	go mod tidy

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary with version info"
	@echo "  build-dev     - Build the binary without version info (faster)"
	@echo "  install       - Install the binary with version info"
	@echo "  test          - Run tests"
	@echo "  test-race     - Run tests with the race detector"
	@echo "  test-coverage - Run tests with coverage, gated at COVERAGE_THRESHOLD"
	@echo "  fuzz          - Fuzz the untrusted-input parsers for FUZZTIME each"
	@echo "  clean         - Clean build artifacts"
	@echo "  build-all     - Build for multiple platforms"
	@echo "  release       - Create a release (clean, test, build-all)"
	@echo "  version       - Show version information"
	@echo "  run           - Build and take the demo tour"
	@echo "  demo          - Same as run"
	@echo "  demo-gif      - Re-record demo.gif with vhs"
	@echo "  completions   - Regenerate the shell completion scripts"
	@echo "  fmt           - Format code"
	@echo "  lint          - Lint code"
	@echo "  vulncheck     - Check dependencies for known vulnerabilities"
	@echo "  tidy          - Tidy dependencies"
	@echo "  help          - Show this help"
