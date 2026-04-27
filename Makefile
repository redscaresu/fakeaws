.PHONY: build test test-race test-short test-coverage vet clean run install-hooks

# install-hooks wires the tracked hook installer at .githooks/ via
# core.hooksPath. Idempotent — re-running is a no-op. Run once after
# cloning. README quickstart calls this out as the second step after
# `go mod download`.
install-hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-commit
	@echo "Hooks installed: pre-commit will run gitleaks then go test."

build:
	go build -o fakeaws ./cmd/fakeaws

test:
	go test -count=1 ./...

test-race:
	go test -count=1 -race ./...

test-short:
	go test -count=1 -short ./...

# Aggregate handlers/... coverage (per concepts.md § "Coverage targets and CI").
# Two-step: collect profile, then summarise. The 'total:' line is what CI parses.
test-coverage:
	go test -count=1 -coverprofile=cov.out -covermode=atomic ./handlers/...
	@go tool cover -func=cov.out | tail -1
	@go tool cover -html=cov.out -o coverage.html
	@echo "coverage report: coverage.html"

vet:
	go vet ./...

clean:
	rm -f fakeaws cov.out coverage.html

run: build
	./fakeaws --port 8082
