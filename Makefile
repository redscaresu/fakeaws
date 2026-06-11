.PHONY: build test test-race test-short test-coverage vet clean run install-hooks demo-help demo-up demo-down demo-env demo-shell demo-apply demo-destroy demo-clean

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

# ─── demo targets ───────────────────────────────────────────────────────
# Drive a real aws provider through init → apply → plan-no-op → destroy
# against a local fakeaws. Useful for blog demos, manual exploration, and
# proving the wire-shape contract end-to-end.
#
#   make demo-apply                       # one-shot: up + apply + plan-no-op (default: sqs_queue)
#   make demo-apply EXAMPLE=iam_role      # pick a different example
#   make demo-shell                       # bash subshell with env set + cd'd to example
#   make demo-down                        # kill fakeaws + remove temp files
#
# Override the example with EXAMPLE=<dir> (any subdir of examples/working/).
# Each example's main.tf hardcodes 127.0.0.1:8082 as the endpoint, so
# DEMO_PORT is effectively pinned at 8082.
DEMO_PORT      ?= 8082
EXAMPLE        ?= sqs_queue
DEMO_EXAMPLE_DIR := examples/working/$(EXAMPLE)
DEMO_ENV_FILE  := /tmp/fakeaws.env
DEMO_BASE      := http://localhost:$(DEMO_PORT)
DEMO_BIN       := $(shell command -v tofu 2>/dev/null || command -v terraform 2>/dev/null)

demo-help:
	@echo "Demo targets (drive real terraform/tofu against this fakeaws):"
	@echo "  demo-up                        boot fakeaws + write env to /tmp"
	@echo "  demo-apply [EXAMPLE=<dir>]     one-shot: init + apply + plan-no-op"
	@echo "  demo-shell [EXAMPLE=<dir>]     bash subshell with env set + cd'd to example"
	@echo "  demo-destroy [EXAMPLE=<dir>]   tofu destroy on the current example"
	@echo "  demo-down                      kill fakeaws + remove temp files"
	@echo "  demo-clean                     demo-destroy + nuke .terraform/ + state files"
	@echo ""
	@echo "Available examples:"
	@ls examples/working/ | sed 's/^/  /'

demo-up:
	@if pgrep -f "fakeaws --port $(DEMO_PORT)" >/dev/null 2>&1; then \
	  echo "✓ fakeaws already running on :$(DEMO_PORT)"; \
	else \
	  [ -x ./fakeaws ] || { echo "ERROR: ./fakeaws binary not found. Run 'make build' first." >&2; exit 1; }; \
	  ./fakeaws --port $(DEMO_PORT) --db ':memory:' >/tmp/fakeaws.log 2>&1 & \
	  for i in 1 2 3 4 5 6 7 8 9 10; do sleep 0.5; curl -sf $(DEMO_BASE)/healthz >/dev/null 2>&1 && break; done; \
	  echo "✓ fakeaws booted on :$(DEMO_PORT)  (logs: /tmp/fakeaws.log)"; \
	fi
	@{ \
	  echo '# fakeaws examples hardcode region + fake creds + endpoints in the'; \
	  echo '# provider block, so no env vars are strictly required. These mirror'; \
	  echo '# what the smoke harness sets and are safe to source.'; \
	  echo 'export AWS_REGION=us-east-1'; \
	  echo 'export AWS_DEFAULT_REGION=us-east-1'; \
	  echo 'export AWS_ACCESS_KEY_ID=fake'; \
	  echo 'export AWS_SECRET_ACCESS_KEY=fake'; \
	  echo 'export FAKEAWS_URL=$(DEMO_BASE)'; \
	} > $(DEMO_ENV_FILE)
	@echo "✓ env written to $(DEMO_ENV_FILE)"

demo-down:
	@pkill -f "fakeaws --port $(DEMO_PORT)" 2>/dev/null && echo "✓ killed" || echo "✓ nothing to kill"
	@rm -f $(DEMO_ENV_FILE)

demo-env: demo-up
	@cat $(DEMO_ENV_FILE)

demo-shell: demo-up
	@[ -d "$(DEMO_EXAMPLE_DIR)" ] || { echo "ERROR: $(DEMO_EXAMPLE_DIR) not found" >&2; exit 1; }
	@echo "→ entering subshell with fakeaws env. Type 'exit' to leave."
	@cd $(DEMO_EXAMPLE_DIR) && /bin/bash --rcfile <(echo "source ~/.bashrc 2>/dev/null; source $(DEMO_ENV_FILE); PS1='[fakeaws $(EXAMPLE)] $$PS1'")

demo-apply: demo-up
	@[ -n "$(DEMO_BIN)" ] || { echo "ERROR: neither tofu nor terraform on PATH" >&2; exit 1; }
	@[ -d "$(DEMO_EXAMPLE_DIR)" ] || { echo "ERROR: $(DEMO_EXAMPLE_DIR) not found" >&2; exit 1; }
	@set -e; . $(DEMO_ENV_FILE); cd $(DEMO_EXAMPLE_DIR); \
	  echo "=== $(DEMO_BIN) init ==="; $(DEMO_BIN) init -input=false; \
	  echo ""; echo "=== $(DEMO_BIN) apply ==="; $(DEMO_BIN) apply -auto-approve -input=false; \
	  echo ""; echo "=== $(DEMO_BIN) plan -detailed-exitcode (brutal correctness check) ==="; \
	  if $(DEMO_BIN) plan -detailed-exitcode -input=false >/dev/null 2>&1; then \
	    echo "✓ exit 0 — wire shape correct (real provider's state matches fakeaws's responses)."; \
	  else \
	    echo "✗ exit $$? — drift detected."; exit 1; \
	  fi

demo-destroy:
	@[ -n "$(DEMO_BIN)" ] || { echo "ERROR: neither tofu nor terraform on PATH" >&2; exit 1; }
	@[ -f $(DEMO_ENV_FILE) ] || { echo "ERROR: no env file — run 'make demo-up' first" >&2; exit 1; }
	@set -e; . $(DEMO_ENV_FILE); cd $(DEMO_EXAMPLE_DIR); $(DEMO_BIN) destroy -auto-approve -input=false

demo-clean:
	@-$(MAKE) demo-destroy 2>/dev/null
	@find examples/working -name '.terraform' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@find examples/working -name '.terraform.lock.hcl' -delete 2>/dev/null || true
	@find examples/working -name 'terraform.tfstate*' -delete 2>/dev/null || true
	@echo "✓ terraform state cleaned"
