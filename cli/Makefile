GO ?= go
MAINTAINER ?= go run ./cmd/prufyx-maintainer
RELEASE_POLICY := release/community-shipping-policy-v2.json
STATICCHECK ?= staticcheck

.PHONY: mutants toolchain-check staticcheck staticcheck-full dco-check release-gate-test release-manifest regenerate-pack-goldens

toolchain-check:
	@version="$$(GOTOOLCHAIN=local $(GO) env GOVERSION)"; test "$$version" = go1.26.8 || { echo "Go 1.26.8 is required; found $$version" >&2; exit 1; }

staticcheck: toolchain-check
	@go_root="$$(GOTOOLCHAIN=local $(GO) env GOROOT)"; status=0; \
	PATH="$$go_root/bin:$$PATH" GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' $(STATICCHECK) -checks=SA* ./... || status=1; \
	PATH="$$go_root/bin:$$PATH" GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' $(STATICCHECK) -checks=SA* -tags parityreview ./... || status=1; \
	exit "$$status"

staticcheck-full: toolchain-check
	@go_root="$$(GOTOOLCHAIN=local $(GO) env GOROOT)"; status=0; \
	PATH="$$go_root/bin:$$PATH" GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' $(STATICCHECK) ./... || status=1; \
	PATH="$$go_root/bin:$$PATH" GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS='-mod=vendor -buildvcs=false' $(STATICCHECK) -tags parityreview ./... || status=1; \
	exit "$$status"

dco-check:
	@test -n "$(REVISION_RANGE)" || { echo "REVISION_RANGE=<base>..<head> is required" >&2; exit 2; }
	@./scripts/check-dco-range.sh "$(REVISION_RANGE)"

release-gate-test:
	$(GO) test ./internal/maintainer/...

# Regenerate the test artefacts that follow the embedded CNCF rule pack, then run
# the tests that read it (see the script's header).
regenerate-pack-goldens:
	./scripts/regenerate-pack-goldens.sh

release-manifest:
	@test -n "$(OUTPUT)" || { echo "OUTPUT=/absolute/path/SOURCE-MANIFEST.json is required" >&2; exit 2; }
	$(MAINTAINER) release-gate generate --source-root .. --policy $(RELEASE_POLICY) --go $(GO) --output "$(OUTPUT)"

# Source mutation checks (see CONTRIBUTING.md). Slow; not part of default CI.
# One mutant at a time, go test -p 2, GOMAXPROCS=4. MUTANT_ARGS="-only ID,ID" selects some.
mutants:
	GOMAXPROCS=4 GOFLAGS=-mod=vendor nice -n 10 $(GO) run ./internal/tools/mutants -data testdata/mutants.json $(MUTANT_ARGS)
