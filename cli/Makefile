GO ?= go
MAINTAINER ?= go run ./cmd/prufyx-maintainer
RELEASE_POLICY := release/community-shipping-policy-v2.json
STATICCHECK ?= staticcheck

.PHONY: toolchain-check staticcheck staticcheck-full dco-check release-gate-test release-manifest

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

release-manifest:
	@test -n "$(OUTPUT)" || { echo "OUTPUT=/absolute/path/SOURCE-MANIFEST.json is required" >&2; exit 2; }
	$(MAINTAINER) release-gate generate --source-root .. --policy $(RELEASE_POLICY) --go $(GO) --output "$(OUTPUT)"
