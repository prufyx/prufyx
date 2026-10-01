# syntax=docker/dockerfile:1
#
# Image for the unattended maintenance workers ("factory"). Build context is
# the cli/ directory:
#
#   docker build -f factory/Dockerfile -t prufyx-factory cli
#
# The mirror worker shells out to git (partial clones), so a static-only
# distroless image is not enough; the final stage is distroless "base"
# (glibc, OpenSSL, CA certificates; no shell, no package manager) with just
# the git binaries and their shared libraries copied in. It runs as the
# non-root user (uid/gid 65532) and holds no signing keys.

FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -buildvcs=false -trimpath -ldflags="-s -w" \
      -o /out/prufyx-maintainer ./cmd/prufyx-maintainer

FROM debian:trixie-slim AS git
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /out \
 && for bin in /usr/bin/git /usr/lib/git-core/git-remote-http /usr/lib/git-core/git-remote-https; do \
      cp --parents -L "$bin" /out; \
      ldd "$bin" | awk '/=> \//{print $3} /^[[:space:]]*\//{print $1}'; \
    done | sed 's#^/lib#/usr/lib#' | sort -u | xargs -r -I{} cp --parents -L {} /out \
 && cp --parents -L /usr/share/git-core/templates/description /out 2>/dev/null || true

FROM gcr.io/distroless/base-debian13:nonroot
COPY --from=git /out/ /
COPY --from=build /out/prufyx-maintainer /usr/local/bin/prufyx-maintainer
COPY factory/registry.yaml /etc/prufyx/registry.yaml
ENV GIT_EXEC_PATH=/usr/lib/git-core \
    HOME=/tmp
VOLUME ["/state"]
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/prufyx-maintainer", "factory"]
CMD ["mirror", "--state", "/state", "--registry", "/etc/prufyx/registry.yaml"]
