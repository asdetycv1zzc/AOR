# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG GO_IMAGE=golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
ARG ALPINE_IMAGE=alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

FROM ${GO_IMAGE} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download all
COPY cmd ./cmd
COPY internal ./internal
COPY model-adapters ./model-adapters
COPY pkg ./pkg
COPY prompts ./prompts
ARG AOR_COMPONENT
ARG AOR_VERSION=0.1.0-test
ARG AOR_COMMIT=local
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    test -n "${AOR_COMPONENT}" && \
    go build -trimpath \
      -ldflags "-s -w -X github.com/akimisaka/aor/internal/version.Version=${AOR_VERSION} -X github.com/akimisaka/aor/internal/version.Commit=${AOR_COMMIT}" \
      -o /out/aor "./cmd/${AOR_COMPONENT}"
RUN mkdir -p /out/runtime/knowledge/global/policies \
    /out/runtime/knowledge/global/prompts \
    /out/runtime/knowledge/global/protocols \
    /out/runtime/knowledge/global/standards \
    /out/runtime/knowledge/global/workflows
COPY knowledge/global /out/runtime/knowledge/global

FROM ${RUNTIME_IMAGE} AS runtime
COPY --from=build /out/aor /usr/local/bin/aor
COPY --from=build --chown=65532:65532 /out/runtime/knowledge /var/lib/aor/knowledge
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/aor"]
CMD ["serve"]

FROM ${GO_IMAGE} AS worker-runtime
COPY --from=build /out/aor /usr/local/bin/aor
RUN apk add --no-cache git=2.52.0-r0 && \
    mkdir -p /var/lib/aor/knowledge \
      /var/lib/aor/work && \
    chown -R 65532:65532 /var/lib/aor
ENV HOME=/var/lib/aor/work
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/aor"]
CMD ["serve"]

FROM ${ALPINE_IMAGE} AS tool-broker-runtime
COPY --from=build /out/aor /usr/local/bin/aor
RUN apk add --no-cache git=2.52.0-r0 && \
    mkdir -p /var/lib/aor/repositories && \
    chown -R 65532:65532 /var/lib/aor && \
    chmod 1777 /var/lib/aor/repositories
ENV HOME=/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/aor"]
CMD ["serve"]

FROM runtime AS final
