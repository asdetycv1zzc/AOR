# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG GO_IMAGE=golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
ARG DOCKER_CLI_IMAGE=docker:29.6.1-cli@sha256:862099ada15c669000bef53aa4cb9d821262829f45b0dda2159ccb276443043b

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

FROM ${RUNTIME_IMAGE} AS runtime
COPY --from=build /out/aor /usr/local/bin/aor
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aor"]
CMD ["serve"]

FROM ${DOCKER_CLI_IMAGE} AS worker-runtime
COPY --from=build /out/aor /usr/local/bin/aor
ENV HOME=/tmp
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aor"]
CMD ["serve"]

FROM runtime AS final
