# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG GO_IMAGE=golang:1.26.0-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

FROM ${GO_IMAGE} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
ARG AOR_COMPONENT
ARG AOR_VERSION=0.1.0-test
ARG AOR_COMMIT=local
RUN test -n "${AOR_COMPONENT}" && \
    go build -trimpath \
      -ldflags "-s -w -X github.com/akimisaka/aor/internal/version.Version=${AOR_VERSION} -X github.com/akimisaka/aor/internal/version.Commit=${AOR_COMMIT}" \
      -o /out/aor "./cmd/${AOR_COMPONENT}"

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/aor /usr/local/bin/aor
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aor"]
CMD ["serve"]
