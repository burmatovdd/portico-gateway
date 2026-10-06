# Override both bases with internal mirrors in disconnected environments.
ARG GO_IMAGE=golang:1.26.4-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/portico ./cmd/portico
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/portico-models ./cmd/portico-models
FROM ${RUNTIME_IMAGE}
COPY --from=build /out/ /usr/local/bin/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/portico"]
