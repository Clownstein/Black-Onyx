FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build
WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY contracts/common /contracts/common
COPY services/ingestion-gateway /src

WORKDIR /src
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/ingestion-gateway ./cmd/server

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=busybox:1.36.1-uclibc /bin/wget /wget
COPY --from=build /out/ingestion-gateway /ingestion-gateway
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/ingestion-gateway"]
