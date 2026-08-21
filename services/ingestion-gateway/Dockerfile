FROM golang:1.23.10-bookworm AS build
WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY contracts/common /contracts/common
COPY services/ingestion-gateway /src

WORKDIR /src
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/ingestion-gateway ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=busybox:1.36.1-uclibc /bin/wget /wget
COPY --from=build /out/ingestion-gateway /ingestion-gateway
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/ingestion-gateway"]
