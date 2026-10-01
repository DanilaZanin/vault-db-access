# Build natively on the builder's CPU and cross-compile (GOARCH), so multi-arch builds do not need QEMU for Go.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS plugin-builder
ARG TARGETARCH

# Third-party ClickHouse database plugin, pinned to an exact commit (no moving "main").
ARG CH_PLUGIN_COMMIT=9ca33fa4c4da280c6afeed823c712be247a830f5
WORKDIR /src
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN git init . \
    && git remote add origin https://github.com/ContentSquare/vault-plugin-database-clickhouse.git \
    && git fetch --depth 1 origin ${CH_PLUGIN_COMMIT} \
    && git checkout -q FETCH_HEAD
# The plugin's own go.mod pins several vulnerable transitive deps (GCP/cloudsqlconn,
# docker, grpc, x/*). Bump them to current fixed releases and rebuild.
RUN go get \
      google.golang.org/grpc@v1.84.0 \
      golang.org/x/net@v0.59.0 \
      golang.org/x/crypto@v0.57.0 \
      golang.org/x/text@v0.42.0 \
      github.com/docker/docker@v28.5.2+incompatible \
    && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -o /out/clickhouse-database-plugin ./cmd/vault-plugin-database-clickhouse \
    && sha256sum /out/clickhouse-database-plugin | cut -d' ' -f1 > /out/clickhouse-database-plugin.sha256

FROM hashicorp/vault:2.1.1@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2

USER root
RUN apk upgrade --no-cache \
    && mkdir -p /vault/plugins /vault/logs && chown vault:vault /vault/plugins /vault/logs
# Plugin is baked into the image (no shared volume that could shadow it). The sha256 file is
# read by the setup container (via a compose additional_context) to register the plugin.
COPY --from=plugin-builder --chown=root:root --chmod=0755 /out/clickhouse-database-plugin /vault/plugins/clickhouse-database-plugin
COPY --from=plugin-builder --chmod=0644 /out/clickhouse-database-plugin.sha256 /vault/plugins/clickhouse-database-plugin.sha256
USER vault
