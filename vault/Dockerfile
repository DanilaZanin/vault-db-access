FROM golang:1.26-bookworm AS plugin-builder

# Third-party ClickHouse database plugin, pinned to an exact commit (no moving "main").
ARG CH_PLUGIN_COMMIT=9ca33fa4c4da280c6afeed823c712be247a830f5
RUN git init /src && cd /src \
    && git remote add origin https://github.com/ContentSquare/vault-plugin-database-clickhouse.git \
    && git fetch --depth 1 origin ${CH_PLUGIN_COMMIT} \
    && git checkout -q FETCH_HEAD
WORKDIR /src
# The plugin's own go.mod pins several vulnerable transitive deps (GCP/cloudsqlconn,
# docker, grpc, x/*). Bump them to current fixed releases and rebuild.
RUN go get \
      google.golang.org/grpc@v1.84.0 \
      golang.org/x/net@v0.59.0 \
      golang.org/x/crypto@v0.57.0 \
      golang.org/x/text@v0.42.0 \
      github.com/docker/docker@v28.5.2+incompatible \
    && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/clickhouse-database-plugin ./cmd/vault-plugin-database-clickhouse \
    && sha256sum /out/clickhouse-database-plugin | cut -d' ' -f1 > /out/clickhouse-database-plugin.sha256

FROM hashicorp/vault:2.1.1

USER root
RUN mkdir -p /vault/plugins /vault/logs && chown vault:vault /vault/plugins /vault/logs
# Plugin is baked into the image (no shared volume that could shadow it). The sha256 file is
# read by the setup container (via a compose additional_context) to register the plugin.
COPY --from=plugin-builder --chown=root:root --chmod=0755 /out/clickhouse-database-plugin /vault/plugins/clickhouse-database-plugin
COPY --from=plugin-builder --chmod=0644 /out/clickhouse-database-plugin.sha256 /vault/plugins/clickhouse-database-plugin.sha256
USER vault
