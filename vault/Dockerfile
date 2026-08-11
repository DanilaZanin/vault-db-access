FROM golang:1.24-bookworm AS plugin-builder

RUN git clone --depth 1 https://github.com/ContentSquare/vault-plugin-database-clickhouse.git /src
WORKDIR /src
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/clickhouse-database-plugin ./cmd/vault-plugin-database-clickhouse

FROM hashicorp/vault:2.0.4

# 2.0.4's base image runs as the non-root `vault` user by default (1.19.0 didn't),
# so root is needed here to place and chmod the plugin binary; the entrypoint still
# handles runtime ownership/privilege-drop itself, same as before.
USER root
RUN mkdir -p /vault/plugins
COPY --from=plugin-builder --chown=vault:vault /out/clickhouse-database-plugin /vault/plugins/clickhouse-database-plugin
RUN chmod +x /vault/plugins/clickhouse-database-plugin
USER vault
