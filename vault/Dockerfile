FROM golang:1.24-bookworm AS plugin-builder

RUN git clone --depth 1 https://github.com/ContentSquare/vault-plugin-database-clickhouse.git /src
WORKDIR /src
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/clickhouse-database-plugin ./cmd/vault-plugin-database-clickhouse

FROM hashicorp/vault:1.19.0

RUN mkdir -p /vault/plugins
COPY --from=plugin-builder /out/clickhouse-database-plugin /vault/plugins/clickhouse-database-plugin
RUN chmod +x /vault/plugins/clickhouse-database-plugin
