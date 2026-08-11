FROM golang:1.26-bookworm AS plugin-builder

RUN git clone --depth 1 https://github.com/ContentSquare/vault-plugin-database-clickhouse.git /src
WORKDIR /src
# The plugin's own go.mod pins several vulnerable transitive deps (pulled in via the
# GCP/cloudsqlconn chain): grpc v1.70.0 had CVE-2026-33186 (CRITICAL, HTTP/2 path
# validation authz bypass); v1.79.3 itself still had GHSA-hrxh-6v49-42gf (xDS RBAC/HTTP2),
# fixed in 1.82.1, so that's the version actually built here, not the 1.79.3 originally
# requested. x/net, x/crypto, x/text carried their own HIGH findings (CVE-2026-25681,
# -33814, -39821 in x/net; -39831/-39832/-39835/-42508/-46595/-46597 in x/crypto/ssh;
# -56852 in x/text) -- bumped all of them to their fixed releases in the same pass
# (x/crypto landed on 0.51.0, not the minimum-fixed 0.46.0, because x/net@0.55.0 itself
# requires >=0.51.0).
# Confirmed clean (0 findings) with `trivy image --severity HIGH,CRITICAL` after this.
# Only pin the packages with a direct fix requirement; x/net@0.55.0 pulls in its own
# minimum-compatible x/crypto and x/sys transitively (both already >= the fixed
# thresholds for CVE-2026-39824 etc, so no separate pin needed -- go get rejected
# pinning them lower than what x/net demands).
RUN go get \
      google.golang.org/grpc@v1.82.1 \
      golang.org/x/net@v0.55.0 \
      golang.org/x/crypto@v0.52.0 \
      golang.org/x/text@v0.39.0 \
      github.com/docker/docker@v28.5.2+incompatible \
    && go mod tidy
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
