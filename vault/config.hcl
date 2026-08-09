storage "file" {
  path = "/vault/file"
}

# The listener and api_addr are intentionally NOT here -- they're supplied via the
# VAULT_LOCAL_CONFIG env var (see docker-compose.yml) so TLS can be turned on for
# production without touching this file. See README.md "Production deployment".
plugin_directory = "/vault/plugins"
disable_mlock    = true
ui               = true
