storage "file" {
  path = "/vault/file"
}

# The listener and api_addr are supplied via VAULT_LOCAL_CONFIG (see docker-compose.yml) so TLS
# can be switched on for production without touching this file.
plugin_directory = "/vault/plugins"
disable_mlock    = true
ui               = false
