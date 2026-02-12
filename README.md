# WebDAV Server

Lightweight WebDAV server with LDAP authentication.

## Docker

### Pre-built image (recommended)

Images are published to GitHub Container Registry on each push to `main` and on version tags:

```bash
docker pull ghcr.io/zapthedingbat/webdav-server:main
# Or a specific version:
docker pull ghcr.io/zapthedingbat/webdav-server:v1.0.0
```

### Build locally

```bash
docker build -t webdav-server .
```

## Configuration

- **Config path**: `/config/config.yaml` (or set `CONFIG_PATH` env var)
- **Index page path**: `/config/index.html` (set `INDEX_HTML_PATH`). If the file is missing, root/collection index requests return HTTP `405` with an empty body.
- **LDAP**: Override via env vars `LDAP_URL`, `LDAP_BASE_DN`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`, etc.
- See `config.default.yaml` for the schema and example ACLs.

## Environment variables

| Variable | Description |
|----------|-------------|
| `CONFIG_PATH` | Path to config file (default: `/config/config.yaml`) |
| `INDEX_HTML_PATH` | Path to index HTML (default: `/config/index.html`); if missing, index requests return empty `405` |
| `LDAP_URL` | LDAP server URL (e.g. `ldap://authentik-ldap:3389`) |
| `LDAP_BASE_DN` | Base DN for user search |
| `LDAP_BIND_DN` | Bind DN for LDAP auth |
| `LDAP_BIND_PASSWORD` | Bind password |
| `LDAP_USER_FILTER` | User search filter (default: `(objectClass=person)`) |
| `LDAP_USERNAME_ATTRIBUTE` | Username attribute (e.g. `mail` for Authentik) |
| `LDAP_GROUP_ATTRIBUTE` | Group membership attribute (default: `memberOf`) |

## License

MIT
