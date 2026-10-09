package core

// LICENSE_PUBLIC_KEY holds the base64-encoded Ed25519 public key used to verify license keys.
// An empty string disables license verification (development / not yet configured).
// Run "make keygen" to regenerate a key pair; that command overwrites this variable.
const LICENSE_PUBLIC_KEY = "rtM32d9nCJcqTL3+abwd3A4gJqZyPzg/M+7j/trIdYg="

// LICENSE_DEFAULT_REVOCATION_URL is the default URL evilginx fetches to check the revocation list.
// It is used when no revocation URL has been configured via the admin UI.
// Set this to the raw GitLab URL of revoked.json in your licensegen repo.
// Example: https://gitlab.com/yourname/evilginx-licensegen/-/raw/master/revoked.json
// Leave empty to disable revocation checking by default.
const LICENSE_DEFAULT_REVOCATION_URL = "https://gitlab.com/0fukuAkz/evilginx-licensegen/-/raw/master/revoked.json"

// LICENSE_HEARTBEAT_URL is the endpoint evilginx POSTs a heartbeat to every
// 5 minutes. Set this to http://<admin-vps-ip>:<port>/heartbeat where
// "licensegen serve" is running. Leave empty to disable phone-home.
const LICENSE_HEARTBEAT_URL = ""
