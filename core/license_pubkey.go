package core

// LICENSE_PUBLIC_KEY holds the base64-encoded Ed25519 public key used to verify license keys.
// An empty string disables license verification (development / not yet configured).
// Run "make keygen" to regenerate a key pair; that command overwrites this variable.
var LICENSE_PUBLIC_KEY = ""
