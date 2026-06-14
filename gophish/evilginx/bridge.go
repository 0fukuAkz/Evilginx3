package evilginx

// SessionData contains phishing session information passed from the evilginx
// proxy layer into GoPhish campaign tracking.
type SessionData struct {
	RID        string
	Username   string
	Password   string
	Tokens     map[string]string
	RemoteAddr string
}

// SessionBridge is the formal interface between the GoPhish email campaign
// system and the evilginx proxy layer. All coupling between the two systems
// must flow through this interface so that upstream GoPhish patches only
// require updating the bridge implementation rather than auditing 88+ files.
//
// To update from upstream GoPhish:
//  1. Cherry-pick or merge changes into /gophish/ (excluding /gophish/evilginx/)
//  2. Re-implement any changed method signatures here
//  3. Update the concrete bridge in core/ that satisfies this interface
type SessionBridge interface {
	// GetSessionByRID returns the active phishing session for the given
	// result ID, or an error if no session is found.
	GetSessionByRID(rid string) (*SessionData, error)

	// UpdateSessionStatus sets the status of the session identified by rid.
	// status values mirror GoPhish EventData constants (e.g. "Email Opened").
	UpdateSessionStatus(rid string, status string) error

	// RecordCredentials stores captured credentials against the session.
	RecordCredentials(rid string, username string, password string) error
}
