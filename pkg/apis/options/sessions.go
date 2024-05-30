package options

// SessionOptions contains configuration options for the SessionStore providers.
type SessionOptions struct {
	Type   string             `flag:"session-store-type" cfg:"session_store_type"`
	Cookie CookieStoreOptions `cfg:",squash"`
}

// CookieSessionStoreType is used to indicate the CookieSessionStore should be
// used for storing sessions.
var CookieSessionStoreType = "cookie"

// CookieStoreOptions contains configuration options for the CookieSessionStore.
type CookieStoreOptions struct {
	Minimal bool `flag:"session-cookie-minimal" cfg:"session_cookie_minimal"`
}

func sessionOptionsDefaults() SessionOptions {
	return SessionOptions{
		Type: CookieSessionStoreType,
		Cookie: CookieStoreOptions{
			Minimal: false,
		},
	}
}
