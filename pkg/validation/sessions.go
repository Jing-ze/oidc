package validation

import (
	"fmt"
	"time"

	"oidc/pkg/apis/options"
)

func validateSessionCookieMinimal(o *options.Options) []string {
	if !o.Session.Cookie.Minimal {
		return []string{}
	}

	msgs := []string{}
	for _, header := range append(o.InjectRequestHeaders, o.InjectResponseHeaders...) {
		for _, value := range header.Values {
			if value.ClaimSource != nil {
				if value.ClaimSource.Claim == "access_token" {
					msgs = append(msgs,
						fmt.Sprintf("access_token claim for header %q requires oauth tokens in sessions. session_cookie_minimal cannot be set", header.Name))
				}
				if value.ClaimSource.Claim == "id_token" {
					msgs = append(msgs,
						fmt.Sprintf("id_token claim for header %q requires oauth tokens in sessions. session_cookie_minimal cannot be set", header.Name))
				}
			}
		}
	}

	if o.Cookie.Refresh != time.Duration(0) {
		msgs = append(msgs,
			"cookie_refresh > 0 requires oauth tokens in sessions. session_cookie_minimal cannot be set")
	}
	return msgs
}
