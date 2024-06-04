package validation

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"oidc/pkg/apis/options"
)

// Validate checks that required options are set and validates those that they
// are of the correct format
func Validate(o *options.Options) error {
	msgs := validateCookie(o.Cookie)
	msgs = append(msgs, validateProviders(o)...)

	if o.SSLInsecureSkipVerify {
		insecureTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- InsecureSkipVerify is a configurable option we allow
		}
		http.DefaultClient = &http.Client{Transport: insecureTransport}
	} else if len(o.Providers[0].CAFiles) > 0 {
		pool, err := util.GetCertPool(o.Providers[0].CAFiles, o.Providers[0].UseSystemTrustStore)
		if err == nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.TLSClientConfig = &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			}

			http.DefaultClient = &http.Client{Transport: transport}
		} else {
			msgs = append(msgs, fmt.Sprintf("unable to load provider CA file(s): %v", err))
		}
	}

	if o.AuthenticatedEmailsFile == "" && len(o.EmailDomains) == 0 {
		msgs = append(msgs, "missing setting for email validation: email-domain or authenticated-emails-file required."+
			"\n      use email-domain=* to authorize all email addresses")
	}

	var redirectURL *url.URL
	redirectURL, msgs = parseURL(o.RawRedirectURL, "redirect", msgs)
	o.SetRedirectURL(redirectURL)
	if o.RawRedirectURL == "" && !o.Cookie.Secure && !o.ReverseProxy {
		logger.Print("WARNING: no explicit redirect URL: redirects will default to insecure HTTP")
	}

	if len(msgs) != 0 {
		return fmt.Errorf("invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseURL(toParse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(toParse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, toParse, err))
	}
	return parsed, msgs
}
