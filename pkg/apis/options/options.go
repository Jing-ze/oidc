package options

import (
	"crypto"
	"net/url"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
)

// SignatureData holds hmacauth signature hash and key
type SignatureData struct {
	Hash crypto.Hash
	Key  string
}

// Options holds Configuration Options that can be set by Command Line Flag,
// or Config File
type Options struct {
	ProxyPrefix         string `mapstructure:"proxy_prefix"`
	ReverseProxy        bool   `mapstructure:"reverse_proxy"`
	RealClientIPHeader  string `mapstructure:"real_client_ip_header"`
	RawRedirectURL      string `mapstructure:"redirect_url"`
	RelativeRedirectURL bool   `mapstructure:"relative_redirect_url"`

	AuthenticatedEmailsFile string   `mapstructure:"authenticated_emails_file"`
	EmailDomains            []string `mapstructure:"email_domains"`
	WhitelistDomains        []string `mapstructure:"whitelist_domains"`

	Cookie  Cookie         `mapstructure:",squash"`
	Session SessionOptions `mapstructure:",squash"`

	Providers Providers

	SSLInsecureSkipVerify bool `mapstructure:"ssl_insecure_skip_verify"`
	SkipAuthPreflight     bool `mapstructure:"skip_auth_preflight"`
	EncodeState           bool `mapstructure:"encode_state"`

	SignatureKey string `mapstructure:"signature_key"`

	// internal values that are set after config validation
	redirectURL        *url.URL // 私有字段通常不需要 mapstructure 标签
	signatureData      *SignatureData
	oidcVerifier       internaloidc.IDTokenVerifier
	jwtBearerVerifiers []internaloidc.IDTokenVerifier
	realClientIPParser ipapi.RealClientIPParser
}

// Options for Getting internal values
func (o *Options) GetRedirectURL() *url.URL                      { return o.redirectURL }
func (o *Options) GetSignatureData() *SignatureData              { return o.signatureData }
func (o *Options) GetOIDCVerifier() internaloidc.IDTokenVerifier { return o.oidcVerifier }
func (o *Options) GetJWTBearerVerifiers() []internaloidc.IDTokenVerifier {
	return o.jwtBearerVerifiers
}
func (o *Options) GetRealClientIPParser() ipapi.RealClientIPParser { return o.realClientIPParser }

// Options for Setting internal values
func (o *Options) SetRedirectURL(s *url.URL)                              { o.redirectURL = s }
func (o *Options) SetSignatureData(s *SignatureData)                      { o.signatureData = s }
func (o *Options) SetOIDCVerifier(s internaloidc.IDTokenVerifier)         { o.oidcVerifier = s }
func (o *Options) SetJWTBearerVerifiers(s []internaloidc.IDTokenVerifier) { o.jwtBearerVerifiers = s }
func (o *Options) SetRealClientIPParser(s ipapi.RealClientIPParser)       { o.realClientIPParser = s }

// NewOptions constructs a new Options with defaulted values
func NewOptions() *Options {
	return &Options{
		ProxyPrefix:        "/oauth2",
		Providers:          providerDefaults(),
		RealClientIPHeader: "X-Real-IP",
		Cookie:             cookieDefaults(),
		Session:            sessionOptionsDefaults(),
		SkipAuthPreflight:  false,
	}
}
