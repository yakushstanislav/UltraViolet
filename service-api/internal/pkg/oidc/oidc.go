// Package oidc provides optional OpenID Connect login via Authorization Code
// flow. When disabled, the API only accepts username/password login.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config carries OIDC settings loaded from environment variables.
type Config struct {
	Enabled      bool   `env:"OIDC_ENABLED"       env-default:"false"`
	IssuerURL    string `env:"OIDC_ISSUER_URL"`
	ClientID     string `env:"OIDC_CLIENT_ID"`
	ClientSecret string `env:"OIDC_CLIENT_SECRET"`
	RedirectURL  string `env:"OIDC_REDIRECT_URL"`
	Scope        string `env:"OIDC_SCOPE"          env-default:"openid email profile"`
}

// Provider performs the basic discovery + token-exchange steps required for
// OIDC login. It does not validate ID tokens cryptographically; deployments
// that require strict signature checking should plug in a JWT verifier in
// the auth service.
type Provider struct {
	cfg        Config
	httpClient *http.Client
	endpoints  discovery
}

type discovery struct {
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

// New builds a Provider; when Enabled is false the returned provider is a
// no-op and Provider methods return ErrDisabled.
func New(cfg Config) *Provider {
	return &Provider{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// ErrDisabled signals that OIDC has not been configured in this deployment.
var ErrDisabled = errors.New("OIDC is not enabled")

// Configure performs discovery against the configured issuer URL. The result
// is cached in the Provider until process restart.
func (p *Provider) Configure(ctx context.Context) error {
	if !p.cfg.Enabled {
		return ErrDisabled
	}

	if p.cfg.IssuerURL == "" {
		return errors.New("OIDC_ISSUER_URL must be set when OIDC is enabled")
	}

	well := strings.TrimRight(p.cfg.IssuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, well, nil)
	if err != nil {
		return fmt.Errorf("can't build oidc discovery request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("can't fetch oidc discovery: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc discovery returned %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&p.endpoints); err != nil {
		return fmt.Errorf("can't decode oidc discovery: %w", err)
	}

	return nil
}

// AuthorizationURL returns the URL the browser should be redirected to in
// order to start the Authorization Code flow.
//
// codeChallenge, when non-empty, is added as the S256 PKCE code_challenge.
// PKCE protects against authorization-code interception even on confidential
// clients; the caller stores the matching codeVerifier alongside the state
// and replays it via Exchange.
func (p *Provider) AuthorizationURL(state, codeChallenge string) (string, error) {
	if !p.cfg.Enabled {
		return "", ErrDisabled
	}

	if p.endpoints.AuthURL == "" {
		return "", errors.New("call Configure before AuthorizationURL")
	}

	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", p.cfg.ClientID)
	values.Set("redirect_uri", p.cfg.RedirectURL)
	values.Set("scope", p.cfg.Scope)
	values.Set("state", state)

	if codeChallenge != "" {
		values.Set("code_challenge", codeChallenge)
		values.Set("code_challenge_method", "S256")
	}

	return p.endpoints.AuthURL + "?" + values.Encode(), nil
}

// Exchange swaps an authorization code for an access token and returns the
// caller's email/role hint from the UserInfo endpoint. codeVerifier, when
// non-empty, is sent as the PKCE proof matching the code_challenge the
// caller passed to AuthorizationURL.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier string) (map[string]any, error) {
	if !p.cfg.Enabled {
		return nil, ErrDisabled
	}

	if p.endpoints.TokenURL == "" {
		return nil, errors.New("call Configure before Exchange")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURL)
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)

	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoints.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("can't build oidc token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't exchange oidc code: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc token endpoint returned %d", resp.StatusCode)
	}

	var token struct {
		AccessToken string `json:"access_token"`
	}

	if decodeErr := json.NewDecoder(resp.Body).Decode(&token); decodeErr != nil {
		return nil, fmt.Errorf("can't decode oidc token response: %w", decodeErr)
	}

	if token.AccessToken == "" {
		return nil, errors.New("oidc token response missing access_token")
	}

	userInfoReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoints.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("can't build oidc userinfo request: %w", err)
	}

	userInfoReq.Header.Set("Authorization", "Bearer "+token.AccessToken)

	userInfoResp, err := p.httpClient.Do(userInfoReq)
	if err != nil {
		return nil, fmt.Errorf("can't fetch oidc userinfo: %w", err)
	}

	defer func() { _ = userInfoResp.Body.Close() }()

	if userInfoResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc userinfo returned %d", userInfoResp.StatusCode)
	}

	var userInfo map[string]any
	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("can't decode oidc userinfo: %w", err)
	}

	return userInfo, nil
}

// RandomState returns a 32-byte URL-safe random string suitable for the
// OIDC state parameter.
func RandomState() (string, error) {
	buf := make([]byte, 32)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("can't read random bytes for state: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// RandomCodeVerifier returns a 32-byte URL-safe random string suitable for
// the PKCE code_verifier (RFC 7636 §4.1: 43-128 unreserved chars).
func RandomCodeVerifier() (string, error) {
	buf := make([]byte, 32)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("can't read random bytes for code verifier: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// CodeChallengeFromVerifier returns base64url(SHA-256(verifier)) — the
// "S256" variant of the PKCE code_challenge.
func CodeChallengeFromVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
