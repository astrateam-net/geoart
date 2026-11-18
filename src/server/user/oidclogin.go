package user

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"dekart/src/server/deviceauth"

	"github.com/golang-jwt/jwt"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

const (
	defaultOIDCLoginScopes = "openid email profile offline_access"
	oidcCallbackPath       = "/api/v1/oidc/callback"
	oidcLoginCookieName    = "dekart_oidc_login"
	oidcLoginCookiePath    = "/api/v1/oidc"
	oidcLoginCookieMaxAge  = 10 * time.Minute
	// Used when the provider omits expires_in; short, so the session re-checks the provider soon.
	oidcFallbackTokenLifetime = 5 * time.Minute
	oidcHTTPTimeout           = 10 * time.Second
)

// oidcDiscovery is the subset of provider metadata Dekart uses.
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// oidcLoginState travels in a short-lived cookie from login to callback.
type oidcLoginState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Redirect string `json:"redirect"`
}

// oidcLogin runs the authorization code flow and owns the server-side sessions.
type oidcLogin struct {
	issuer       string
	clientID     string
	clientSecret string
	scopes       []string
	client       *http.Client
	sessions     *oidcSessionStore
	refreshGroup singleflight.Group

	mu        sync.Mutex
	discovery *oidcDiscovery
	verifier  *oidcJWTVerifier
}

// validateOIDCLoginConfig stops startup when OIDC login cannot work.
func validateOIDCLoginConfig(c ClaimsCheckConfig) {
	if c.OIDCIssuer == "" {
		log.Fatal().Msgf("DEKART_OIDC_ISSUER is required for OIDC login")
	}
	if c.OIDCClientID == "" {
		log.Fatal().Msgf("DEKART_OIDC_CLIENT_ID is required for OIDC login")
	}
	if _, err := parseOIDCTokenKey(c.OIDCTokenKey); err != nil {
		log.Fatal().Err(err).Msgf("DEKART_OIDC_TOKEN_KEY is required for OIDC login: base64 of 32 random bytes")
	}
	// The provider redirects back to this URL, so it must be the public one.
	if deviceauth.RequestBaseURL(nil) == "" {
		log.Fatal().Msgf("DEKART_APP_URL is required for OIDC login")
	}
}

// newOIDCLogin builds the login flow; config was validated by validateConfig.
func newOIDCLogin(c ClaimsCheckConfig, db *sql.DB) *oidcLogin {
	key, err := parseOIDCTokenKey(c.OIDCTokenKey)
	if err != nil {
		log.Fatal().Err(err).Msg("DEKART_OIDC_TOKEN_KEY is invalid")
	}
	sessions, err := newOIDCSessionStore(db, key)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize OIDC session store")
	}
	scopes := c.OIDCScopes
	if strings.TrimSpace(scopes) == "" {
		scopes = defaultOIDCLoginScopes
	}
	return &oidcLogin{
		issuer:       c.OIDCIssuer,
		clientID:     c.OIDCClientID,
		clientSecret: c.OIDCClientSecret,
		scopes:       strings.Fields(scopes),
		client:       &http.Client{Timeout: oidcHTTPTimeout},
		sessions:     sessions,
	}
}

// metadata returns provider discovery and the ID token verifier, fetching them once.
func (l *oidcLogin) metadata() (*oidcDiscovery, *oidcJWTVerifier, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.discovery != nil {
		return l.discovery, l.verifier, nil
	}
	discoveryURL := strings.TrimRight(l.issuer, "/") + "/.well-known/openid-configuration"
	resp, err := l.client.Get(discoveryURL)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("discovery status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	var discovery oidcDiscovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return nil, nil, err
	}
	// The issuer in metadata must match configuration exactly, or tokens would be checked against another provider.
	if discovery.Issuer != l.issuer {
		return nil, nil, fmt.Errorf("discovery issuer mismatch")
	}
	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" || discovery.JWKSURI == "" {
		return nil, nil, fmt.Errorf("discovery is missing required endpoints")
	}
	l.discovery = &discovery
	l.verifier = &oidcJWTVerifier{
		jwksURL:  discovery.JWKSURI,
		issuer:   l.issuer,
		audience: l.clientID,
		cacheTTL: time.Duration(defaultOIDCJWKSCacheTTLSec) * time.Second,
		client:   l.client,
		keys:     map[string]interface{}{},
	}
	return l.discovery, l.verifier, nil
}

// oauthConfig returns the client config for the discovered endpoints.
func (l *oidcLogin) oauthConfig(discovery *oidcDiscovery) *oauth2.Config {
	// Explicit style: auto-detect retries a failed request, so one refused refresh would hit the provider twice.
	authStyle := oauth2.AuthStyleInParams
	if l.clientSecret != "" {
		authStyle = oauth2.AuthStyleInHeader
	}
	return &oauth2.Config{
		ClientID:     l.clientID,
		ClientSecret: l.clientSecret,
		Scopes:       l.scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   discovery.AuthorizationEndpoint,
			TokenURL:  discovery.TokenEndpoint,
			AuthStyle: authStyle,
		},
		RedirectURL: deviceauth.RequestBaseURL(nil) + oidcCallbackPath,
	}
}

// clientContext makes oauth2 use the login HTTP client with its timeout.
func (l *oidcLogin) clientContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, l.client)
}

// secureCookies reports whether Dekart is served over https, so cookies get the Secure flag.
func secureCookies() bool {
	return strings.HasPrefix(deviceauth.RequestBaseURL(nil), "https://")
}

// safeRedirectPath keeps post-login redirects on Dekart's own origin.
func safeRedirectPath(value string) string {
	// Only absolute paths; "//host" and "/\host" are treated by browsers as another origin.
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.HasPrefix(value, "/\\") {
		return "/"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" {
		return "/"
	}
	return value
}

// setLoginStateCookie stores state, nonce and PKCE verifier until the provider calls back.
func setLoginStateCookie(w http.ResponseWriter, state oidcLoginState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcLoginCookieName,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     oidcLoginCookiePath,
		MaxAge:   int(oidcLoginCookieMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// readLoginStateCookie returns the pending login and clears its cookie.
func readLoginStateCookie(w http.ResponseWriter, r *http.Request) (oidcLoginState, error) {
	var state oidcLoginState
	cookie, err := r.Cookie(oidcLoginCookieName)
	http.SetCookie(w, &http.Cookie{Name: oidcLoginCookieName, Path: oidcLoginCookiePath, MaxAge: -1, HttpOnly: true, Secure: secureCookies(), SameSite: http.SameSiteLaxMode})
	if err != nil {
		return state, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return state, err
	}
	err = json.Unmarshal(raw, &state)
	return state, err
}

// setSessionCookie hands the browser the opaque session value.
func setSessionCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcSessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

// HandleOIDCLogin redirects the browser to the provider with state, nonce and PKCE.
func (c ClaimsCheck) HandleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	discovery, _, err := c.oidcLogin.metadata()
	if err != nil {
		log.Warn().Err(err).Msg("OIDC discovery failed")
		http.Error(w, "OIDC provider unavailable", http.StatusServiceUnavailable)
		return
	}
	state, errState := randomURLToken()
	nonce, errNonce := randomURLToken()
	if errState != nil || errNonce != nil {
		log.Error().Msg("Failed to generate OIDC login state")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	login := oidcLoginState{
		State:    state,
		Nonce:    nonce,
		Verifier: oauth2.GenerateVerifier(),
		Redirect: safeRedirectPath(r.URL.Query().Get("redirect")),
	}
	if err := setLoginStateCookie(w, login); err != nil {
		log.Error().Err(err).Msg("Failed to store OIDC login state")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	authURL := c.oidcLogin.oauthConfig(discovery).AuthCodeURL(
		login.State,
		oauth2.S256ChallengeOption(login.Verifier),
		oauth2.SetAuthURLParam("nonce", login.Nonce),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleOIDCCallback exchanges the code, verifies the ID token and starts a session.
func (c ClaimsCheck) HandleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	login, err := readLoginStateCookie(w, r)
	if err != nil {
		log.Warn().Err(err).Msg("OIDC login state cookie is missing or invalid")
		http.Error(w, "Login expired, sign in again", http.StatusBadRequest)
		return
	}
	query := r.URL.Query()
	if authErr := query.Get("error"); authErr != "" {
		log.Warn().Str("authErr", authErr).Msg("OIDC provider returned an error")
		http.Error(w, "Login was not completed", http.StatusForbidden)
		return
	}
	// A state mismatch means the callback was not started by this browser.
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(login.State)) != 1 {
		log.Warn().Bool("hasState", query.Get("state") != "").Msg("OIDC state mismatch (sanitized)")
		http.Error(w, "Login expired, sign in again", http.StatusBadRequest)
		return
	}
	discovery, _, err := c.oidcLogin.metadata()
	if err != nil {
		log.Warn().Err(err).Msg("OIDC discovery failed")
		http.Error(w, "OIDC provider unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	code := query.Get("code")
	token, err := c.oidcLogin.oauthConfig(discovery).Exchange(c.oidcLogin.clientContext(ctx), code, oauth2.VerifierOption(login.Verifier))
	if err != nil {
		log.Warn().Err(err).Bool("hasCode", code != "").Msg("OIDC code exchange failed (sanitized)")
		http.Error(w, "Login failed", http.StatusForbidden)
		return
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	identity, err := c.oidcLogin.verifyIDToken(rawIDToken, login.Nonce)
	if err != nil {
		log.Warn().Err(err).Int("idTokenLen", len(rawIDToken)).Msg("OIDC ID token rejected")
		http.Error(w, "Login failed", http.StatusForbidden)
		return
	}
	_, err = c.db.ExecContext(
		ctx,
		"INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET updated_at = CURRENT_TIMESTAMP",
		identity.email,
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to upsert OIDC user")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	idpExpiresAt := token.Expiry
	if idpExpiresAt.IsZero() {
		idpExpiresAt = c.oidcLogin.sessions.now().Add(oidcFallbackTokenLifetime)
	}
	value, _, err := c.oidcLogin.sessions.create(ctx, identity.email, identity.subject, token.RefreshToken, idpExpiresAt)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create OIDC session")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	// The cookie outlives idle expiry on purpose: the server, not the browser, decides when a session ends.
	setSessionCookie(w, value, int(oidcSessionMaxLifetime.Seconds()))
	http.Redirect(w, r, login.Redirect, http.StatusFound)
}

// HandleOIDCLogout ends the session and returns the provider logout URL when it has one.
func (c ClaimsCheck) HandleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(oidcSessionCookieName); err == nil && cookie.Value != "" {
		if err := c.oidcLogin.sessions.delete(r.Context(), hashOIDCSessionToken(cookie.Value)); err != nil {
			log.Error().Err(err).Msg("Failed to delete OIDC session")
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	}
	setSessionCookie(w, "", -1)
	response := struct {
		LogoutURL string `json:"logoutUrl,omitempty"`
	}{}
	// Provider logout is best effort: the Dekart session is already gone.
	if discovery, _, err := c.oidcLogin.metadata(); err == nil && discovery.EndSessionEndpoint != "" {
		values := url.Values{}
		values.Set("client_id", c.oidcLogin.clientID)
		values.Set("post_logout_redirect_uri", deviceauth.RequestBaseURL(nil)+"/")
		response.LogoutURL = discovery.EndSessionEndpoint + "?" + values.Encode()
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Warn().Err(err).Msg("Failed to write OIDC logout response")
	}
}

// oidcIdentity is what Dekart keeps from a verified ID token.
type oidcIdentity struct {
	email   string
	subject string
}

// verifyIDToken checks signature, issuer, audience, expiry and nonce, then reads email and subject.
func (l *oidcLogin) verifyIDToken(rawIDToken, nonce string) (oidcIdentity, error) {
	if rawIDToken == "" {
		return oidcIdentity{}, errors.New("token response has no id_token")
	}
	_, verifier, err := l.metadata()
	if err != nil {
		return oidcIdentity{}, err
	}
	token, err := jwt.Parse(rawIDToken, verifier.getPublicKey)
	if err != nil {
		return oidcIdentity{}, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return oidcIdentity{}, errors.New("invalid ID token")
	}
	if err := verifier.validateClaims(claims); err != nil {
		return oidcIdentity{}, err
	}
	tokenNonce, _ := claims["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(tokenNonce), []byte(nonce)) != 1 {
		return oidcIdentity{}, errors.New("nonce mismatch")
	}
	email, _ := claims[defaultOIDCEmailClaim].(string)
	subject, _ := claims["sub"].(string)
	if email == "" || subject == "" {
		return oidcIdentity{}, errors.New("ID token is missing email or sub")
	}
	return oidcIdentity{email: email, subject: subject}, nil
}

// oidcLoginClaims resolves bearer credentials first, then the session cookie.
func (c ClaimsCheck) oidcLoginClaims(r *http.Request) *Claims {
	authHeader := r.Header.Get("Authorization")
	// A bearer is an explicit credential and never falls back to the cookie.
	if strings.TrimSpace(authHeader) != "" {
		token, ok := normalizeBearerToken(authHeader)
		if !ok {
			return nil
		}
		if claims := validateSnapshotToken(token); claims != nil {
			return claims
		}
		return c.validateDeviceAuthToken(r.Context(), authHeader)
	}
	cookie, err := r.Cookie(oidcSessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}
	return c.oidcLogin.sessionClaims(r.Context(), cookie.Value)
}

// sessionClaims returns claims for a live session, refreshing provider tokens when they expired.
func (l *oidcLogin) sessionClaims(ctx context.Context, value string) *Claims {
	session, err := l.sessions.get(ctx, value)
	if err != nil {
		log.Warn().Err(err).Msg("OIDC session lookup failed")
		return nil
	}
	if session == nil {
		return nil
	}
	// Re-checking the provider on expiry is what ends the session of a user disabled there.
	if !l.sessions.now().Before(session.IDPExpiresAt) && !l.refresh(ctx, session) {
		return nil
	}
	if err := l.sessions.touch(ctx, session); err != nil {
		log.Warn().Err(err).Msg("Failed to update OIDC session expiry")
	}
	return &Claims{Email: session.Email}
}

// refresh renews provider tokens once per session at a time; false means the request is not authenticated.
func (l *oidcLogin) refresh(ctx context.Context, session *oidcSession) bool {
	if session.RefreshToken == "" {
		log.Warn().Msg("OIDC session expired and has no refresh token")
		if err := l.sessions.delete(ctx, session.ID); err != nil {
			log.Error().Err(err).Msg("Failed to delete OIDC session")
		}
		return false
	}
	_, err, _ := l.refreshGroup.Do(session.ID, func() (interface{}, error) {
		// Detached from the first caller so a cancelled request does not fail the others waiting on it.
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), oidcHTTPTimeout)
		defer cancel()
		discovery, _, err := l.metadata()
		if err != nil {
			return nil, err
		}
		source := l.oauthConfig(discovery).TokenSource(l.clientContext(refreshCtx), &oauth2.Token{RefreshToken: session.RefreshToken})
		token, err := source.Token()
		if err != nil {
			return nil, err
		}
		idpExpiresAt := token.Expiry
		if idpExpiresAt.IsZero() {
			idpExpiresAt = l.sessions.now().Add(oidcFallbackTokenLifetime)
		}
		return nil, l.sessions.updateTokens(refreshCtx, session.ID, token.RefreshToken, idpExpiresAt)
	})
	if err == nil {
		return true
	}
	var retrieveErr *oauth2.RetrieveError
	// The provider refused the refresh token: the user was disabled or the grant revoked.
	if errors.As(err, &retrieveErr) && retrieveErr.Response != nil && retrieveErr.Response.StatusCode < http.StatusInternalServerError {
		log.Warn().Str("errorCode", retrieveErr.ErrorCode).Msg("OIDC refresh rejected, ending session")
		if err := l.sessions.delete(ctx, session.ID); err != nil {
			log.Error().Err(err).Msg("Failed to delete OIDC session")
		}
		return false
	}
	// Provider outage: deny this request but keep the session for the next one.
	log.Warn().Err(err).Msg("OIDC refresh failed")
	return false
}
