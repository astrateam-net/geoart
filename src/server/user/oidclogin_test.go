package user

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dekart/src/server/reportsnapshot"

	"github.com/golang-jwt/jwt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

// fakeOIDCProvider serves discovery, JWKS and the token endpoint for one client.
type fakeOIDCProvider struct {
	t             *testing.T
	server        *httptest.Server
	key           *rsa.PrivateKey
	challenge     string
	nonce         string
	idClaims      jwt.MapClaims
	refreshStatus int
	refreshCalls  int
}

// newFakeOIDCProvider starts a provider whose issuer ends with a slash, as Authentik's does.
func newFakeOIDCProvider(t *testing.T) *fakeOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	provider := &fakeOIDCProvider{t: t, key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, http.StatusOK, map[string]string{
			"issuer":                 provider.issuer(),
			"authorization_endpoint": provider.server.URL + "/authorize",
			"token_endpoint":         provider.server.URL + "/token",
			"jwks_uri":               provider.server.URL + "/jwks",
			"end_session_endpoint":   provider.server.URL + "/logout",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, http.StatusOK, map[string]interface{}{"keys": []map[string]string{{
			"kid": "test-kid",
			"kty": "RSA",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", provider.token)
	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *fakeOIDCProvider) issuer() string {
	return p.server.URL + "/"
}

// token answers code and refresh grants; the code grant enforces the PKCE challenge.
func (p *fakeOIDCProvider) token(w http.ResponseWriter, r *http.Request) {
	require.NoError(p.t, r.ParseForm())
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge {
			writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]interface{}{
			"access_token": "access-1", "token_type": "Bearer", "expires_in": 300,
			"refresh_token": "refresh-1", "id_token": p.idToken(),
		})
	case "refresh_token":
		p.refreshCalls++
		if p.refreshStatus != 0 {
			writeTestJSON(w, p.refreshStatus, map[string]string{"error": "invalid_grant"})
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]interface{}{
			"access_token": "access-2", "token_type": "Bearer", "expires_in": 300, "refresh_token": "refresh-2",
		})
	default:
		writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

// idToken signs an ID token for the last login, with idClaims overriding defaults.
func (p *fakeOIDCProvider) idToken() string {
	claims := jwt.MapClaims{
		"iss": p.issuer(), "aud": "dekart", "sub": "user-1", "email": "oidc@example.com",
		"nonce": p.nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	for key, value := range p.idClaims {
		claims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-kid"
	signed, err := token.SignedString(p.key)
	require.NoError(p.t, err)
	return signed
}

func writeTestJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// newOIDCLoginCheck builds a ClaimsCheck in OIDC login mode on an in-memory database with the real migration.
func newOIDCLoginCheck(t *testing.T, provider *fakeOIDCProvider) (ClaimsCheck, *sql.DB) {
	t.Helper()
	t.Setenv("DEKART_APP_URL", "https://dekart.example")
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	// One connection: every :memory: connection is a separate database.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	migration, err := os.ReadFile(filepath.Join("..", "..", "..", "sqlite", "migrations", "000056_create_oidc_sessions.up.sql"))
	require.NoError(t, err)
	_, err = db.Exec(string(migration))
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE users (email TEXT PRIMARY KEY, sensitive_scope TEXT DEFAULT '',
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`)
	require.NoError(t, err)
	createDeviceSessionFixture(t, db)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	check := NewClaimsCheck(ClaimsCheckConfig{
		RequireOIDCLogin: true,
		OIDCIssuer:       provider.issuer(),
		OIDCClientID:     "dekart",
		OIDCTokenKey:     base64.StdEncoding.EncodeToString(key),
	}, db)
	return check, db
}

// startOIDCLogin runs the login handler and returns the callback query and state cookie.
func startOIDCLogin(t *testing.T, check ClaimsCheck, provider *fakeOIDCProvider) (url.Values, *http.Cookie) {
	t.Helper()
	recorder := httptest.NewRecorder()
	check.HandleOIDCLogin(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/login?redirect=/reports/report-1", nil))
	require.Equal(t, http.StatusFound, recorder.Code)
	location, err := url.Parse(recorder.Header().Get("Location"))
	require.NoError(t, err)
	authorize := location.Query()
	require.Equal(t, "S256", authorize.Get("code_challenge_method"))
	require.Equal(t, "https://dekart.example/api/v1/oidc/callback", authorize.Get("redirect_uri"))
	require.NotEmpty(t, authorize.Get("nonce"))
	provider.challenge = authorize.Get("code_challenge")
	provider.nonce = authorize.Get("nonce")
	callback := url.Values{"code": {"code-1"}, "state": {authorize.Get("state")}}
	return callback, findCookie(recorder.Result().Cookies(), oidcLoginCookieName)
}

// runOIDCCallback calls the callback handler the way the provider redirect would.
func runOIDCCallback(check ClaimsCheck, query url.Values, stateCookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/callback?"+query.Encode(), nil)
	if stateCookie != nil {
		request.AddCookie(stateCookie)
	}
	recorder := httptest.NewRecorder()
	check.HandleOIDCCallback(recorder, request)
	return recorder
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func countOIDCSessions(t *testing.T, db *sql.DB) int {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM oidc_sessions").Scan(&count))
	return count
}

func TestOIDCLoginFlow(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	check, db := newOIDCLoginCheck(t, provider)
	query, stateCookie := startOIDCLogin(t, check, provider)
	require.NotNil(t, stateCookie)
	require.True(t, stateCookie.HttpOnly)

	recorder := runOIDCCallback(check, query, stateCookie)
	require.Equal(t, http.StatusFound, recorder.Code)
	require.Equal(t, "/reports/report-1", recorder.Header().Get("Location"))
	session := findCookie(recorder.Result().Cookies(), oidcSessionCookieName)
	require.NotNil(t, session)
	require.True(t, session.HttpOnly)
	require.True(t, session.Secure)
	require.Equal(t, http.SameSiteLaxMode, session.SameSite)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(session)
	claims := GetClaims(check.GetContext(request))
	require.NotNil(t, claims)
	require.Equal(t, "oidc@example.com", claims.Email)

	var users int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM users WHERE email = 'oidc@example.com'").Scan(&users))
	require.Equal(t, 1, users)
	var stored string
	require.NoError(t, db.QueryRow("SELECT refresh_token FROM oidc_sessions").Scan(&stored))
	require.NotContains(t, stored, "refresh-1")
	plaintext, err := check.oidcLogin.sessions.decrypt(stored)
	require.NoError(t, err)
	require.Equal(t, "refresh-1", plaintext)
}

func TestOIDCCallbackRejects(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		idClaims jwt.MapClaims
		mutate   func(provider *fakeOIDCProvider, query url.Values) url.Values
		noCookie bool
		status   int
	}{
		{name: "state mismatch", mutate: func(_ *fakeOIDCProvider, q url.Values) url.Values { q.Set("state", "other"); return q }, status: http.StatusBadRequest},
		{name: "missing login cookie", noCookie: true, status: http.StatusBadRequest},
		{name: "provider error", mutate: func(_ *fakeOIDCProvider, q url.Values) url.Values { q.Set("error", "access_denied"); return q }, status: http.StatusForbidden},
		{name: "pkce verifier mismatch", mutate: func(p *fakeOIDCProvider, q url.Values) url.Values { p.challenge = "other"; return q }, status: http.StatusForbidden},
		{name: "nonce mismatch", idClaims: jwt.MapClaims{"nonce": "other"}, status: http.StatusForbidden},
		{name: "wrong audience", idClaims: jwt.MapClaims{"aud": "another-client"}, status: http.StatusForbidden},
		{name: "wrong issuer", idClaims: jwt.MapClaims{"iss": "https://idp.example/"}, status: http.StatusForbidden},
		{name: "missing email", idClaims: jwt.MapClaims{"email": ""}, status: http.StatusForbidden},
		{name: "expired id token", idClaims: jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()}, status: http.StatusForbidden},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			provider := newFakeOIDCProvider(t)
			check, db := newOIDCLoginCheck(t, provider)
			query, stateCookie := startOIDCLogin(t, check, provider)
			provider.idClaims = scenario.idClaims
			if scenario.mutate != nil {
				query = scenario.mutate(provider, query)
			}
			if scenario.noCookie {
				stateCookie = nil
			}
			recorder := runOIDCCallback(check, query, stateCookie)
			require.Equal(t, scenario.status, recorder.Code)
			require.Nil(t, findCookie(recorder.Result().Cookies(), oidcSessionCookieName))
			require.Equal(t, 0, countOIDCSessions(t, db))
		})
	}
}

func TestSafeRedirectPath(t *testing.T) {
	for input, expected := range map[string]string{
		"/reports/1?x=1":       "/reports/1?x=1",
		"":                     "/",
		"reports":              "/",
		"//evil.example/x":     "/",
		"/\\evil.example":      "/",
		"https://evil.example": "/",
	} {
		require.Equal(t, expected, safeRedirectPath(input), input)
	}
}

func TestGetContextOIDCLogin(t *testing.T) {
	privateKey, publicKeyPEM := generateDeviceJWTKeyPair(t)
	t.Setenv(deviceAuthPublicKeyEnv, base64.StdEncoding.EncodeToString(publicKeyPEM))
	deviceToken := signDeviceToken(t, privateKey, "user@example.com", "workspace-1")
	snapshotToken, _, err := reportsnapshot.IssueToken(reportsnapshot.Claims{
		Email: "snapshot@example.com", WorkspaceID: "workspace-1", ReportID: "report-1",
	})
	require.NoError(t, err)
	t.Cleanup(func() { reportsnapshot.DeleteToken(snapshotToken) })

	for _, scenario := range []struct {
		name, authorization, reportID, email string
		noCookie, unknownCookie              bool
		refreshToken                         string
		idpExpired                           bool
		refreshStatus                        int
		setup                                func(t *testing.T, check ClaimsCheck, db *sql.DB)
		sessions, refreshCalls               int
	}{
		{name: "valid session", email: "oidc@example.com", refreshToken: "refresh-1", sessions: 1},
		{name: "no cookie", noCookie: true, refreshToken: "refresh-1", sessions: 1},
		{name: "unknown cookie", unknownCookie: true, refreshToken: "refresh-1", sessions: 1},
		{name: "idle expired", refreshToken: "refresh-1", setup: func(t *testing.T, check ClaimsCheck, _ *sql.DB) {
			check.oidcLogin.sessions.now = func() time.Time { return time.Now().UTC().Add(oidcSessionIdleTimeout + time.Hour) }
		}},
		{name: "absolute lifetime exceeded", refreshToken: "refresh-1", setup: func(t *testing.T, _ ClaimsCheck, db *sql.DB) {
			_, err := db.Exec("UPDATE oidc_sessions SET created_at = $1", time.Now().UTC().Add(-oidcSessionMaxLifetime-time.Hour))
			require.NoError(t, err)
		}},
		{name: "provider token expired, refresh succeeds", email: "oidc@example.com", refreshToken: "refresh-1", idpExpired: true, sessions: 1, refreshCalls: 1},
		{name: "refresh rejected ends session", refreshToken: "refresh-1", idpExpired: true, refreshStatus: http.StatusBadRequest, refreshCalls: 1},
		{name: "provider outage keeps session", refreshToken: "refresh-1", idpExpired: true, refreshStatus: http.StatusServiceUnavailable, sessions: 1, refreshCalls: 1},
		{name: "expired without refresh token", idpExpired: true},
		{name: "device only", noCookie: true, authorization: "Bearer " + deviceToken, email: "user@example.com", refreshToken: "refresh-1", sessions: 1},
		{name: "revoked device", noCookie: true, authorization: "Bearer " + deviceToken, refreshToken: "refresh-1", sessions: 1, setup: func(t *testing.T, _ ClaimsCheck, db *sql.DB) {
			_, err := db.Exec("UPDATE device_auth_log SET status = 'revoked'")
			require.NoError(t, err)
		}},
		{name: "snapshot only", noCookie: true, authorization: "Bearer " + snapshotToken, email: "snapshot@example.com", refreshToken: "refresh-1", sessions: 1},
		{name: "snapshot report mismatch", noCookie: true, authorization: "Bearer " + snapshotToken, reportID: "another-report", refreshToken: "refresh-1", sessions: 1},
		{name: "invalid bearer blocks cookie", authorization: "Bearer not-a-dekart-token", refreshToken: "refresh-1", sessions: 1},
		{name: "malformed authorization blocks cookie", authorization: "Basic " + deviceToken, refreshToken: "refresh-1", sessions: 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			provider := newFakeOIDCProvider(t)
			provider.refreshStatus = scenario.refreshStatus
			check, db := newOIDCLoginCheck(t, provider)
			idpExpiresAt := time.Now().Add(5 * time.Minute)
			if scenario.idpExpired {
				idpExpiresAt = time.Now().Add(-time.Minute)
			}
			value, _, err := check.oidcLogin.sessions.create(context.Background(), "oidc@example.com", "user-1", scenario.refreshToken, idpExpiresAt)
			require.NoError(t, err)
			if scenario.setup != nil {
				scenario.setup(t, check, db)
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if scenario.unknownCookie {
				value = "unknown"
			}
			if !scenario.noCookie {
				request.AddCookie(&http.Cookie{Name: oidcSessionCookieName, Value: value})
			}
			request.Header.Set("Authorization", scenario.authorization)
			request.Header.Set("X-Dekart-Report-Id", scenario.reportID)

			claims := GetClaims(check.GetContext(request))
			if scenario.email == "" {
				require.Nil(t, claims)
			} else {
				require.NotNil(t, claims)
				require.Equal(t, scenario.email, claims.Email)
			}
			require.Equal(t, scenario.sessions, countOIDCSessions(t, db))
			require.Equal(t, scenario.refreshCalls, provider.refreshCalls)
			if scenario.refreshCalls == 1 && scenario.sessions == 1 && scenario.refreshStatus == 0 {
				session, err := check.oidcLogin.sessions.get(context.Background(), value)
				require.NoError(t, err)
				require.Equal(t, "refresh-2", session.RefreshToken)
				require.True(t, session.IDPExpiresAt.After(time.Now()))
			}
		})
	}
}

func TestOIDCSessionRefreshTokenEncryption(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	store, err := newOIDCSessionStore(nil, key)
	require.NoError(t, err)
	sealed, err := store.encrypt("refresh-1")
	require.NoError(t, err)
	require.NotContains(t, sealed, "refresh-1")
	plaintext, err := store.decrypt(sealed)
	require.NoError(t, err)
	require.Equal(t, "refresh-1", plaintext)

	raw, err := base64.StdEncoding.DecodeString(sealed)
	require.NoError(t, err)
	raw[len(raw)-1] ^= 0xff
	_, err = store.decrypt(base64.StdEncoding.EncodeToString(raw))
	require.Error(t, err)

	empty, err := store.encryptNullable("")
	require.NoError(t, err)
	require.False(t, empty.Valid)

	_, err = parseOIDCTokenKey(base64.StdEncoding.EncodeToString(key[:16]))
	require.Error(t, err)
}

func TestOIDCSessionTouchSlidesExpiry(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	check, db := newOIDCLoginCheck(t, provider)
	store := check.oidcLogin.sessions
	value, firstExpiry, err := store.create(context.Background(), "oidc@example.com", "user-1", "", time.Now().Add(time.Hour))
	require.NoError(t, err)
	readExpiry := func() time.Time {
		var expiresAt time.Time
		require.NoError(t, db.QueryRow("SELECT expires_at FROM oidc_sessions").Scan(&expiresAt))
		return expiresAt
	}

	session, err := store.get(context.Background(), value)
	require.NoError(t, err)
	require.NoError(t, store.touch(context.Background(), session))
	require.True(t, readExpiry().Equal(firstExpiry), "no write within the touch interval")

	later := time.Now().UTC().Add(2 * time.Hour)
	store.now = func() time.Time { return later }
	require.NoError(t, store.touch(context.Background(), session))
	require.True(t, readExpiry().Equal(later.Add(oidcSessionIdleTimeout)))
}

func TestHandleOIDCLogout(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	check, db := newOIDCLoginCheck(t, provider)
	value, _, err := check.oidcLogin.sessions.create(context.Background(), "oidc@example.com", "user-1", "refresh-1", time.Now().Add(time.Hour))
	require.NoError(t, err)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/oidc/logout", nil)
	request.AddCookie(&http.Cookie{Name: oidcSessionCookieName, Value: value})
	recorder := httptest.NewRecorder()
	check.HandleOIDCLogout(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, 0, countOIDCSessions(t, db))
	cleared := findCookie(recorder.Result().Cookies(), oidcSessionCookieName)
	require.NotNil(t, cleared)
	require.Less(t, cleared.MaxAge, 0)
	var response struct {
		LogoutURL string `json:"logoutUrl"`
	}
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	logout, err := url.Parse(response.LogoutURL)
	require.NoError(t, err)
	require.Equal(t, "/logout", logout.Path)
	require.Equal(t, "dekart", logout.Query().Get("client_id"))
	require.Equal(t, "https://dekart.example/", logout.Query().Get("post_logout_redirect_uri"))
}
