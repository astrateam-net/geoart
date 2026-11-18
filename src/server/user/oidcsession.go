package user

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	oidcSessionCookieName    = "dekart_session"
	oidcSessionIdleTimeout   = 7 * 24 * time.Hour
	oidcSessionMaxLifetime   = 30 * 24 * time.Hour
	oidcSessionTouchInterval = time.Hour
)

// oidcSession is one row of oidc_sessions with the refresh token decrypted.
type oidcSession struct {
	ID           string
	Email        string
	Subject      string
	RefreshToken string
	IDPExpiresAt time.Time
	CreatedAt    time.Time
	LastUsedAt   time.Time
	ExpiresAt    time.Time
}

// oidcSessionStore persists login sessions and encrypts refresh tokens at rest.
type oidcSessionStore struct {
	db   *sql.DB
	aead cipher.AEAD
	now  func() time.Time
}

// parseOIDCTokenKey decodes the base64 AES-256 key that encrypts stored refresh tokens.
func parseOIDCTokenKey(raw string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}

// newOIDCSessionStore builds the store from a 32-byte AES key.
func newOIDCSessionStore(db *sql.DB, key []byte) (*oidcSessionStore, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &oidcSessionStore{db: db, aead: aead, now: func() time.Time { return time.Now().UTC() }}, nil
}

// hashOIDCSessionToken returns the row id for a cookie value; raw values are never stored.
func hashOIDCSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// randomURLToken returns a URL-safe random string with 256 bits of entropy.
func randomURLToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// encrypt seals a refresh token as base64(nonce || ciphertext).
func (s *oidcSessionStore) encrypt(plaintext string) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// decrypt opens a value produced by encrypt and fails on any tampering.
func (s *oidcSessionStore) decrypt(value string) (string, error) {
	sealed, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	if len(sealed) < s.aead.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// encryptNullable keeps a missing refresh token as NULL instead of encrypting an empty string.
func (s *oidcSessionStore) encryptNullable(refreshToken string) (sql.NullString, error) {
	if refreshToken == "" {
		return sql.NullString{}, nil
	}
	encrypted, err := s.encrypt(refreshToken)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: encrypted, Valid: true}, nil
}

// idleExpiry slides the idle timeout without passing the absolute lifetime.
func idleExpiry(now, createdAt time.Time) time.Time {
	expiresAt := now.Add(oidcSessionIdleTimeout)
	if limit := createdAt.Add(oidcSessionMaxLifetime); expiresAt.After(limit) {
		return limit
	}
	return expiresAt
}

// create inserts a session and returns the raw cookie value with its expiry.
func (s *oidcSessionStore) create(ctx context.Context, email, subject, refreshToken string, idpExpiresAt time.Time) (string, time.Time, error) {
	token, err := randomURLToken()
	if err != nil {
		return "", time.Time{}, err
	}
	encrypted, err := s.encryptNullable(refreshToken)
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	expiresAt := idleExpiry(now, now)
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO oidc_sessions (id, email, subject, refresh_token, idp_expires_at, created_at, last_used_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		hashOIDCSessionToken(token), email, subject, encrypted, idpExpiresAt.UTC(), now, now, expiresAt,
	)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

// get returns the live session for a cookie value, or nil when it is unknown or expired.
func (s *oidcSessionStore) get(ctx context.Context, token string) (*oidcSession, error) {
	session := &oidcSession{ID: hashOIDCSessionToken(token)}
	var refreshToken sql.NullString
	err := s.db.QueryRowContext(
		ctx,
		`SELECT email, subject, refresh_token, idp_expires_at, created_at, last_used_at, expires_at
		 FROM oidc_sessions WHERE id = $1`,
		session.ID,
	).Scan(&session.Email, &session.Subject, &refreshToken, &session.IDPExpiresAt, &session.CreatedAt, &session.LastUsedAt, &session.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	// Expired rows are removed on sight so a stolen cookie value cannot outlive its session.
	if !now.Before(session.ExpiresAt) || !now.Before(session.CreatedAt.Add(oidcSessionMaxLifetime)) {
		return nil, s.delete(ctx, session.ID)
	}
	if refreshToken.Valid {
		session.RefreshToken, err = s.decrypt(refreshToken.String)
		if err != nil {
			return nil, fmt.Errorf("decrypt refresh token: %w", err)
		}
	}
	return session, nil
}

// touch slides the idle expiry, writing at most once per oidcSessionTouchInterval.
func (s *oidcSessionStore) touch(ctx context.Context, session *oidcSession) error {
	now := s.now()
	if now.Sub(session.LastUsedAt) < oidcSessionTouchInterval {
		return nil
	}
	_, err := s.db.ExecContext(
		ctx,
		"UPDATE oidc_sessions SET last_used_at = $1, expires_at = $2 WHERE id = $3",
		now, idleExpiry(now, session.CreatedAt), session.ID,
	)
	return err
}

// updateTokens stores the outcome of a refresh: the possibly rotated refresh token and its access token expiry.
func (s *oidcSessionStore) updateTokens(ctx context.Context, id, refreshToken string, idpExpiresAt time.Time) error {
	encrypted, err := s.encryptNullable(refreshToken)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(
		ctx,
		"UPDATE oidc_sessions SET refresh_token = $1, idp_expires_at = $2 WHERE id = $3",
		encrypted, idpExpiresAt.UTC(), id,
	)
	return err
}

// delete removes a session; removing an unknown id is not an error.
func (s *oidcSessionStore) delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM oidc_sessions WHERE id = $1", id)
	return err
}
